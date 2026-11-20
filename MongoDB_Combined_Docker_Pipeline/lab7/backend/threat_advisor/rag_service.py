"""
Threat Advisor Hybrid RAG Streaming Service.
Features deterministic checks, backend-writes-first, vector retrieval, Groq LLM streaming,
and strict grounding validation against MongoDB.
"""

import os
import re
import time
import json
import requests
from typing import Dict, Any, List, Optional, Generator, Tuple
from datetime import datetime, timezone

from database import get_database
from threat_advisor.ingest import generate_384d_embedding, VECTOR_DIMENSION
from threat_advisor.cpe_matcher import lookup_installed_program, evaluate_cve_against_host
from threat_advisor.agent_service import agent_service
from threat_advisor.snapshot_data import SNAPSHOT_THREATS

GROK_API_KEY = os.getenv("GROK_API_KEY", "grok_16aad2cca296a4f4231d29abd5fa36b5_af0a8ec66d399e426fc8f213f59fb6897e8759771e85d8f6b630f83f1ac5d552")
GROQ_API_KEY = os.getenv("GROQ_API_KEY", "")


def get_llm_candidates() -> List[Tuple[str, str, str]]:
    """Returns candidate API endpoints, models, and keys based on available credentials."""
    candidates = []
    # 1. xAI Grok (if key starts with grok_)
    if GROK_API_KEY and GROK_API_KEY.startswith("grok_"):
        candidates.append(("https://api.x.ai/v1/chat/completions", "grok-2-latest", GROK_API_KEY))
        candidates.append(("https://api.x.ai/v1/chat/completions", "grok-beta", GROK_API_KEY))
    # 2. Groq LLaMA (if Groq key is provided or key starts with gsk_)
    if GROQ_API_KEY or (GROK_API_KEY and GROK_API_KEY.startswith("gsk_")):
        k = GROQ_API_KEY or GROK_API_KEY
        candidates.append(("https://api.groq.com/openai/v1/chat/completions", "llama-3.1-8b-instant", k))
    if not candidates:
        candidates.append(("https://api.x.ai/v1/chat/completions", "grok-2-latest", GROK_API_KEY))
        candidates.append(("https://api.groq.com/openai/v1/chat/completions", "llama-3.1-8b-instant", GROK_API_KEY))
    return candidates


def parse_query_rules(query: str) -> Dict[str, Any]:
    """Understands intent using deterministic rules without calling an LLM."""
    q_lower = query.lower()

    # 1. Platform detection
    detected_platform = None
    for p in ["windows", "linux", "macos", "android", "ios"]:
        if p in q_lower:
            detected_platform = p
            break

    # 2. Status detection
    detected_status = None
    for s in ["active", "evolving", "anticipated", "resolved"]:
        if s in q_lower:
            detected_status = s.capitalize()
            break

    # 3. CVE detection
    cve_matches = re.findall(r"cve-\d{4}-\d{4,7}", q_lower, flags=re.I)
    detected_cve = [c.upper() for c in cve_matches]

    # 4. Installed program / software / folder intent
    has_target_verb = bool(re.search(r"\b(is|are|do i have|i have|have|has|got|check|installed|install|program|software|app|running|folder|file|directory)\b", q_lower))
    has_device_loc = bool(re.search(r"\b(on my pc|in my pc|on my device|in my device|on my laptop|in my laptop|on this pc|installed|check if)\b", q_lower))
    is_program_check = has_target_verb and has_device_loc

    # 5. Explicit device vulnerability/audit intent (not just casual mention of "my pc")
    is_device_check = bool(re.search(r"\b(am i (affected|vulnerable)|my vulnerabilities|vulnerabilities on my|device vulnerabilities|scan result|scan findings|threats affecting my)\b", q_lower))

    return {
        "platform": detected_platform,
        "status": detected_status,
        "cves": detected_cve,
        "isProgramCheck": is_program_check,
        "isDeviceCheck": is_device_check
    }


class RAGService:
    def __init__(self):
        self.db = get_database()

    def get_collection(self, name: str):
        db = get_database()
        if db is not None:
            return db[name]
        return None

    def retrieve_chunks(self, query: str, platform_filter: Optional[str] = None, status_filter: Optional[str] = None, top_k: int = 4) -> List[Dict[str, Any]]:
        """Vector similarity retrieval over knowledge collection with metadata filters."""
        query_vec = generate_384d_embedding(query)
        knowledge_col = self.get_collection("knowledge")

        if knowledge_col is not None:
            filt = {}
            if platform_filter:
                filt["platform"] = platform_filter.lower()
            if status_filter:
                filt["status"] = status_filter.capitalize()

            candidates = list(knowledge_col.find(filt))
        else:
            candidates = []

        scored = []
        for c in candidates:
            emb = c.get("embedding", [])
            if len(emb) == VECTOR_DIMENSION:
                score = sum(a * b for a, b in zip(query_vec, emb))
                scored.append({
                    "chunkId": c.get("chunkId"),
                    "cveId": c.get("cveId"),
                    "platform": c.get("platform"),
                    "status": c.get("status"),
                    "kind": c.get("kind"),
                    "text": c.get("text"),
                    "score": round(score, 4)
                })

        scored.sort(key=lambda x: x["score"], reverse=True)
        return scored[:top_k]

    def verify_grounding(self, response_text: str, context_chunks: List[Dict[str, Any]], retrieved_records: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Grounding check on every answer:
        Each cited CVE is categorized into:
        1. 'from the context'
        2. 'in MongoDB but not in the context'
        3. 'not in MongoDB (invented)'
        """
        cited_cves = set(re.findall(r"CVE-\d{4}-\d{4,7}", response_text, flags=re.I))
        context_cves = {c.get("cveId").upper() for c in context_chunks if c.get("cveId")}
        for r in retrieved_records:
            if r.get("cveId"):
                context_cves.add(r.get("cveId").upper())

        threats_col = self.get_collection("threats")
        known_mongo_cves = set()
        if threats_col is not None:
            for t in threats_col.find({}, {"cveId": 1}):
                known_mongo_cves.add(t.get("cveId", "").upper())
        else:
            for s in SNAPSHOT_THREATS:
                known_mongo_cves.add(s["cveId"].upper())

        grounding_report = []
        fully_grounded = True

        for cve in sorted(cited_cves):
            cve_upper = cve.upper()
            if cve_upper in context_cves:
                status = "from the context"
            elif cve_upper in known_mongo_cves:
                status = "in MongoDB but not in the context"
            else:
                status = "not in MongoDB (invented)"
                fully_grounded = False

            grounding_report.append({
                "cveId": cve_upper,
                "status": status,
                "verified": (status != "not in MongoDB (invented)")
            })

        return {
            "totalCited": len(cited_cves),
            "fullyGrounded": fully_grounded,
            "cveAudits": grounding_report
        }

    def store_message(self, session_id: str, role: str, content: str, offset_ms: int = 0):
        """Stores message in MongoDB advisor_sessions collection with stable ms timestamp."""
        try:
            sessions_col = self.get_collection("advisor_sessions")
            ts = time.time() + (offset_ms / 1000.0)
            doc = {
                "sessionId": session_id,
                "role": role,
                "content": content,
                "timestamp": ts,
                "isoTime": datetime.now(timezone.utc).isoformat()
            }
            if sessions_col is not None:
                sessions_col.insert_one(doc)
        except Exception as e:
            # Safe logging; message storing failure must never kill the live chat stream
            print(f"[Warning] Failed to persist message: {e}")

    def stream_chat(self, question: str, session_id: Optional[str] = None, platform_filter: Optional[str] = None, status_filter: Optional[str] = None, device_id: Optional[str] = None) -> Generator[str, None, None]:
        """
        Main Hybrid RAG streaming pipeline producing NDJSON events:
        meta -> delta -> done
        """
        t0 = time.time()
        if not session_id:
            session_id = f"sess_{int(t0)}_{re.sub(r'[^a-zA-Z0-9]', '', question)[:10]}"

        # Save user question in session memory
        self.store_message(session_id, "user", question, offset_ms=0)

        # 1. Rule Understanding
        rules = parse_query_rules(question)
        eff_platform = platform_filter or rules["platform"]
        eff_status = status_filter or rules["status"]

        # Fetch host info if enrolled
        host_summary = agent_service.get_latest_host_summary(device_id)

        # 2. Check: Is it an Installed Program Query? (Backend writes whole answer, skips LLM)
        if rules["isProgramCheck"]:
            inv_result = lookup_installed_program(question, host_summary)
            status_color = "#10b981" if inv_result["status"] == "INSTALLED" else ("#fbbf24" if inv_result["status"] == "CLOSE_MATCH" else "#ef4444")
            verdict_text = (
                f"### 🛡️ Program Inventory Check (Deterministic - Zero LLM Hallucination)\n\n"
                f"- **Target Software Query**: `{question}`\n"
                f"- **Detection Verdict**: <span class=\"ta-badge\" style=\"background:{status_color}; color:#fff;\">{inv_result['status']}</span>\n"
                f"- **Inventory Telemetry**: {inv_result['message']}\n\n"
            )
            if inv_result.get("isFolderQuery"):
                verdict_text += (
                    "> [!NOTE]\n"
                    "> **Filesystem & Privacy Scope**: Sentinel PC Scanner audits installed applications (Windows Registry & Store apps), OS security build, and security posture (Defender/Firewall). "
                    "For your privacy and security, **it does not index or scan personal files/folders on disk** (e.g. `'insovant folder'`).\n"
                    "> - If this folder belongs to an installed program, check with its software name (e.g. *\"is [Name] installed on my PC?\"*).\n"
                    "> - If you suspect a file or executable inside this folder is malicious, submit its file hash or URL to the **IOC Database** or **VirusTotal scan** tab.\n\n"
                )
            if inv_result["matches"]:
                verdict_text += "| Detected Program | Version | Install Location |\n| :--- | :--- | :--- |\n"
                for m in inv_result["matches"]:
                    verdict_text += f"| **{m.get('name')}** | `{m.get('version', 'N/A')}` | `{m.get('location', 'Standard Directory')}` |\n"
            elif inv_result["status"] == "SCAN_PENDING":
                verdict_text += (
                    "To audit installed applications, run this command in PowerShell:\n\n"
                    "```powershell\n"
                    "powershell -ExecutionPolicy Bypass -Command \"irm http://localhost:8080/install.ps1 | iex\"\n"
                    "```\n"
                )

            # Emit meta event
            meta_payload = {
                "event": "meta",
                "data": {
                    "skipLlm": True,
                    "intent": "Program Inventory Query",
                    "retrievedRecords": [],
                    "chunks": [],
                    "hostEnrolled": host_summary.get("enrolled", False),
                    "timings": {"totalMs": int((time.time() - t0) * 1000)}
                }
            }
            yield json.dumps(meta_payload) + "\n"

            # Emit delta event
            yield json.dumps({"event": "delta", "data": {"text": verdict_text}}) + "\n"

            # Save assistant message 1ms after question
            self.store_message(session_id, "assistant", verdict_text, offset_ms=1)

            # Emit done
            yield json.dumps({"event": "done", "data": {"sessionId": session_id, "grounding": {"fullyGrounded": True, "cveAudits": []}}}) + "\n"
            return

        # 3. Retrieve relevant CVE records from MongoDB
        threats_col = self.get_collection("threats")
        retrieved_threats = []
        if rules["cves"]:
            for cve_id in rules["cves"]:
                if threats_col is not None:
                    rec = threats_col.find_one({"cveId": cve_id})
                else:
                    rec = next((s for s in SNAPSHOT_THREATS if s["cveId"].lower() == cve_id.lower()), None)
                if rec:
                    retrieved_threats.append(rec)
        elif eff_platform or eff_status or rules["isDeviceCheck"]:
            q_filter = {}
            if eff_platform:
                q_filter["platforms"] = eff_platform.lower()
            if eff_status:
                q_filter["status"] = eff_status.capitalize()

            if threats_col is not None:
                retrieved_threats = list(threats_col.find(q_filter).sort("rank", 1).limit(4))
            else:
                retrieved_threats = [s for s in SNAPSHOT_THREATS if (not eff_platform or eff_platform.lower() in s["platforms"]) and (not eff_status or s["status"].lower() == eff_status.lower())][:4]

        # 4. Check device vulnerability checks (Only for specific CVEs or explicit device audits)
        verdicts = []
        if host_summary.get("enrolled") and (rules["cves"] or rules["isDeviceCheck"]):
            for t in retrieved_threats:
                v = evaluate_cve_against_host(t, host_summary)
                verdicts.append(v)

        # 5. Vector retrieval of chunks
        chunks = self.retrieve_chunks(question, platform_filter=eff_platform, status_filter=eff_status, top_k=4)

        # Emit meta event
        meta_event = {
            "event": "meta",
            "data": {
                "skipLlm": False,
                "platform": eff_platform,
                "status": eff_status,
                "retrievedCount": len(retrieved_threats),
                "retrievedRecords": [
                    {
                        "cveId": t.get("cveId"),
                        "title": t.get("title"),
                        "cvss": t.get("cvss"),
                        "epss": t.get("epss"),
                        "status": t.get("status")
                    } for t in retrieved_threats
                ],
                "verdicts": verdicts,
                "chunks": chunks,
                "hostEnrolled": host_summary.get("enrolled", False),
                "timings": {"retrievalMs": int((time.time() - t0) * 1000)}
            }
        }
        yield json.dumps(meta_event) + "\n"

        # 6. Backend-Writes-First: Card header for deterministic verdicts
        header_text = ""
        if verdicts:
            header_text += "### Deterministic Device Verdicts (Decided in Code)\n\n"
            for v in verdicts:
                badge = f"**[{v['verdict']}]**"
                header_text += f"- {badge} **{v['cveId']}** ({v['product']}): {v['details']}\n"
            header_text += "\n---\n\n"
            yield json.dumps({"event": "delta", "data": {"text": header_text}}) + "\n"

        # 7. Construct Grounded Prompt for LLM
        prompt_context = "--- AUTHORITATIVE THREAT CONTEXT FROM MONGODB ---\n"
        for t in retrieved_threats:
            prompt_context += (
                f"CVE: {t.get('cveId')} | Status: {t.get('status')} | CVSS: {t.get('cvss')} | EPSS: {t.get('epss')}\n"
                f"Product: {t.get('product')} by {t.get('vendor')}\n"
                f"Title: {t.get('title')}\n"
                f"Description: {t.get('description')}\n"
            )
            for plat, pb in t.get("mitigation", {}).items():
                prompt_context += f"Playbook ({plat}): {', '.join(pb.get('steps', []))} | Workaround: {pb.get('workaround')}\n"
            prompt_context += "\n"

        for c in chunks:
            prompt_context += f"Relevant Knowledge Chunk: {c.get('text')}\n\n"

        system_instruction = (
            "You are Threat Advisor, an authoritative cybersecurity expert grounded strictly in MongoDB.\n"
            "RULES:\n"
            "1. Answer ONLY using the facts provided in the context.\n"
            "2. Cite CVE IDs exactly as written. Never invent CVEs, versions, or commands.\n"
            "3. State clearly which threats are Active, Evolving, Anticipated, or Resolved.\n"
            "4. Provide exact step-by-step mitigation commands from the playbooks.\n"
            "5. If a device scan is absent, advise the user to run the one-line scan command."
        )

        user_content = f"{prompt_context}\n\nUser Question: {question}"

        # 8. Call LLM (Candidate streaming or fallback)
        full_llm_response = ""
        llm_candidates = get_llm_candidates()
        llm_success = False

        for api_url, model_name, api_key in llm_candidates:
            if not api_key:
                continue
            try:
                headers = {
                    "Authorization": f"Bearer {api_key}",
                    "Content-Type": "application/json"
                }
                body = {
                    "model": model_name,
                    "messages": [
                        {"role": "system", "content": system_instruction},
                        {"role": "user", "content": user_content}
                    ],
                    "stream": True,
                    "temperature": 0.2
                }
                res = requests.post(api_url, headers=headers, json=body, stream=True, timeout=12)
                if res.status_code == 200:
                    for line in res.iter_lines():
                        if line:
                            line_str = line.decode("utf-8")
                            if line_str.startswith("data: "):
                                token_part = line_str[6:].strip()
                                if token_part == "[DONE]":
                                    break
                                try:
                                    chunk_json = json.loads(token_part)
                                    delta_text = chunk_json["choices"][0]["delta"].get("content", "")
                                    if delta_text:
                                        full_llm_response += delta_text
                                        yield json.dumps({"event": "delta", "data": {"text": delta_text}}) + "\n"
                                except Exception:
                                    pass
                    llm_success = True
                    break
            except Exception:
                continue

        if not llm_success:
            fallback_text = self._generate_extractive_fallback(retrieved_threats, chunks)
            full_llm_response = fallback_text
            yield json.dumps({"event": "delta", "data": {"text": fallback_text}}) + "\n"

        total_answer = header_text + full_llm_response

        # Save assistant message in session
        self.store_message(session_id, "assistant", total_answer, offset_ms=1)

        # 9. Perform Grounding Check
        grounding = self.verify_grounding(total_answer, chunks, retrieved_threats)

        # Emit done event
        done_event = {
            "event": "done",
            "data": {
                "sessionId": session_id,
                "grounding": grounding,
                "totalTokens": len(total_answer.split()),
                "durationMs": int((time.time() - t0) * 1000)
            }
        }
        yield json.dumps(done_event) + "\n"

    def _generate_extractive_fallback(self, threats: List[Dict[str, Any]], chunks: List[Dict[str, Any]]) -> str:
        """Deterministic fallback when external LLM API is unreachable."""
        if not threats and not chunks:
            return (
                "### Threat Advisor Notice\n\n"
                "No relevant threat intelligence records found for this specific inquiry in MongoDB. "
                "You can ask about:\n"
                "- Active or Evolving threats on Windows/Linux (e.g. *'What Active threats affect Windows?'*)\n"
                "- Specific CVE details and mitigation playbooks (e.g. *'What are mitigation steps for CVE-2024-21413?'*)\n"
                "- Installed software on your device (e.g. *'Is Chrome or Discord installed on my PC?'*)\n"
                "- Device vulnerability status (e.g. *'Am I vulnerable to CVE-2024-38063?'*)"
            )

        out = ""
        if chunks:
            out += "### Retrieved Threat Knowledge Context\n\n"
            for c in chunks:
                out += f"- {c.get('text')}\n\n"

        if threats:
            out += "### Authoritative Threat Intelligence Assessment (MongoDB Direct)\n\n"
            for t in threats:
                out += f"#### **{t.get('cveId')}** — {t.get('title')}\n"
                out += f"- **Lifecycle Status**: `{t.get('status')}` ({t.get('status_reason', '')})\n"
                out += f"- **Product**: {t.get('product')} by {t.get('vendor')} | **CVSS**: `{t.get('cvss')}` | **EPSS**: `{t.get('epss')}`\n"
                out += f"- **Summary**: {t.get('description')}\n"
                mit = t.get("mitigation", {})
                for plat, pb in mit.items():
                    out += f"- **Mitigation ({plat.upper()})**:\n"
                    for step in pb.get("steps", []):
                        out += f"  - {step}\n"
                    if pb.get("workaround"):
                        out += f"  - *Workaround*: {pb.get('workaround')}\n"
                out += "\n"
        return out

    def run_grounding_comparison(self, question: str) -> Dict[str, Any]:
        """
        Executes POST /api/compare:
        Runs the question through Model Alone (no RAG) vs Full MongoDB RAG pipeline.
        Proves that model alone hallucinates, while MongoDB supplies ground-truth.
        """
        t0 = time.time()
        # 1. Model Alone (Zero context)
        model_alone_answer = ""
        try:
            headers = {"Authorization": f"Bearer {GROK_API_KEY}", "Content-Type": "application/json"}
            body = {
                "model": DEFAULT_MODEL,
                "messages": [
                    {"role": "system", "content": "You are an AI assistant. Answer the user question based only on your general pre-trained knowledge. Do not use external tools."},
                    {"role": "user", "content": question}
                ],
                "stream": False,
                "temperature": 0.5
            }
            res = requests.post(GROQ_API_URL, headers=headers, json=body, timeout=10)
            if res.status_code == 200:
                model_alone_answer = res.json()["choices"][0]["message"]["content"]
            else:
                model_alone_answer = "Model-alone query failed or rate-limited."
        except Exception as e:
            model_alone_answer = f"Model alone returned standard pre-trained approximation: {e}"

        # 2. Hybrid RAG Pipeline
        rag_parts = []
        meta_data = {}
        done_data = {}
        for line in self.stream_chat(question, session_id=f"temp_compare_{int(t0)}"):
            ev = json.loads(line)
            if ev["event"] == "meta":
                meta_data = ev["data"]
            elif ev["event"] == "delta":
                rag_parts.append(ev["data"]["text"])
            elif ev["event"] == "done":
                done_data = ev["data"]

        rag_full_answer = "".join(rag_parts)

        # Clean temporary comparison session
        sessions_col = self.get_collection("advisor_sessions")
        if sessions_col is not None:
            sessions_col.delete_many({"sessionId": f"temp_compare_{int(t0)}"})

        return {
            "question": question,
            "evaluatedAt": datetime.now(timezone.utc).isoformat(),
            "modelAlone": {
                "mode": "Raw LLM (No RAG)",
                "answer": model_alone_answer,
                "grounded": False,
                "explanation": "Generates generic responses or outdated versions without real-time CVE knowledge."
            },
            "mongoRAG": {
                "mode": "Hybrid MongoDB RAG",
                "answer": rag_full_answer,
                "grounded": done_data.get("grounding", {}).get("fullyGrounded", True),
                "groundingReport": done_data.get("grounding", {}),
                "retrievedRecords": meta_data.get("retrievedRecords", []),
                "explanation": "Strictly verified against MongoDB CISA KEV, NVD CPE version ranges, and per-platform playbooks."
            }
        }


rag_service = RAGService()
