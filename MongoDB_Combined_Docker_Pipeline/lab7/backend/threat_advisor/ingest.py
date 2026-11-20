"""
Threat Advisor Data Ingestor & Vector Indexing Engine.
Handles CISA KEV, NVD, EPSS data loading, ESR indexing, and 384-d semantic chunking.
"""

import math
import hashlib
import logging
from datetime import datetime, timezone
from typing import List, Dict, Any, Optional

from database import get_database
from threat_advisor.snapshot_data import SNAPSHOT_THREATS
from threat_advisor.lifecycle import build_lifecycle_aggregation_pipeline, compute_python_fallback_status

logger = logging.getLogger("threat_intel.threat_advisor.ingest")
VECTOR_DIMENSION = 384


def generate_384d_embedding(text: str) -> List[float]:
    """Generates deterministic 384-dimensional L2-normalized embedding."""
    vec = [0.0] * VECTOR_DIMENSION
    words = text.lower().split()
    for w in words:
        h = int(hashlib.sha256(w.encode("utf-8")).hexdigest(), 16)
        idx = h % VECTOR_DIMENSION
        sign = 1.0 if (h >> 8) & 1 else -1.0
        vec[idx] += sign * (1.0 + (h % 10) / 10.0)

    norm = math.sqrt(sum(v * v for v in vec))
    if norm > 0:
        vec = [round(v / norm, 6) for v in vec]
    return vec


def calculate_text_hash(text: str) -> str:
    """Computes SHA-256 hash of chunk text to avoid redundant embedding generation."""
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


class ThreatAdvisorIngestor:
    def __init__(self):
        self.db = get_database()

    def get_collection(self, name: str):
        db = get_database()
        if db is not None:
            return db[name]
        return None

    def ensure_indexes(self):
        """Creates ESR rule indexes and TTL indexes across Threat Advisor collections."""
        db = self.db
        if db is None:
            return

        try:
            # 1. threats ESR indexes
            db["threats"].create_index([("platforms", 1), ("status", 1), ("rank", 1)], background=True)
            db["threats"].create_index([("status", 1), ("rank", 1)], background=True)
            db["threats"].create_index([("cveId", 1)], unique=True, background=True)

            # 2. knowledge chunk index
            db["knowledge"].create_index([("chunkId", 1)], unique=True, background=True)
            db["knowledge"].create_index([("platform", 1), ("status", 1), ("kind", 1)], background=True)

            # 3. sessions ESR index
            db["advisor_sessions"].create_index([("sessionId", 1), ("timestamp", 1)], background=True)

            # 4. host findings ESR indexes
            db["hosts"].create_index([("deviceHash", 1)], unique=True, background=True)
            db["device_checks"].create_index([("deviceHash", 1), ("verdict", 1)], background=True)
            db["findings"].create_index([("deviceHash", 1), ("severity", 1)], background=True)

            # 5. Security & Tokens TTL indexes
            db["scan_tokens"].create_index([("createdAt", 1)], expireAfterSeconds=1800, background=True)  # 30 mins
            db["requests"].create_index([("createdAt", 1)], expireAfterSeconds=604800, background=True)   # 7 days
            db["rate_limits"].create_index([("createdAt", 1)], expireAfterSeconds=3600, background=True)

            db["agent_devices"].create_index([("tokenHash", 1)], unique=True, background=True)
            db["agent_devices"].create_index([("deviceHash", 1)], unique=True, background=True)

            logger.info("Threat Advisor ESR and TTL indexes successfully ensured.")
        except Exception as e:
            logger.warning(f"Error ensuring indexes (standalone/mock mode): {e}")

    def seed_offline_snapshot(self) -> Dict[str, Any]:
        """Loads curated offline CISA KEV + NVD snapshot into MongoDB."""
        self.ensure_indexes()
        threats_col = self.get_collection("threats")

        upserted_count = 0
        now_iso = datetime.now(timezone.utc).isoformat()

        for threat in SNAPSHOT_THREATS:
            cve_id = threat["cveId"]
            doc = dict(threat)
            doc["updatedAt"] = now_iso

            # Use defined status or compute if missing
            if not doc.get("status"):
                doc["status"] = compute_python_fallback_status(doc)

            if threats_col is not None:
                threats_col.update_one({"cveId": cve_id}, {"$set": doc}, upsert=True)
            upserted_count += 1

        # Chunk and embed knowledge documents
        chunk_count = self.build_and_embed_knowledge_chunks()

        return {
            "status": "success",
            "threatsUpserted": upserted_count,
            "knowledgeChunks": chunk_count,
            "indexedAt": now_iso
        }

    def build_and_embed_knowledge_chunks(self) -> int:
        """Chunks threat records and mitigation playbooks into the knowledge collection."""
        threats_col = self.get_collection("threats")
        knowledge_col = self.get_collection("knowledge")

        if threats_col is not None:
            threats = list(threats_col.find({}))
        else:
            threats = SNAPSHOT_THREATS

        total_chunks = 0
        for t in threats:
            cve_id = t["cveId"]
            platforms = t.get("platforms", ["windows"])
            status = t.get("status", "Active")
            title = t.get("title", "")
            desc = t.get("description", "")
            mitigation_dict = t.get("mitigation", {})

            # 1. Threat overview chunk
            desc_text = (
                f"Threat: {cve_id} - {title}\n"
                f"Product: {t.get('product')} by {t.get('vendor')}\n"
                f"CVSS: {t.get('cvss')} | EPSS: {t.get('epss')} | Status: {status}\n"
                f"Details: {desc}"
            )
            for plat in platforms:
                chunk_id = f"{cve_id}_{plat}_desc"
                self._upsert_chunk(chunk_id, cve_id, plat, status, "threat_desc", desc_text)
                total_chunks += 1

            # 2. Playbook mitigation chunk
            for plat, pb in mitigation_dict.items():
                steps_text = "\n".join(f"- {s}" for s in pb.get("steps", []))
                workaround = pb.get("workaround", "None")
                pb_text = (
                    f"Mitigation Playbook for {cve_id} on {plat.upper()}:\n"
                    f"Recommended Actions:\n{steps_text}\n"
                    f"Workaround: {workaround}\n"
                    f"Advisories: {', '.join(pb.get('vendorAdvisories', []))}"
                )
                chunk_id = f"{cve_id}_{plat}_mitigation"
                self._upsert_chunk(chunk_id, cve_id, plat, status, "mitigation_playbook", pb_text)
                total_chunks += 1

        return total_chunks

    def _upsert_chunk(self, chunk_id: str, cve_id: str, platform: str, status: str, kind: str, text: str):
        knowledge_col = self.get_collection("knowledge")
        text_hash = calculate_text_hash(text)

        if knowledge_col is not None:
            existing = knowledge_col.find_one({"chunkId": chunk_id})
            if existing and existing.get("textHash") == text_hash:
                # Text didn't change; avoid re-embedding
                return

            embedding = generate_384d_embedding(text)
            knowledge_col.update_one(
                {"chunkId": chunk_id},
                {
                    "$set": {
                        "chunkId": chunk_id,
                        "cveId": cve_id,
                        "platform": platform.lower(),
                        "status": status,
                        "kind": kind,
                        "text": text,
                        "textHash": text_hash,
                        "embedding": embedding,
                        "updatedAt": datetime.now(timezone.utc).isoformat()
                    }
                },
                upsert=True
            )


ingestor = ThreatAdvisorIngestor()
