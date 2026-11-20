"""
ThreatPulse SOC Platform - Chapter 17 Automated Test Suite.
Validates the Retrieval-Augmented Generation (RAG) & Vector Search Architecture:
1. Document ingestion and multi-page threat report corpus.
2. Sentence-aware text chunking and metadata preservation.
3. 384-dimensional deterministic semantic vector embeddings (L2 normalized).
4. Embedding dimension validation (prevents mixed-model corruption).
5. Cosine similarity computation and semantic retrieval ranking.
6. RAG answer generation with inline citations ([1], [2]).
7. Extractive fallback disclosure: "Extractive answer – generated from retrieved report content without an LLM."
8. User-isolated conversation history and session erasure ("Forget this conversation").
9. Admin index management, telemetry, and duplicate job rejection (HTTP 409).
10. Role-based access control enforcement.
11. Empirical vector benchmarking: HNSW in MongoDB vs IVF in MongoDB (UNSUPPORTED) vs IVF in Memory.
12. Lab 17 executor pipeline execution.
13. Frontend UI integration in index.html.
"""

import os
import sys
import math
import time
from pathlib import Path
import pytest
from fastapi.testclient import TestClient

# Add backend directory to sys.path
BACKEND_DIR = Path(__file__).resolve().parent.parent / "MongoDB_Combined_Docker_Pipeline" / "lab7" / "backend"
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

from main import app
from auth import ADMIN_API_KEY, create_user_session
from lab_executor import executor
from routes.lab17 import (
    THREAT_REPORTS_CORPUS,
    VECTOR_DIMENSION,
    EMBEDDING_MODEL_NAME,
    chunk_text,
    generate_deterministic_embedding,
    validate_embedding_dimension,
    cosine_similarity,
    retrieve_relevant_chunks,
    generate_rag_answer,
    run_vector_benchmarks,
    index_all_reports_sync,
    _CONVERSATION_HISTORY,
    _INDEX_METADATA,
    _INDEXED_CHUNKS
)

client = TestClient(app)

ADMIN_HEADERS = {"X-Admin-Key": ADMIN_API_KEY, "X-Admin-Confirm": "true"}

_admin_session = create_user_session(user_id="sec_admin_01", email="admin@threatpulse.io", role="admin")
_analyst_session_a = create_user_session(user_id="analyst_alice", email="alice@threatpulse.io", role="analyst")
_analyst_session_b = create_user_session(user_id="analyst_bob", email="bob@threatpulse.io", role="analyst")
_user_session = create_user_session(user_id="user_unauth", email="user@threatpulse.io", role="user")

ADMIN_COOKIE = {"tp_session": _admin_session["token"]}
ALICE_COOKIE = {"tp_session": _analyst_session_a["token"]}
BOB_COOKIE = {"tp_session": _analyst_session_b["token"]}
USER_COOKIE = {"tp_session": _user_session["token"]}


# -----------------------------------------------------------------------------
# 1. Route Registration Tests
# -----------------------------------------------------------------------------
def test_fastapi_route_registration_lab17():
    """Verifies all Chapter 17 API and client endpoints are mounted in FastAPI."""
    routes = [r.path for r in app.routes]

    # Required API routes
    assert "/api/ask" in routes
    assert "/api/ask/history" in routes
    assert "/api/ops/ask-index" in routes
    assert "/api/services/lab17" in routes
    assert "/api/labs/17/run" in routes

    # Client Single-Page App routes
    assert "/ask" in routes
    assert "/extras/lab17" in routes


# -----------------------------------------------------------------------------
# 2. Document Corpus & Ingestion Validation
# -----------------------------------------------------------------------------
def test_threat_reports_corpus_structure():
    """Verifies authoritative threat reports corpus contains structured multi-page documents."""
    assert len(THREAT_REPORTS_CORPUS) >= 4

    for rpt in THREAT_REPORTS_CORPUS:
        assert "reportId" in rpt
        assert "title" in rpt
        assert "organization" in rpt
        assert "year" in rpt
        assert "pages" in rpt
        assert len(rpt["pages"]) >= 2
        for pg in rpt["pages"]:
            assert "pageNumber" in pg
            assert "text" in pg or "content" in pg
            text_val = pg.get("text") or pg.get("content")
            assert len(text_val) > 100


# -----------------------------------------------------------------------------
# 3. Document Chunking & Sentence Awareness
# -----------------------------------------------------------------------------
def test_document_chunking_sentence_aware():
    """Verifies text chunker respects sentence boundaries and attaches page metadata."""
    sample_text = (
        "Adversaries employ advanced rootkits. These rootkits alter kernel syscall tables. "
        "Detection requires hardware memory forensics. Offline analysis is recommended."
    )
    chunks = chunk_text(sample_text, report_id="RPT-TEST-01", page_num=2, max_words=10, overlap_words=2)

    assert len(chunks) >= 2
    for c in chunks:
        assert c["reportId"] == "RPT-TEST-01"
        assert c["pageNumber"] == 2
        assert "text" in c
        assert "tokenCount" in c
        assert c["tokenCount"] > 0
        assert len(c["text"]) > 10


# -----------------------------------------------------------------------------
# 4. 384-Dimensional Embedding Generation & L2 Normalization
# -----------------------------------------------------------------------------
def test_embedding_generation_and_normalization():
    """Verifies embeddings are 384 dimensions and unit-normalized (||v|| = 1.0)."""
    text1 = "Zero-day vulnerability in Linux netfilter module allows privilege escalation."
    vec1 = generate_deterministic_embedding(text1, dim=384)

    assert len(vec1) == 384
    assert isinstance(vec1[0], float)

    # Compute Euclidean norm: ||v|| = sqrt(sum(v_i^2))
    norm = math.sqrt(sum(x * x for x in vec1))
    assert math.isclose(norm, 1.0, rel_tol=1e-4)

    # Determinism: same input produces identical vector
    vec1_repeat = generate_deterministic_embedding(text1, dim=384)
    assert vec1 == vec1_repeat

    # Different text produces distinct vector
    text2 = "Phishing campaign delivering invoice lures with macros."
    vec2 = generate_deterministic_embedding(text2, dim=384)
    assert vec1 != vec2


# -----------------------------------------------------------------------------
# 5. Vector Dimension Mismatch Validation
# -----------------------------------------------------------------------------
def test_vector_dimension_mismatch_validation():
    """Verifies validator rejects incompatible vector dimensions to protect index."""
    valid_vec = [0.1] * 384
    assert validate_embedding_dimension(valid_vec, expected_dim=384) is True

    # Incompatible dimensions
    short_vec = [0.1] * 256
    with pytest.raises(ValueError, match="Vector dimension mismatch"):
        validate_embedding_dimension(short_vec, expected_dim=384)

    long_vec = [0.1] * 512
    with pytest.raises(ValueError, match="Vector dimension mismatch"):
        validate_embedding_dimension(long_vec, expected_dim=384)


# -----------------------------------------------------------------------------
# 6. Cosine Similarity & Ranking
# -----------------------------------------------------------------------------
def test_cosine_similarity_ranking():
    """Verifies cosine similarity computation and semantic retrieval ranking."""
    v1 = generate_deterministic_embedding("ransomware hypervisor encryption", dim=384)
    v2 = generate_deterministic_embedding("ransomware hypervisor encryption", dim=384)
    v3 = generate_deterministic_embedding("database backup retention schedule", dim=384)

    sim_identical = cosine_similarity(v1, v2)
    assert math.isclose(sim_identical, 1.0, rel_tol=1e-4)

    sim_different = cosine_similarity(v1, v3)
    assert sim_different < 0.95

    # Retrieve chunks for a query
    index_all_reports_sync()
    top_chunks = retrieve_relevant_chunks("ransomware ESXi hypervisor", top_k=3, score_threshold=0.01)
    assert len(top_chunks) == 3
    # Top ranked chunk must have higher or equal similarity to following
    assert top_chunks[0]["similarity"] >= top_chunks[1]["similarity"]
    assert top_chunks[1]["similarity"] >= top_chunks[2]["similarity"]


# -----------------------------------------------------------------------------
# 7. RAG Generation & Extractive Fallback
# -----------------------------------------------------------------------------
def test_rag_extractive_fallback():
    """Verifies extractive fallback answer generation and citation structure."""
    res = generate_rag_answer("What techniques are used for memory evasion?", force_extractive=True)

    assert "answer" in res
    assert "sources" in res
    assert "mode" in res
    assert "model" in res

    # Without external API key or with force_extractive, mode must be extractive
    assert res["mode"] == "extractive"
    assert "extractive" in res["model"].lower()

    # Sources must contain citation details
    assert len(res["sources"]) > 0
    first_src = res["sources"][0]
    assert "source_number" in first_src
    assert "report_title" in first_src
    assert "page_number" in first_src
    assert "relevance_score" in first_src
    assert "retrieved_text" in first_src


# -----------------------------------------------------------------------------
# 8. Extractive Answer Explicit Disclosure
# -----------------------------------------------------------------------------
def test_extractive_answer_explicit_disclosure():
    """Asserts that extractive answers are explicitly labeled and never faked as LLM."""
    res = generate_rag_answer("Explain Linux netfilter kernel vulnerability", force_extractive=True)

    expected_disclosure = "Extractive answer – generated from retrieved report content without an LLM."
    assert expected_disclosure in res["answer"]
    assert res["mode"] != "llm"


# -----------------------------------------------------------------------------
# 9. Citation Reference Mapping ([1], [2])
# -----------------------------------------------------------------------------
def test_citation_reference_mapping():
    """Verifies that citations in answer text correspond to numbered sources."""
    res = generate_rag_answer("What ransomware targets VMware ESXi hypervisors?")

    sources = res["sources"]
    assert len(sources) >= 1
    # Check that source numbers start at 1
    source_nums = [s["source_number"] for s in sources]
    assert 1 in source_nums

    # Answer text should reference at least one [1]
    assert "[1]" in res["answer"]


# -----------------------------------------------------------------------------
# 10. Empty Retrieval Graceful Handling
# -----------------------------------------------------------------------------
def test_empty_retrieval_handling():
    """Verifies system handles unindexed or zero-match queries gracefully."""
    # Force query with non-overlapping gibberish and high score threshold
    res = generate_rag_answer("xyzzy12345nonexistenttoken99999", score_threshold=0.999, force_extractive=True)

    assert "No supporting report content was retrieved" in res["answer"]
    assert len(res["sources"]) == 0


# -----------------------------------------------------------------------------
# 11. Conversational Endpoint (POST /api/ask)
# -----------------------------------------------------------------------------
def test_api_ask_endpoint():
    """Tests POST /api/ask returns answer, mode, model, and source citations."""
    resp = client.post(
        "/api/ask",
        json={"question": "What are the key IoCs for LockBit ransomware?"},
        cookies=ALICE_COOKIE
    )
    assert resp.status_code == 200
    data = resp.json()

    assert data["status"] == "success"
    assert data["question"] == "What are the key IoCs for LockBit ransomware?"
    assert "answer" in data
    assert "mode" in data
    assert "sources" in data
    assert len(data["sources"]) >= 1


# -----------------------------------------------------------------------------
# 12. Conversation History User Isolation
# -----------------------------------------------------------------------------
def test_conversation_history_user_isolation():
    """Verifies User A and User B maintain separate isolated conversation histories."""
    # 1. Alice asks a question
    client.post("/api/ask", json={"question": "Alice secret question on zero-days"}, cookies=ALICE_COOKIE)

    # 2. Bob asks a different question
    client.post("/api/ask", json={"question": "Bob question on cloud persistence"}, cookies=BOB_COOKIE)

    # 3. Retrieve Alice's history
    alice_hist = client.get("/api/ask/history", cookies=ALICE_COOKIE).json()
    assert alice_hist["status"] == "success"
    alice_questions = [t["question"] for t in alice_hist["history"]]
    assert "Alice secret question on zero-days" in alice_questions
    assert "Bob question on cloud persistence" not in alice_questions

    # 4. Retrieve Bob's history
    bob_hist = client.get("/api/ask/history", cookies=BOB_COOKIE).json()
    assert bob_hist["status"] == "success"
    bob_questions = [t["question"] for t in bob_hist["history"]]
    assert "Bob question on cloud persistence" in bob_questions
    assert "Alice secret question on zero-days" not in bob_questions


# -----------------------------------------------------------------------------
# 13. Forget Conversation (DELETE /api/ask/history)
# -----------------------------------------------------------------------------
def test_forget_conversation_history():
    """Tests clearing session conversation history ("Forget this conversation")."""
    # Ask question as Alice
    client.post("/api/ask", json={"question": "Temporary question to be forgotten"}, cookies=ALICE_COOKIE)

    # Verify history exists
    h1 = client.get("/api/ask/history", cookies=ALICE_COOKIE).json()
    assert h1["totalTurns"] >= 1

    # Clear history
    del_resp = client.delete("/api/ask/history", cookies=ALICE_COOKIE)
    assert del_resp.status_code == 200
    assert del_resp.json()["status"] == "success"

    # Verify history is now empty for Alice
    h2 = client.get("/api/ask/history", cookies=ALICE_COOKIE).json()
    assert h2["totalTurns"] == 0
    assert len(h2["history"]) == 0


# -----------------------------------------------------------------------------
# 14. Admin Ask Index Overview (GET /api/ops/ask-index)
# -----------------------------------------------------------------------------
def test_admin_ask_index_overview():
    """Verifies admin overview endpoint returns complete index telemetry."""
    resp = client.get("/api/ops/ask-index", headers=ADMIN_HEADERS)
    assert resp.status_code == 200
    data = resp.json()

    assert data["status"] == "success"
    assert "indexedChunks" in data
    assert "reportsIndexed" in data
    assert data["vectorDimension"] == 384
    assert "embeddingModel" in data
    assert "answersGeneratedLlm" in data
    assert "extractiveAnswers" in data
    assert "questionsAsked" in data
    assert data["indexHealth"] in ["READY", "INDEXING", "HEALTHY"]


# -----------------------------------------------------------------------------
# 15. Admin Indexing Trigger & Duplicate Job Protection (HTTP 409)
# -----------------------------------------------------------------------------
def test_admin_indexing_trigger_and_duplicate_protection():
    """Tests triggering indexing and asserts HTTP 409 if another job is already running."""
    # First trigger starts indexing
    resp1 = client.post("/api/ops/ask-index", headers=ADMIN_HEADERS)
    assert resp1.status_code in [200, 409]

    if resp1.status_code == 200:
        data1 = resp1.json()
        assert data1["status"] == "started"
        assert "jobId" in data1

        # Immediate second trigger should return 409 Conflict if active
        resp2 = client.post("/api/ops/ask-index", headers=ADMIN_HEADERS)
        if resp2.status_code == 409:
            assert "already" in str(resp2.json()).lower()


# -----------------------------------------------------------------------------
# 16. Role-Based Access Control for Indexing
# -----------------------------------------------------------------------------
def test_rbac_indexing_controls():
    """Verifies non-admin users cannot access admin indexing management."""
    # Unauthenticated / user cannot access /api/ops/ask-index
    resp_get = client.get("/api/ops/ask-index", cookies=USER_COOKIE)
    assert resp_get.status_code in [401, 403]

    resp_post = client.post("/api/ops/ask-index", cookies=USER_COOKIE)
    assert resp_post.status_code in [401, 403]


# -----------------------------------------------------------------------------
# 17. Empirical Vector Benchmarking (HNSW vs IVF in Mongo vs IVF in Memory)
# -----------------------------------------------------------------------------
def test_vector_benchmarking_accuracy():
    """
    Verifies vector benchmarking evaluates:
    1. HNSW in MongoDB (Atlas Vector Search): SUPPORTED
    2. IVF in MongoDB: UNSUPPORTED (Never pretend MongoDB supports an un-implemented index)
    3. IVF in Memory: SUPPORTED
    """
    resp = client.get("/api/services/lab17")
    assert resp.status_code == 200
    data = resp.json()

    assert data["status"] == "success"
    assert data["chapter"] == 17
    assert "benchmarks" in data

    benchmarks = data["benchmarks"]
    strategies = benchmarks["strategies"]
    strat_names = [s["strategy"] for s in strategies]

    assert "HNSW in MongoDB" in strat_names
    assert "IVF in MongoDB" in strat_names
    assert "IVF in Memory" in strat_names

    # Check HNSW
    hnsw = next(s for s in strategies if s["strategy"] == "HNSW in MongoDB")
    assert hnsw["status"] == "SUPPORTED"
    assert hnsw["supported"] is True
    assert hnsw["latencyMs"] is not None
    assert hnsw["recallPct"] is not None
    assert hnsw["recallPct"] > 90.0

    # Check IVF in MongoDB: Must be explicitly marked UNSUPPORTED
    ivf_mongo = next(s for s in strategies if s["strategy"] == "IVF in MongoDB")
    assert ivf_mongo["status"] == "UNSUPPORTED"
    assert ivf_mongo["supported"] is False
    assert "not implemented" in ivf_mongo["reason"].lower() or "hnsw" in ivf_mongo["reason"].lower()

    # Check IVF in Memory
    ivf_mem = next(s for s in strategies if s["strategy"] == "IVF in Memory")
    assert ivf_mem["status"] == "SUPPORTED"
    assert ivf_mem["supported"] is True
    assert ivf_mem["latencyMs"] is not None


# -----------------------------------------------------------------------------
# 18. Lab 17 Executor Run
# -----------------------------------------------------------------------------
def test_lab17_executor_pipeline_run():
    """Verifies Lab 17 execution step in lab_executor.py."""
    res = executor.run_lab17()

    assert res["success"] is True
    assert "summary" in res
    assert "VERIFIED" in res["summary"]

    # Verify executor status
    status = executor.get_status()
    assert "17" in status["labs"]
    assert status["labs"]["17"]["status"] in ["PASSED", "COMPLETED", "SUCCESS"]
    assert status["labs"]["17"]["results"] is not None

    # Test API endpoint
    resp = client.post("/api/labs/17/run", headers=ADMIN_HEADERS)
    assert resp.status_code == 200
    assert resp.json()["started"] is True


# -----------------------------------------------------------------------------
# 19. Frontend DOM Elements in index.html
# -----------------------------------------------------------------------------
def test_frontend_chapter17_elements_presence():
    """Validates all Chapter 17 elements exist in index.html."""
    html_path = BACKEND_DIR.parent / "frontend" / "index.html"
    assert html_path.exists()
    html = html_path.read_text(encoding="utf-8")

    # Ask Conversational UI
    assert 'id="tab-ask"' in html
    assert 'id="askChatStream"' in html
    assert 'id="askInput"' in html
    assert 'id="btnAskSend"' in html
    assert 'id="btnForgetConversation"' in html

    # Admin Ops Ask View
    assert 'id="btnAdminOpsViewAsk"' in html
    assert 'id="adminOpsViewAskPane"' in html
    assert 'id="btnTriggerAskIndex"' in html
    assert 'id="askIndexProgressBar"' in html

    # Lab 17 Dedicated Workspace
    assert 'id="tab-lab17"' in html
    assert 'id="lab17Subnav"' in html
    assert 'id="lab17SubtabOverview"' in html
    assert 'id="lab17SubtabIndex"' in html
    assert 'id="lab17SubtabSearch"' in html
    assert 'id="lab17SubtabBenchmark"' in html
    assert 'id="lab17SubtabHistory"' in html

    # Lab Runner Card
    assert 'id="cardLab17"' in html
    assert 'id="btnRunLab17"' in html
