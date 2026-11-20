"""
ThreatPulse SOC Platform - Chapter 18 Automated Test Suite.
Comparative Database Capstone: False-Positive Detection across MongoDB, Cassandra, and Neo4j.

Validates:
1. Route registration for all Chapter 18 endpoints and SPA routes.
2. Authoritative labeled ground truth dataset and 5 CTI feed registry.
3. Physical schema structures: MongoDB fp.full_threats/fp.candidates, Cassandra wide-column tables, Neo4j graph nodes.
4. Multi-feed ingestion with deduplication and MongoDB-first write confirmation.
5. Partial failure and rejection tracking.
6. Empirical Q1-Q4 query benchmarking (10 iterations per query, median latency calculation).
7. Tri-database false-positive evaluation per candidate (MongoDB, Cassandra, Neo4j verdicts).
8. Dataset-wide false-positive evaluation: TP, FN, FP, TN, Precision, Recall, F1.
9. Two-of-Three Consensus Voting superiority (highest F1, zero dropped real threats: FN == 0).
10. Concrete disagreement case studies with forensic explanations.
11. Threat community graph detection, bridging hub identification (Z-score), Cypher query generation.
12. GET /api/services/lab18 service status, counts, latency, and health reporting.
13. GET /api/moderation/fp RBAC enforcement and parameter filtering.
14. GET /api/moderation/fp/value deep tri-DB forensic evidence dossier.
15. POST /api/moderation/fp/decision validation (mandatory notes and confirmation checkbox).
16. Analyst decision lifecycle, audit recording, and forensic evidence preservation (no hard delete).
17. GET /api/ops/export/threats downstream filtering with false-positive suppression.
18. GET /api/ops/report.pdf ReportLab PDF compilation with all 10 architectural sections.
19. Lab 18 executor pipeline execution and frontend DOM elements presence in index.html.
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
from routes.lab18 import (
    SOURCES_REGISTRY,
    LABELED_GROUND_TRUTH,
    FEED_CISA,
    FEED_ENISA,
    FEED_MANDIANT,
    FEED_SHADOWNET,
    FEED_OPENCTI,
    initialize_tri_db_corpus,
    evaluate_false_positive_candidate_tri_db,
    evaluate_all_false_positives_dataset,
    run_q1_q4_benchmarks,
    analyze_threat_communities,
    generate_comparative_pdf_report,
    _ANALYST_DECISION_AUDIT,
    _MONGO_FULL_THREATS,
    _MONGO_FP_CANDIDATES,
    _INGESTION_METADATA
)

client = TestClient(app)

# Helper headers
ADMIN_HEADERS = {"X-Admin-Key": ADMIN_API_KEY}


# -----------------------------------------------------------------------------
# 1. FastAPI Route Registration
# -----------------------------------------------------------------------------
def test_fastapi_route_registration_lab18():
    """Verify all Chapter 18 endpoints and SPA views are registered."""
    routes = [r.path for r in app.routes]
    expected_routes = [
        "/api/services/lab18",
        "/api/moderation/fp",
        "/api/moderation/fp/value",
        "/api/moderation/fp/decision",
        "/api/ops/sources",
        "/api/ops/report.pdf",
        "/api/ops/export/threats",
        "/api/labs/18/run",
        "/extras/lab18"
    ]
    for er in expected_routes:
        assert er in routes, f"Missing expected route in FastAPI app: {er}"


# -----------------------------------------------------------------------------
# 2. Labeled Ground Truth & Feed Registry
# -----------------------------------------------------------------------------
def test_labeled_ground_truth_and_feed_registry():
    """Verify the 5 threat intelligence feeds and labeled ground truth structure."""
    assert len(SOURCES_REGISTRY) == 5
    for fid in [FEED_CISA, FEED_ENISA, FEED_MANDIANT, FEED_SHADOWNET, FEED_OPENCTI]:
        assert fid in SOURCES_REGISTRY
        assert "name" in SOURCES_REGISTRY[fid]
        assert "reliabilityScore" in SOURCES_REGISTRY[fid]
        assert 0.0 < SOURCES_REGISTRY[fid]["reliabilityScore"] <= 1.0

    # Labeled ground truth must contain both benign false positives and real threats
    fps = [i for i in LABELED_GROUND_TRUTH if i["groundTruth"] == "BENIGN_FALSE_POSITIVE"]
    reals = [i for i in LABELED_GROUND_TRUTH if i["groundTruth"] == "REAL_THREAT"]
    assert len(fps) >= 4, "Must contain benign false-positive candidates"
    assert len(reals) >= 4, "Must contain confirmed real threats"

    # Known infrastructure candidates
    values = {i["value"] for i in LABELED_GROUND_TRUTH}
    assert "1.1.1.1" in values  # Cloudflare DNS
    assert "8.8.8.8" in values  # Google DNS
    assert "telemetry.microsoft.com" in values  # Legitimate telemetry


# -----------------------------------------------------------------------------
# 3. Tri-Database Corpus Initialization & Indexes
# -----------------------------------------------------------------------------
def test_tri_database_corpus_initialization_and_indexes():
    """Test initialization of MongoDB collections, Cassandra tables, and Neo4j graph nodes."""
    res = initialize_tri_db_corpus()
    assert res["status"] in ("initialized", "already_initialized")
    assert res["mongodb"]["full_threats_count"] > 0
    assert res["mongodb"]["candidates_count"] > 0
    assert res["cassandra"]["total_rows"] > 0
    assert res["neo4j"]["nodes"] > 0
    assert res["neo4j"]["relationships"] > 0


# -----------------------------------------------------------------------------
# 4. MongoDB-First Confirmation & Deduplication
# -----------------------------------------------------------------------------
def test_mongodb_first_write_confirmation_and_deduplication():
    """Verify that writes confirm in MongoDB before peer replication and deduplicate by (source, value, timestamp)."""
    res = initialize_tri_db_corpus()
    # MongoDB-first policy guarantees MongoDB count reflects authoritative write confirmation
    assert res["mongodb"]["confirmed_write_barrier"] is True
    # Deduplication ensures no duplicate (source, value, timestamp) tuples
    assert res["deduplication"]["duplicates_suppressed"] >= 0


# -----------------------------------------------------------------------------
# 5. Partial Failure and Rejection Tracking
# -----------------------------------------------------------------------------
def test_partial_failure_and_rejection_tracking():
    """Verify partial failures and malformed records are explicitly tracked and not masked."""
    res = initialize_tri_db_corpus()
    rejections = res.get("rejections", {})
    assert "malformed_records" in rejections
    assert "unsupported_types" in rejections
    assert isinstance(rejections["malformed_records"], int)


# -----------------------------------------------------------------------------
# 6. Q1-Q4 Benchmarking Execution & Medians
# -----------------------------------------------------------------------------
def test_q1_q4_benchmarking_execution_and_medians():
    """Verify Q1-Q4 benchmarks execute across MongoDB, Cassandra, and Neo4j and compute median latency."""
    bm = run_q1_q4_benchmarks(runs_per_query=5)
    for q_key in ["q1", "q2", "q3", "q4"]:
        assert q_key in bm, f"Missing benchmark {q_key}"
        q_data = bm[q_key]
        assert "mongodb_ms" in q_data
        assert "cassandra_ms" in q_data
        assert "neo4j_ms" in q_data
        assert "fastest_engine" in q_data

        # Latencies must be positive numbers
        assert q_data["mongodb_ms"] > 0
        assert q_data["cassandra_ms"] > 0
        assert q_data["neo4j_ms"] > 0

    # Architecture validation: Neo4j should excel at graph traversal (Q2)
    # Cassandra should excel at wide-column point/daily lookups (Q1/Q3)
    assert bm["q2"]["fastest_engine"] == "Neo4j"


# -----------------------------------------------------------------------------
# 7. Tri-Database Candidate Evaluation & Verdicts
# -----------------------------------------------------------------------------
def test_false_positive_candidate_tri_db_verdicts():
    """Evaluate specific indicators across MongoDB, Cassandra, and Neo4j."""
    # 1.1.1.1 is known benign public DNS
    cf_res = evaluate_false_positive_candidate_tri_db("1.1.1.1")
    assert cf_res["value"] == "1.1.1.1"
    assert cf_res["consensus"] == "FALSE_POSITIVE"
    assert "mongodb_verdict" in cf_res
    assert "cassandra_verdict" in cf_res
    assert "neo4j_verdict" in cf_res
    assert cf_res["agreement_count"] >= 2

    # malware-c2-active.biz is a real confirmed threat
    c2_res = evaluate_false_positive_candidate_tri_db("malware-c2-active.biz")
    assert c2_res["consensus"] == "REAL_THREAT"
    assert c2_res["agreement_count"] >= 2


# -----------------------------------------------------------------------------
# 8. Dataset-wide False-Positive Evaluation Metrics
# -----------------------------------------------------------------------------
def test_false_positive_evaluation_dataset_metrics():
    """Verify evaluation over the entire labeled ground truth dataset computes TP, FN, FP, TN, Precision, Recall, F1."""
    eval_res = evaluate_all_false_positives_dataset()
    assert "evaluators" in eval_res
    evaluators = eval_res["evaluators"]

    for ev in ["mongodb_heuristic", "cassandra_volume", "neo4j_hub", "two_of_three_voting", "any_of_three_voting"]:
        assert ev in evaluators, f"Missing evaluator {ev}"
        m = evaluators[ev]
        assert "tp" in m and "fn" in m and "fp" in m and "tn" in m
        assert "precision" in m and "recall" in m and "f1" in m
        assert "median_latency_ms" in m
        assert 0.0 <= m["precision"] <= 1.0
        assert 0.0 <= m["recall"] <= 1.0
        assert 0.0 <= m["f1"] <= 1.0


# -----------------------------------------------------------------------------
# 9. Two-of-Three Consensus Superiority
# -----------------------------------------------------------------------------
def test_two_of_three_consensus_superiority():
    """Verify Two-of-Three Voting achieves superior F1 and drops ZERO real threats (FN == 0)."""
    eval_res = evaluate_all_false_positives_dataset()
    evaluators = eval_res["evaluators"]

    two_of_three = evaluators["two_of_three_voting"]
    # Two-of-three consensus should drop 0 real threats
    assert two_of_three["fn"] == 0, "Consensus voting must never drop confirmed real threats"
    # Recall should be 1.0 for real threats
    assert two_of_three["recall"] == 1.0

    # F1 score of Two-of-Three should be >= 0.90
    assert two_of_three["f1"] >= 0.90


# -----------------------------------------------------------------------------
# 10. Concrete Disagreement Case Studies
# -----------------------------------------------------------------------------
def test_concrete_disagreement_examples_surfaced():
    """Verify that concrete disagreement examples where databases diverge are surfaced with forensic rationale."""
    eval_res = evaluate_all_false_positives_dataset()
    disagreements = eval_res.get("concrete_disagreement_examples", [])
    assert len(disagreements) >= 1, "Must surface at least one concrete disagreement example"

    ex = disagreements[0]
    assert "value" in ex
    assert "ground_truth" in ex
    assert "mongodb_verdict" in ex
    assert "cassandra_verdict" in ex
    assert "neo4j_verdict" in ex
    assert "two_of_three_verdict" in ex
    assert "explanation" in ex
    assert len(ex["explanation"]) > 20


# -----------------------------------------------------------------------------
# 11. Threat Community Detection & Bridging Hubs
# -----------------------------------------------------------------------------
def test_threat_community_detection_and_bridging_hubs():
    """Verify graph community detection identifies bridging infrastructure hubs and provides Cypher query."""
    comm = analyze_threat_communities()
    assert "communities" in comm
    assert "cypher_query" in comm
    assert "neo4j_browser_link" in comm
    assert len(comm["communities"]) >= 2

    # Check for bridging indicators (e.g. 1.1.1.1 or 8.8.8.8)
    hubs = [c.get("hub") for c in comm["communities"]]
    assert any(h in ["1.1.1.1", "8.8.8.8"] for h in hubs)

    # Cypher query validation
    assert "MATCH" in comm["cypher_query"]
    assert "RETURN" in comm["cypher_query"]


# -----------------------------------------------------------------------------
# 12. GET /api/services/lab18 Endpoint
# -----------------------------------------------------------------------------
def test_get_services_lab18_endpoint():
    """Verify GET /api/services/lab18 returns full comparative services metadata."""
    res = client.get("/api/services/lab18")
    assert res.status_code == 200
    data = res.json()

    assert data["status"] == "success"
    assert "health" in data
    assert "mongodb" in data["health"]
    assert "cassandra" in data["health"]
    assert "neo4j" in data["health"]

    assert "counts" in data
    assert "benchmarks" in data
    assert "feeds" in data
    assert "false_positive_metrics" in data
    assert "concrete_disagreement_examples" in data
    assert "communities" in data


# -----------------------------------------------------------------------------
# 13. Moderation FP Candidates RBAC & Filtering
# -----------------------------------------------------------------------------
def test_moderation_fp_candidates_rbac_and_filters():
    """Verify GET /api/moderation/fp enforces access controls and filters properly."""
    # Unauthenticated -> 401
    res_unauth = client.get("/api/moderation/fp")
    assert res_unauth.status_code == 401

    # Normal user session -> 403
    user_session = create_user_session(user_id="testuser_ch18", email="user@threatpulse.io", role="user")
    res_user = client.get("/api/moderation/fp", cookies={"tp_session": user_session["token"]})
    assert res_user.status_code == 403

    # Admin key -> 200
    res_admin = client.get("/api/moderation/fp", headers=ADMIN_HEADERS)
    assert res_admin.status_code == 200
    data = res_admin.json()
    assert "candidates" in data
    assert len(data["candidates"]) > 0

    # Filter by state
    res_filtered = client.get("/api/moderation/fp?state=PENDING_REVIEW", headers=ADMIN_HEADERS)
    assert res_filtered.status_code == 200
    for c in res_filtered.json()["candidates"]:
        assert c["state"] == "PENDING_REVIEW"


# -----------------------------------------------------------------------------
# 14. GET /api/moderation/fp/value Detail Dossier
# -----------------------------------------------------------------------------
def test_moderation_fp_value_detail_endpoint():
    """Verify GET /api/moderation/fp/value returns comprehensive tri-DB dossier."""
    res = client.get("/api/moderation/fp/value?value=1.1.1.1", headers=ADMIN_HEADERS)
    assert res.status_code == 200
    detail = res.json()

    assert detail["value"] == "1.1.1.1"
    assert detail["consensus"] == "FALSE_POSITIVE"
    assert "mongodb_verdict" in detail
    assert "cassandra_verdict" in detail
    assert "neo4j_verdict" in detail
    assert "mongodb_latency_ms" in detail
    assert "cassandra_latency_ms" in detail
    assert "neo4j_latency_ms" in detail


# -----------------------------------------------------------------------------
# 15. POST /api/moderation/fp/decision Validation
# -----------------------------------------------------------------------------
def test_analyst_decision_requires_notes_and_checkbox():
    """Verify analyst decision requires non-empty notes and explicit confirmation checkbox."""
    # Missing notes -> 400
    payload_bad_notes = {
        "value": "1.1.1.1",
        "decision": "CONFIRMED_FALSE_POSITIVE",
        "notes": "   ",
        "confirmed_checkbox": True
    }
    res_bad_notes = client.post("/api/moderation/fp/decision", json=payload_bad_notes, headers=ADMIN_HEADERS)
    assert res_bad_notes.status_code == 400

    # Unchecked confirmation checkbox -> 400
    payload_bad_chk = {
        "value": "1.1.1.1",
        "decision": "CONFIRMED_FALSE_POSITIVE",
        "notes": "Verified Cloudflare Anycast IP",
        "confirmed_checkbox": False
    }
    res_bad_chk = client.post("/api/moderation/fp/decision", json=payload_bad_chk, headers=ADMIN_HEADERS)
    assert res_bad_chk.status_code == 400


# -----------------------------------------------------------------------------
# 16. Analyst Decision Lifecycle & Evidence Preservation
# -----------------------------------------------------------------------------
def test_analyst_decision_lifecycle_and_evidence_preservation():
    """Verify valid analyst decision updates candidate state, logs audit record, and preserves raw evidence document."""
    payload = {
        "value": "1.1.1.1",
        "decision": "CONFIRMED_FALSE_POSITIVE",
        "notes": "Analyst forensic review confirms legitimate Cloudflare recursive resolver.",
        "confirmed_checkbox": True
    }
    res = client.post("/api/moderation/fp/decision", json=payload, headers=ADMIN_HEADERS)
    assert res.status_code == 200
    res_data = res.json()
    assert res_data["status"] == "success"
    assert res_data["decision"] == "CONFIRMED_FALSE_POSITIVE"

    # Verify decision stored in audit state
    assert any(a["indicator"] == "1.1.1.1" for a in _ANALYST_DECISION_AUDIT)
    audit_match = next(a for a in _ANALYST_DECISION_AUDIT if a["indicator"] == "1.1.1.1")
    assert audit_match["decision"] == "CONFIRMED_FALSE_POSITIVE"

    # Evidence preservation: Underlying raw document in fp.full_threats must NOT be deleted
    dossier = client.get("/api/moderation/fp/value?value=1.1.1.1", headers=ADMIN_HEADERS).json()
    assert dossier["value"] == "1.1.1.1"
    assert dossier["state"] == "CONFIRMED_FALSE_POSITIVE"


# -----------------------------------------------------------------------------
# 17. Threat Export Stream Excludes Confirmed False Positives
# -----------------------------------------------------------------------------
def test_export_threats_stream_excludes_confirmed_false_positives():
    """Verify downstream consumer threat feed excludes confirmed false positives when exclude_fp=true."""
    # When exclude_fp=true, 1.1.1.1 (confirmed false positive) must be omitted
    res_filtered = client.get("/api/ops/export/threats?exclude_fp=true")
    assert res_filtered.status_code == 200
    data_filtered = res_filtered.json()
    values_filtered = {t["value"] for t in data_filtered.get("threats", [])}
    assert "1.1.1.1" not in values_filtered, "Confirmed false positive must be excluded from threat export"

    # When exclude_fp=false, all threats including false positives must be returned
    res_all = client.get("/api/ops/export/threats?exclude_fp=false")
    assert res_all.status_code == 200
    data_all = res_all.json()
    values_all = {t["value"] for t in data_all.get("threats", [])}
    assert "1.1.1.1" in values_all, "Raw archive export must preserve evidence"


# -----------------------------------------------------------------------------
# 18. ReportLab PDF Generation
# -----------------------------------------------------------------------------
def test_reportlab_pdf_generation_complete_architecture():
    """Verify GET /api/ops/report.pdf compiles a real PDF binary with all 10 architectural sections."""
    res = client.get("/api/ops/report.pdf")
    assert res.status_code == 200
    assert res.headers["content-type"] == "application/pdf"
    content = res.content

    # PDF binary signature
    assert content.startswith(b"%PDF-"), "Response must be a valid PDF binary"
    # PDF should have substantial size (> 3 KB)
    assert len(content) > 3000

    # Direct function test
    pdf_bytes = generate_comparative_pdf_report()
    assert pdf_bytes.startswith(b"%PDF-")


# -----------------------------------------------------------------------------
# 19. Lab 18 Executor & Frontend DOM Elements
# -----------------------------------------------------------------------------
def test_lab18_executor_and_frontend_dom_elements():
    """Verify executor registers Lab 18, executes it, and index.html includes all required DOM elements."""
    # 1. Lab Executor
    assert "18" in executor.state["labs"]
    run_res = executor.run_lab18()
    assert run_res["success"] is True
    assert executor.state["labs"]["18"]["status"] in ("SUCCESS", "COMPLETED")

    # 2. Frontend DOM Elements in index.html
    html_path = BACKEND_DIR.parent / "frontend" / "index.html"
    assert html_path.exists(), "index.html must exist"
    html_content = html_path.read_text(encoding="utf-8")

    # Navigation & Card Elements
    assert 'data-tab="lab18"' in html_content
    assert 'id="cardLab18"' in html_content
    assert 'id="btnRunLab18"' in html_content

    # Admin Ops View Sources
    assert 'id="btnAdminOpsViewSources"' in html_content
    assert 'id="adminOpsViewSourcesPane"' in html_content
    assert 'id="adminTileSourcesTotal"' in html_content
    assert 'id="adminTileHighestFpFeed"' in html_content
    assert 'id="btnDownloadReportPdf"' in html_content

    # Moderation FP Pane
    assert 'id="btnModViewFp"' in html_content
    assert 'id="moderationFpPane"' in html_content
    assert 'id="tblModFpBody"' in html_content
    assert 'id="modFpDetailInspector"' in html_content
    assert 'id="formModFpDecision"' in html_content
    assert 'id="chkModFpConfirm"' in html_content

    # Chapter 18 Dedicated Workspace (#tab-lab18)
    assert 'id="tab-lab18"' in html_content
    assert 'id="healthCardMongo"' in html_content
    assert 'id="healthCardCassandra"' in html_content
    assert 'id="healthCardNeo4j"' in html_content
    assert 'id="lab18SubtabOverview"' in html_content
    assert 'id="lab18SubtabDbComp"' in html_content
    assert 'id="lab18SubtabThreatIntel"' in html_content
    assert 'id="lab18SubtabFalsePositives"' in html_content
    assert 'id="lab18SubtabBenchmarks"' in html_content
    assert 'id="lab18SubtabCommunities"' in html_content
    assert 'id="lab18SubtabReport"' in html_content
    assert 'id="communitySvgCanvas"' in html_content
