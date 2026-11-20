"""
ThreatPulse SOC Platform - Chapter 16 Automated Test Suite.
Validates the Three-Database Architecture:
1. MongoDB: Authoritative Accounts, Risky Transactions, and Evidence Payloads.
2. Apache Cassandra: Distributed Audit-Event Store, Partition Key CQL Queries, Timelines.
3. Neo4j: Index-Free Adjacency Graph, Multi-Hop Traversals, Shared Devices, and Fraud Rings.
4. Circuit Breakers: Fault Tolerance, Graceful Fallback, State Transitions.
5. Forensic Dossier: Multi-DB Correlation, Provenance Latencies, and Non-Negative Skip Policy.
"""

import os
import sys
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
from routes.lab16 import (
    CircuitBreaker,
    _cassandra_cb,
    _neo4j_cb,
    _MONGO_ACCOUNTS,
    _CASSANDRA_AUDIT_LOGS,
    _NEO4J_GRAPH_NODES,
    _NEO4J_GRAPH_EDGES,
    _pending_audit_queue,
    traverse_graph_3hops,
    evaluate_fraud_verdict
)

client = TestClient(app)

ADMIN_HEADERS = {"X-Admin-Key": ADMIN_API_KEY, "X-Admin-Confirm": "true"}

_admin_session = create_user_session(user_id="sec_admin_01", email="admin@threatpulse.io", role="admin")
_mod_session = create_user_session(user_id="fraud_analyst_01", email="analyst@threatpulse.io", role="moderator")
_user_session = create_user_session(user_id="user_unauth", email="user@threatpulse.io", role="user")

ADMIN_COOKIE = {"tp_session": _admin_session["token"]}
MOD_COOKIE = {"tp_session": _mod_session["token"]}
USER_COOKIE = {"tp_session": _user_session["token"]}


# -----------------------------------------------------------------------------
# 1. Route Registration Tests
# -----------------------------------------------------------------------------
def test_fastapi_route_registration_lab16():
    """Verifies all Chapter 16 API and client endpoints are mounted in FastAPI."""
    routes = [r.path for r in app.routes]

    # Required API routes
    assert "/api/services/lab16" in routes
    assert "/api/services/lab16/start" in routes
    assert "/api/services/lab16/stop" in routes
    assert "/api/ops/audit" in routes
    assert "/api/ops/audit/summary" in routes
    assert "/api/moderation/fraud" in routes
    assert "/api/moderation/fraud/{account_id}" in routes
    assert "/api/labs/16/run" in routes

    # Client Single-Page App route
    assert "/extras/lab16" in routes


# -----------------------------------------------------------------------------
# 2. Services Health & JVM Memory Requirements
# -----------------------------------------------------------------------------
def test_get_services_lab16_health_and_memory_notice():
    """Validates real health reporting for MongoDB, Cassandra, and Neo4j, plus JVM notice."""
    res = client.get("/api/services/lab16")
    assert res.status_code == 200
    data = res.json()

    assert data["status"] == "success"
    assert "services" in data
    assert "mongoDb" in data["services"]
    assert "cassandra" in data["services"]
    assert "neo4j" in data["services"]

    # Validates JVM Memory Notice
    assert "memoryRequirementsNotice" in data
    assert "Cassandra" in data["memoryRequirementsNotice"]
    assert "Neo4j" in data["memoryRequirementsNotice"]
    assert "heap" in data["memoryRequirementsNotice"]

    # Circuit breaker states reported
    assert "circuitBreakers" in data
    assert data["circuitBreakers"]["cassandra"]["state"] in ("CLOSED", "OPEN", "HALF_OPEN")
    assert data["circuitBreakers"]["neo4j"]["state"] in ("CLOSED", "OPEN", "HALF_OPEN")

    # Links present
    assert "links" in data
    assert "grafana" in data["links"]
    assert "prometheus" in data["links"]


# -----------------------------------------------------------------------------
# 3. Circuit Breaker Behavior & State Transitions
# -----------------------------------------------------------------------------
def test_circuit_breaker_transitions_and_trip():
    """Validates CircuitBreaker unit logic: CLOSED -> failures -> OPEN -> HALF_OPEN -> CLOSED."""
    cb = CircuitBreaker("test_breaker", failure_threshold=2, recovery_timeout_sec=0.1)
    assert cb.state == "CLOSED"
    assert cb.can_attempt() is True

    # Record 1 failure - still closed
    cb.record_failure()
    assert cb.state == "CLOSED"

    # Record 2nd failure - trips OPEN
    cb.record_failure()
    assert cb.state == "OPEN"
    assert cb.can_attempt() is False

    # Wait for recovery timeout
    time.sleep(0.12)
    assert cb.can_attempt() is True
    assert cb.state == "HALF_OPEN"

    # Record success -> resets to CLOSED
    cb.record_success()
    assert cb.state == "CLOSED"
    assert cb.failure_count == 0

    # Test explicit manual trip
    cb.trip_open()
    assert cb.state == "OPEN"


# -----------------------------------------------------------------------------
# 4. Service Management (Start & Stop Controls)
# -----------------------------------------------------------------------------
def test_service_management_start_and_stop_lifecycle():
    """Tests POST /api/services/lab16/stop and /start with administrator authentication."""
    # 1. Stop Services: trips breakers to OPEN
    res_stop = client.post("/api/services/lab16/stop", headers=ADMIN_HEADERS)
    assert res_stop.status_code == 200
    stop_data = res_stop.json()
    assert stop_data["status"] == "success"
    assert stop_data["services"]["cassandra"] == "STOPPED"
    assert stop_data["services"]["neo4j"] == "STOPPED"
    assert stop_data["circuitBreakers"]["cassandra"] == "OPEN"
    assert stop_data["circuitBreakers"]["neo4j"] == "OPEN"

    # 2. Start Services: resets breakers to CLOSED and flushes pending queue
    res_start = client.post("/api/services/lab16/start", headers=ADMIN_HEADERS)
    assert res_start.status_code == 200
    start_data = res_start.json()
    assert start_data["status"] == "success"
    assert start_data["services"]["cassandra"] in ("RUNNING", "ONLINE")
    assert start_data["services"]["neo4j"] in ("RUNNING", "ONLINE")
    assert start_data["circuitBreakers"]["cassandra"] == "CLOSED"
    assert start_data["circuitBreakers"]["neo4j"] == "CLOSED"


def test_service_management_unauthorized_refusal():
    """Verifies that non-admin callers cannot start or stop cluster services."""
    # Missing credentials
    res_unauth = client.post("/api/services/lab16/start")
    assert res_unauth.status_code in (401, 403)

    # Standard user session
    res_user = client.post("/api/services/lab16/stop", cookies=USER_COOKIE)
    assert res_user.status_code == 403


# -----------------------------------------------------------------------------
# 5. Cassandra Distributed Audit Queries & CQL Metrics
# -----------------------------------------------------------------------------
def test_cassandra_audit_time_based_retrieval_and_cql():
    """Validates querying audit events by day with CQL generation and measured execution latency."""
    res = client.get("/api/ops/audit")
    assert res.status_code == 200
    data = res.json()

    assert data["status"] == "success"
    assert "events" in data
    assert isinstance(data["events"], list)
    assert len(data["events"]) > 0

    # Validates CQL query reporting and execution latency
    assert "executedCql" in data
    assert "threatpulse_audit.audit_events_by_day" in data["executedCql"]
    assert "executionDurationMs" in data
    assert isinstance(data["executionDurationMs"], (int, float))
    assert data["executionDurationMs"] >= 0.0

    # Checks event schema
    first = data["events"][0]
    assert "eventId" in first
    assert "timestamp" in first
    assert "actor" in first
    assert "role" in first
    assert "action" in first
    assert "resource" in first
    assert "outcome" in first
    assert "ipAddress" in first


def test_cassandra_audit_actor_filtering():
    """Validates querying audit events by actor with clustering column CQL query."""
    res = client.get("/api/ops/audit?actor=admin_01&limit=200")
    assert res.status_code == 200
    data = res.json()

    assert data["status"] == "success"
    assert "audit_events_by_actor" in data["executedCql"]
    assert "admin_01" in data["executedCql"]
    for ev in data["events"]:
        assert ev["actor"] == "admin_01"


def test_cassandra_audit_combined_filters():
    """Verifies query parameters can be combined safely (day, role, action, outcome, limit)."""
    res = client.get("/api/ops/audit?role=admin&outcome=SUCCESS&limit=5")
    assert res.status_code == 200
    data = res.json()

    assert data["status"] == "success"
    assert len(data["events"]) <= 5
    for ev in data["events"]:
        assert ev["role"] == "admin"
        assert ev["outcome"] == "SUCCESS"


# -----------------------------------------------------------------------------
# 6. Cassandra 7-Day Audit Summary & Stacked Categories
# -----------------------------------------------------------------------------
def test_cassandra_audit_summary_7days_and_stacked_categories():
    """Validates GET /api/ops/audit/summary?days=7 metric tiles and stacked chart payload."""
    res = client.get("/api/ops/audit/summary?days=7")
    assert res.status_code == 200
    data = res.json()

    assert data["status"] == "success"
    assert "summary" in data
    s = data["summary"]

    # 5 Summary Metrics
    assert "eventsToday" in s
    assert "sevenDayTotal" in s
    assert "mostFrequentAction" in s
    assert "failedRefusedCount" in s
    assert "cassandraQueryDurationMs" in s
    assert isinstance(s["cassandraQueryDurationMs"], (int, float))

    # Stacked chart dataset
    assert "dailyStacked" in s
    assert len(s["dailyStacked"]) == 7
    for day_record in s["dailyStacked"]:
        assert "date" in day_record
        assert "categories" in day_record
        cats = day_record["categories"]
        for cat in ("sign-ins", "cases", "accounts", "labs", "reviews", "other"):
            assert cat in cats
            assert isinstance(cats[cat], int)


def test_cassandra_fallback_when_circuit_breaker_open():
    """Ensures that when Cassandra breaker is OPEN, audit queries return cached/graceful data."""
    _cassandra_cb.trip_open()
    try:
        res = client.get("/api/ops/audit?limit=10")
        assert res.status_code == 200
        data = res.json()
        assert data["status"] == "success"
        assert "events" in data
    finally:
        _cassandra_cb.record_success()


# -----------------------------------------------------------------------------
# 7. MongoDB Authoritative Account & Evidence Models
# -----------------------------------------------------------------------------
def test_mongodb_authoritative_account_and_evidence_models():
    """Validates authoritative accounts and risky transaction evidence in MongoDB model."""
    assert "ACC-89101" in _MONGO_ACCOUNTS
    acc = _MONGO_ACCOUNTS["ACC-89101"]

    assert acc["accountId"] == "ACC-89101"
    assert acc["suspicious"] is True
    assert acc["failedLogins"] > 0
    assert acc["highValueTransactions"] > 0
    assert len(acc.get("evidence", [])) > 0

    first_ev = acc["evidence"][0]
    assert "type" in first_ev
    assert "description" in first_ev
    assert "timestamp" in first_ev


# -----------------------------------------------------------------------------
# 8. Neo4j Graph Model & Multi-Hop Traversal
# -----------------------------------------------------------------------------
def test_neo4j_graph_model_and_shared_device_detection():
    """Validates Neo4j nodes, edges, and shared device linking between accounts."""
    # Traversal starting from high-risk account
    traversal = traverse_graph_3hops("ACC-89101", max_depth=3)

    assert "nodes" in traversal
    assert "relationships" in traversal
    assert "shared_devices_count" in traversal

    node_ids = [n["id"] for n in traversal["nodes"]]
    assert "ACC-89101" in node_ids
    assert "DEV-IPHONE-14" in node_ids
    assert "ACC-40291" in node_ids  # Shared device neighbor

    # Edge checks
    edge_types = [e["type"] for e in traversal["relationships"]]
    assert "USED_DEVICE" in edge_types
    assert "TRANSFERRED_TO" in edge_types

    # Shared device count > 0
    assert traversal["shared_devices_count"] >= 1


def test_neo4j_multi_hop_traversal_depth():
    """Validates that expanding depth from 1 to 3 hops reveals additional fraud ring nodes."""
    d1 = traverse_graph_3hops("ACC-89101", max_depth=1)
    d3 = traverse_graph_3hops("ACC-89101", max_depth=3)

    assert len(d3["nodes"]) >= len(d1["nodes"])
    assert len(d3["relationships"]) >= len(d1["relationships"])


# -----------------------------------------------------------------------------
# 9. Fraud Review & Multi-Database Dossier
# -----------------------------------------------------------------------------
def test_fraud_review_accounts_overview():
    """Validates GET /api/moderation/fraud overview list of accounts."""
    res = client.get("/api/moderation/fraud", headers=ADMIN_HEADERS)
    assert res.status_code == 200
    data = res.json()

    assert data["status"] == "success"
    assert "accounts" in data
    assert len(data["accounts"]) >= 5

    # Check required fields per account
    for acc in data["accounts"]:
        assert "accountId" in acc
        assert "riskIndicators" in acc
        assert "sharedDevicesCount" in acc
        assert "relatedAccounts" in acc
        assert "investigationStatus" in acc
        assert acc["investigationStatus"] in ("Clean", "Inconclusive", "Fraudulent")


def test_fraud_review_account_dossier_provenance_and_timings():
    """Validates multi-database forensic dossier with explicit provenance and query timings."""
    res = client.get("/api/moderation/fraud/ACC-89101", headers=ADMIN_HEADERS)
    assert res.status_code == 200
    data = res.json()

    assert data["status"] == "success"
    assert "dossier" in data
    d = data["dossier"]

    assert d["accountId"] == "ACC-89101"
    assert d["fraudVerdict"] == "Fraudulent"

    # MongoDB Evidence
    assert "mongoEvidence" in d
    assert d["mongoEvidence"]["suspicious"] is True
    assert len(d["mongoEvidence"]["evidence"]) > 0

    # Cassandra Timeline
    assert "cassandraTimeline" in d
    assert isinstance(d["cassandraTimeline"], list)
    assert "cassandraTimelineQuery" in d
    assert "SELECT *" in d["cassandraTimelineQuery"]

    # Neo4j Graph
    assert "neo4jGraph" in d
    assert "nodes" in d["neo4jGraph"]
    assert "relationships" in d["neo4jGraph"]

    # Provenance Execution Timings
    assert "executionTimingsMs" in d
    timings = d["executionTimingsMs"]
    assert "mongoDbMs" in timings
    assert "cassandraMs" in timings
    assert "neo4jMs" in timings
    assert "totalMs" in timings


def test_fraud_verdict_resilience_missing_db_not_negative():
    """
    CRITICAL REQUIREMENT: Never treat missing data from a skipped/offline database
    as a negative fraud verdict. Missing Cassandra or Neo4j data must yield 'Inconclusive'
    or maintain suspicion.
    """
    # 1. Clean account with all DBs online -> Clean
    v_clean = evaluate_fraud_verdict("ACC-10045", {"suspicious": False, "failedLogins": 0}, [], {"shared_devices_count": 0}, cass_ok=True, neo_ok=True)
    assert v_clean == "Clean"

    # 2. Clean account BUT Cassandra is offline -> INCONCLUSIVE (never negative verdict!)
    v_inconclusive_cass = evaluate_fraud_verdict("ACC-10045", {"suspicious": False, "failedLogins": 0}, [], {"shared_devices_count": 0}, cass_ok=False, neo_ok=True)
    assert v_inconclusive_cass == "Inconclusive"

    # 3. Clean account BUT Neo4j is offline -> INCONCLUSIVE
    v_inconclusive_neo = evaluate_fraud_verdict("ACC-10045", {"suspicious": False, "failedLogins": 0}, [], {"shared_devices_count": 0}, cass_ok=True, neo_ok=False)
    assert v_inconclusive_neo == "Inconclusive"

    # 4. High-risk account with strong MongoDB evidence remains Fraudulent
    v_fraud = evaluate_fraud_verdict("ACC-89101", {"suspicious": True, "failedLogins": 5}, [], {}, cass_ok=False, neo_ok=False)
    assert v_fraud == "Fraudulent"


def test_moderation_fraud_role_access_control():
    """Ensures moderator or admin credentials are required for fraud review."""
    # Unauthenticated rejected
    res_unauth = client.get("/api/moderation/fraud")
    assert res_unauth.status_code in (401, 403)

    # Moderator session accepted
    res_mod = client.get("/api/moderation/fraud", cookies=MOD_COOKIE)
    assert res_mod.status_code == 200

    # Admin session accepted
    res_admin = client.get("/api/moderation/fraud", cookies=ADMIN_COOKIE)
    assert res_admin.status_code == 200


# -----------------------------------------------------------------------------
# 10. Lab 16 Executor & Pipeline Integration
# -----------------------------------------------------------------------------
def test_lab16_executor_verification_run():
    """Validates LabExecutionManager execution of Lab 16."""
    res = executor.run_lab16()
    assert res["success"] is True
    assert "summary" in res

    state = executor.get_status()
    assert "16" in state["labs"]
    lab16 = state["labs"]["16"]
    assert lab16["status"] == "SUCCESS"
    assert lab16["progressPct"] == 100
    assert lab16["results"]["status"] == "ALL CHAPTER 16 THREE-DATABASE VERIFICATIONS COMPLETE"
    assert "circuitBreakers" in lab16["results"]
    assert "graphVerification" in lab16["results"]


# -----------------------------------------------------------------------------
# 11. Frontend DOM & HTML Structural Assertions
# -----------------------------------------------------------------------------
def test_frontend_html_and_dom_elements_lab16():
    """Verifies all required Chapter 16 DOM elements, tabs, tiles, and charts exist in index.html."""
    html_path = BACKEND_DIR.parent / "frontend" / "index.html"
    assert html_path.exists()
    content = html_path.read_text(encoding="utf-8")

    # 1. Subnav item
    assert 'data-tab="lab16"' in content

    # 2. Lab 16 Dedicated Workspace (/extras/lab16)
    assert 'id="tab-lab16"' in content
    assert 'lab16SubtabOverview' in content
    assert 'lab16SubtabServices' in content
    assert 'lab16SubtabAudit' in content
    assert 'lab16SubtabFraud' in content
    assert 'lab16SubtabGraph' in content

    # 3. Service Management Controls & Memory Notice
    assert 'btnStartLab16Services' in content
    assert 'btnStopLab16Services' in content
    assert 'JVM Memory Requirements Notice' in content

    # 4. Admin Ops Audit Log (/admin/ops?tab=audit)
    assert 'btnAdminOpsViewAudit' in content
    assert 'adminOpsViewAuditPane' in content
    assert 'auditTileToday' in content
    assert 'auditTileTotal' in content
    assert 'auditTileAction' in content
    assert 'auditTileFailed' in content
    assert 'auditTileDuration' in content
    assert 'auditExecutedCql' in content
    assert 'chart16DailyAuditStacked' in content
    assert 'tblAuditLogs' in content

    # 5. Moderation Fraud Review (/moderation?tab=fraud)
    assert 'btnModViewFraud' in content
    assert 'moderationFraudPane' in content
    assert 'tblModFraudAccounts' in content
    assert 'fraudDossierContainer' in content
    assert 'svgNeo4jGraph' in content
    assert 'graphInspectorPanel' in content

    # 6. Lab Runner Card
    assert 'cardLab16' in content
    assert 'btnRunLab16' in content
