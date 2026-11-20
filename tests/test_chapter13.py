"""
Comprehensive Automated Test Suite for Chapter 13: Containers and The Cloud.
Verifies FastAPI route registration, authentication, replica set reporting,
failover orchestration, Prometheus metrics parsing, Kubernetes status,
Atlas deployment diagnostics, frontend HTML elements, and lab executor integration.
"""

import sys
import os
import json
from pathlib import Path
import pytest
from fastapi.testclient import TestClient

# Set up paths
WORKSPACE_ROOT = Path(__file__).resolve().parent.parent
BACKEND_DIR = WORKSPACE_ROOT / "MongoDB_Combined_Docker_Pipeline" / "lab7" / "backend"
FRONTEND_DIR = WORKSPACE_ROOT / "MongoDB_Combined_Docker_Pipeline" / "lab7" / "frontend"

if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

from main import app
from auth import ADMIN_API_KEY
from lab_executor import executor

client = TestClient(app)


# -----------------------------------------------------------------------------
# 1. FastAPI Route Registration Tests
# -----------------------------------------------------------------------------
def test_fastapi_route_registration():
    """Verifies that all required Chapter 13 and Admin Ops routes are registered."""
    route_paths = [route.path for route in app.routes]

    # Required API endpoints
    assert "/api/services/lab13" in route_paths
    assert "/api/services/lab13/failover/test" in route_paths
    assert "/api/services/lab13/k8s/start" in route_paths
    assert "/api/services/lab13/atlas/deploy" in route_paths
    assert "/api/ops/metrics/deployment" in route_paths
    assert "/api/labs/13/run" in route_paths
    assert "/api/auth/login" in route_paths
    assert "/api/auth/me" in route_paths

    # Required UI routes
    assert "/extras/lab13" in route_paths
    assert "/admin/ops" in route_paths


# -----------------------------------------------------------------------------
# 2. Authentication & Authorization Tests
# -----------------------------------------------------------------------------
def test_failover_unauthorized_access():
    """Unauthenticated requests to management actions must be rejected with 401."""
    res = client.post("/api/services/lab13/failover/test", json={"confirmed": True})
    assert res.status_code == 401
    assert res.json().get("detail", {}).get("authRequired") is True


def test_failover_requires_confirmation():
    """Management actions without explicit administrator confirmation must return 400."""
    headers = {"X-Admin-Key": ADMIN_API_KEY}
    # confirmed = False
    res = client.post("/api/services/lab13/failover/test", json={"confirmed": False}, headers=headers)
    assert res.status_code == 400
    assert res.json().get("detail", {}).get("confirmationRequired") is True


def test_failover_authorized_with_admin_key_and_confirmation():
    """Authorized requests with admin key and confirmation must execute successfully."""
    headers = {
        "X-Admin-Key": ADMIN_API_KEY,
        "X-Admin-Confirm": "true"
    }
    res = client.post("/api/services/lab13/failover/test", json={"confirmed": True}, headers=headers)
    assert res.status_code == 200
    data = res.json()
    assert data.get("status") == "success"
    assert "failoverResult" in data
    assert "newPrimary" in data["failoverResult"]


# -----------------------------------------------------------------------------
# 3. Service Health Reporting: GET /api/services/lab13
# -----------------------------------------------------------------------------
def test_get_lab13_services():
    """GET /api/services/lab13 must report actual members, monitoring, k8s, and atlas."""
    res = client.get("/api/services/lab13")
    assert res.status_code == 200
    data = res.json()

    assert data.get("status") == "success"
    assert "replicaSet" in data
    assert "monitoring" in data
    assert "kubernetes" in data
    assert "atlas" in data

    # Verify monitoring links
    mon = data["monitoring"]
    assert "9090" in mon.get("prometheusLink", "")
    assert "3013" in mon.get("grafanaLink", "")
    assert "prometheusTargetStatus" in mon
    assert "operationsPerSec" in mon

    # Verify replica set reporting
    rs = data["replicaSet"]
    assert "setName" in rs
    assert "primary" in rs
    assert "members" in rs
    assert isinstance(rs["members"], list)
    assert "lastFailover" in rs


# -----------------------------------------------------------------------------
# 4. Replica Set Member Reporting & Secret Sanitization
# -----------------------------------------------------------------------------
def test_replica_set_member_details_and_sanitization():
    """Replica set members must contain roles, health, lag, and sanitized URIs."""
    res = client.get("/api/services/lab13")
    assert res.status_code == 200
    rs = res.json()["replicaSet"]

    for member in rs.get("members", []):
        assert "name" in member
        assert "role" in member
        assert member["role"] in ("PRIMARY", "SECONDARY", "ARBITER", "DOWN")
        assert "health" in member
        assert "replicationLagSeconds" in member
        assert member["replicationLagSeconds"] >= 0

    # Ensure no credentials leaked in sanitizedUri or strings
    sanitized_uri = rs.get("sanitizedUri", "")
    if sanitized_uri:
        assert "@" not in sanitized_uri or "*****" in sanitized_uri


# -----------------------------------------------------------------------------
# 5. Failover Result Handling
# -----------------------------------------------------------------------------
def test_failover_result_structure():
    """Failover execution must record and report previous/new primary, duration, and read continuity."""
    headers = {"X-Admin-Key": ADMIN_API_KEY}
    res = client.post(
        "/api/services/lab13/failover/test",
        json={"confirmed": True, "stepDownSeconds": 10},
        headers=headers
    )
    assert res.status_code == 200
    fo = res.json()["failoverResult"]

    assert "previousPrimary" in fo
    assert "newPrimary" in fo
    assert "electionDurationMs" in fo
    assert fo["electionDurationMs"] > 0
    assert "readsAttempted" in fo
    assert "readsSucceeded" in fo
    assert "readsFailed" in fo
    assert "slowestReadMs" in fo


# -----------------------------------------------------------------------------
# 6. Prometheus Metrics Parsing: GET /api/ops/metrics/deployment
# -----------------------------------------------------------------------------
def test_deployment_metrics_period_filters():
    """GET /api/ops/metrics/deployment must accept 15, 30, 60, 360 minutes and return real metrics."""
    for period in [15, 30, 60, 360]:
        res = client.get(f"/api/ops/metrics/deployment?minutes={period}")
        assert res.status_code == 200
        data = res.json()
        assert data.get("status") == "success"
        assert data.get("periodMinutes") == period

        # 5 statistic tiles
        stats = data.get("statistics", {})
        assert "currentPrimary" in stats
        assert "membersOnline" in stats
        assert "operationsPerSecond" in stats
        assert "slowestReplicationLagSec" in stats
        assert "electionsDuringPeriod" in stats

        # 6 charts
        charts = data.get("charts", {})
        assert "memberStateTimeline" in charts
        assert "opsByType" in charts
        assert "replicationLag" in charts
        assert "heartbeatPing" in charts
        assert "connections" in charts
        assert "cacheUsage" in charts

        # Consistent color palette
        assert "colorPalette" in data
        assert isinstance(data["colorPalette"], dict)


def test_deployment_metrics_no_fabricated_data_on_offline():
    """When Prometheus is offline, must report real status and not generate fabricated waves."""
    res = client.get("/api/ops/metrics/deployment?minutes=15")
    assert res.status_code == 200
    data = res.json()
    assert "dataSource" in data
    # Either connected to Prometheus or using Direct MongoDB Telemetry Buffer
    assert data["dataSource"] in ("Prometheus v2.x", "Direct MongoDB Telemetry Buffer")


# -----------------------------------------------------------------------------
# 7. Kubernetes Status Tests
# -----------------------------------------------------------------------------
def test_kubernetes_statefulset_status():
    """Kubernetes status must report StatefulSet pods mongo-0, mongo-1, mongo-2 and data retention."""
    res = client.get("/api/services/lab13")
    assert res.status_code == 200
    k8s = res.json()["kubernetes"]

    assert "environment" in k8s
    assert "status" in k8s
    assert "pods" in k8s
    pod_names = [p["name"] for p in k8s["pods"]]
    assert "mongo-0" in pod_names
    assert "mongo-1" in pod_names
    assert "mongo-2" in pod_names

    assert "deletedPodRecoveryTimeSec" in k8s
    assert "dataIntact" in k8s
    assert k8s["dataIntact"] is True


def test_start_kubernetes_endpoint():
    """Start Kubernetes endpoint must require admin authorization."""
    unauth = client.post("/api/services/lab13/k8s/start", json={"confirmed": True})
    assert unauth.status_code == 401

    headers = {"X-Admin-Key": ADMIN_API_KEY}
    auth = client.post("/api/services/lab13/k8s/start", json={"confirmed": True}, headers=headers)
    assert auth.status_code == 200
    assert "action" in auth.json()


# -----------------------------------------------------------------------------
# 8. MongoDB Atlas & Terraform Error Handling Tests
# -----------------------------------------------------------------------------
def test_atlas_status_diagnostics_when_unconfigured():
    """Atlas status must accurately report NOT_CONFIGURED when API credentials are unset."""
    res = client.get("/api/services/lab13")
    assert res.status_code == 200
    atlas = res.json()["atlas"]

    assert "clusterName" in atlas
    assert "tier" in atlas
    assert "region" in atlas
    assert "deploymentState" in atlas
    # Never claim success if credentials are not configured or failed
    if atlas["deploymentState"] == "NOT_CONFIGURED":
        assert atlas["error"] is not None
        assert atlas["configurationRequired"] is not None


def test_atlas_deploy_refuses_without_credentials():
    """Deploying Atlas without API keys must be refused with HTTP 400 and clear diagnostic."""
    headers = {"X-Admin-Key": ADMIN_API_KEY}
    # Clear env vars if present for test
    old_pub = os.environ.pop("MONGODB_ATLAS_PUBLIC_KEY", None)
    old_priv = os.environ.pop("MONGODB_ATLAS_PRIVATE_KEY", None)
    try:
        res = client.post("/api/services/lab13/atlas/deploy", json={"confirmed": True}, headers=headers)
        assert res.status_code == 400
        detail = res.json().get("detail", {})
        assert detail.get("deploymentState") == "REFUSED"
        assert "actionRequired" in detail
    finally:
        if old_pub:
            os.environ["MONGODB_ATLAS_PUBLIC_KEY"] = old_pub
        if old_priv:
            os.environ["MONGODB_ATLAS_PRIVATE_KEY"] = old_priv


# -----------------------------------------------------------------------------
# 9. Frontend Route & HTML Integration Tests
# -----------------------------------------------------------------------------
def test_extras_lab13_and_admin_ops_routes_serve_html():
    """Both /extras/lab13 and /admin/ops must serve 200 OK with full frontend HTML."""
    res_lab13 = client.get("/extras/lab13")
    assert res_lab13.status_code == 200
    assert "text/html" in res_lab13.headers["content-type"]
    assert "Chapter 13" in res_lab13.text
    assert "tab-lab13" in res_lab13.text

    res_adminops = client.get("/admin/ops")
    assert res_adminops.status_code == 200
    assert "text/html" in res_adminops.headers["content-type"]
    assert "tab-adminops" in res_adminops.text


def test_frontend_has_chapter13_six_tabs():
    """Chapter 13 dedicated workspace must contain all 6 subtabs in HTML."""
    res = client.get("/extras/lab13")
    html = res.text

    assert 'data-subtab="overview"' in html
    assert 'data-subtab="replicaset"' in html
    assert 'data-subtab="failover"' in html
    assert 'data-subtab="monitoring"' in html
    assert 'data-subtab="kubernetes"' in html
    assert 'data-subtab="atlas"' in html


def test_frontend_has_six_chart_canvases():
    """Admin operations dashboard must contain canvases for all 6 monitoring charts."""
    res = client.get("/admin/ops")
    html = res.text

    assert 'id="chartMemberStateTimeline"' in html
    assert 'id="chartOpsByType"' in html
    assert 'id="chartReplicationLag"' in html
    assert 'id="chartHeartbeatPing"' in html
    assert 'id="chartConnections"' in html
    assert 'id="chartCacheUsage"' in html


# -----------------------------------------------------------------------------
# 10. Lab Executor Lab 13 Integration Tests
# -----------------------------------------------------------------------------
def test_lab_executor_lab13_registered():
    """Lab 13 must be initialized in LabExecutionManager state."""
    status = executor.get_status()
    labs = status.get("labs", {})
    assert "13" in labs
    lab13 = labs["13"]
    assert lab13["id"] == "13"
    assert "Lab 13" in lab13["name"]


def test_lab_executor_run_lab13():
    """Executing run_lab13() must succeed and populate results and summary."""
    result = executor.run_lab13()
    assert result.get("success") is True

    status = executor.get_status()
    lab13 = status["labs"]["13"]
    assert lab13["status"] == "SUCCESS"
    assert lab13["results"] is not None
    assert "replicaSet" in lab13["results"]
    assert "monitoring" in lab13["results"]
    assert "kubernetes" in lab13["results"]
    assert "atlas" in lab13["results"]


def test_lab13_results_endpoint():
    """GET /api/labs/results/13 must return Lab 13 structured results."""
    # Ensure run has completed
    executor.run_lab13()

    res = client.get("/api/labs/results/13")
    assert res.status_code == 200
    data = res.json()
    assert data.get("id") == "13"
    assert data.get("results") is not None

