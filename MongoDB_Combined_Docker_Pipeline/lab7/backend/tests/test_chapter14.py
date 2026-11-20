"""
ThreatPulse SOC Platform - Chapter 14 Test Suite.
Validates live database metrics, WiredTiger cache hit ratio, replication lag drift,
alert threshold detection, webhook ingestion, alert acknowledgement,
real BSON gzip backup creation, file existence & metadata, non-destructive restore verification,
RPO/RTO SLA auditing, RBAC security, and frontend HTML workspace integration.
"""

import os
import sys
import time
import pytest
from pathlib import Path

# Add backend directory to path
backend_path = Path(__file__).resolve().parent.parent / "MongoDB_Combined_Docker_Pipeline" / "lab7" / "backend"
sys.path.insert(0, str(backend_path))

from fastapi.testclient import TestClient
from main import app
from config import (
    ADMIN_API_KEY,
    BACKUP_STORAGE_DIR,
    BACKUP_RPO_TARGET_SEC,
    BACKUP_RTO_TARGET_SEC,
    CACHE_HIT_RATIO_WARNING_THRESHOLD,
    REPLICATION_LAG_WARNING_THRESHOLD
)
from lab_executor import executor
from routes.lab14 import (
    execute_real_backup,
    execute_restore_verification,
    _live_alerts,
    _backup_history,
    _alerts_lock,
    _backup_lock
)

client = TestClient(app)


# -----------------------------------------------------------------------------
# 1. FastAPI Route Registration Tests
# -----------------------------------------------------------------------------
def test_fastapi_route_registration_lab14():
    """All Chapter 14 and Moderation endpoints must be registered in the FastAPI app."""
    routes = [r.path for r in app.routes]

    # Required Chapter 14 service routes
    assert "/api/services/lab14" in routes
    assert "/api/ops/lab14/backup" in routes
    assert "/api/ops/lab14/verify" in routes
    assert "/api/services/lab14/webhook" in routes
    assert "/api/ops/metrics/monitoring" in routes

    # Moderation routes
    assert "/api/moderation/alerts" in routes
    assert "/api/moderation/alerts/ack" in routes

    # Frontend SPA routes
    assert "/extras/lab14" in routes
    assert "/admin/ops" in routes
    assert "/moderation" in routes


# -----------------------------------------------------------------------------
# 2. Service Health & Metadata Reporting: GET /api/services/lab14
# -----------------------------------------------------------------------------
def test_get_lab14_services_structure():
    """GET /api/services/lab14 must report live sample, alerts, backup history, benchmarks, RPO, and RTO."""
    res = client.get("/api/services/lab14")
    assert res.status_code == 200
    data = res.json()

    assert data.get("status") == "success"
    assert data.get("chapter") == 14
    assert "newestLiveMetricsSample" in data
    assert "liveAlerts" in data
    assert "unacknowledgedAlertsCount" in data
    assert "backupHistory" in data
    assert "backupBenchmark" in data
    assert "rpo" in data
    assert "rto" in data
    assert "storage" in data
    assert "warningThresholds" in data

    # Verify warning thresholds
    wt = data["warningThresholds"]
    assert wt["cacheHitRatio"] == 80.0
    assert wt["replicationLagSeconds"] == 10.0


def test_live_metrics_sample_values():
    """Live metrics sample must contain real cache hit ratio, usage, connections, and lag."""
    res = client.get("/api/services/lab14")
    assert res.status_code == 200
    sample = res.json()["newestLiveMetricsSample"]

    assert "cacheHitRatio" in sample
    assert 0.0 <= sample["cacheHitRatio"] <= 100.0
    assert "cacheUsageMB" in sample
    assert sample["cacheUsageMB"] >= 0.0
    assert "connections" in sample
    assert sample["connections"]["current"] >= 0
    assert "operationsPerSec" in sample
    assert "replicationLagSeconds" in sample
    assert isinstance(sample["replicationLagSeconds"], dict)
    assert sample["status"] in ("NORMAL", "WARNING", "CRITICAL")


# -----------------------------------------------------------------------------
# 3. Alert Generation & Webhook Ingestion Tests
# -----------------------------------------------------------------------------
def test_alert_threshold_detection_logic():
    """Alert evaluation must trigger warnings when hit ratio < 80% or lag > 10s."""
    from routes.lab14 import evaluate_and_generate_alerts

    # Test metric payload violating both thresholds
    violation_metrics = {
        "cacheHitRatio": 74.2,  # < 80%
        "replicationLagSeconds": {"mongo2:27017": 12.8},  # > 10s
        "primaryHost": "mongo1:27017"
    }

    alerts = evaluate_and_generate_alerts(violation_metrics)
    assert len(alerts) > 0

    # Ensure cache hit ratio alert exists
    chr_alert = next((a for a in alerts if a["metric"] == "cache_hit_ratio"), None)
    assert chr_alert is not None
    assert chr_alert["severity"] == "WARNING"
    assert chr_alert["threshold"] == 80.0
    assert chr_alert["acknowledged"] is False

    # Ensure replication lag alert exists
    lag_alert = next((a for a in alerts if a["metric"] == "replication_lag"), None)
    assert lag_alert is not None
    assert lag_alert["severity"] == "WARNING"
    assert lag_alert["threshold"] == 10.0


def test_webhook_alert_ingestion():
    """POST /api/services/lab14/webhook must accept Alertmanager payloads and add to live alerts."""
    payload = {
        "alerts": [
            {
                "labels": {
                    "alertname": "MongoDBTestExternalAlert",
                    "severity": "warning",
                    "instance": "mongo2:27017",
                    "metric": "replication_lag"
                },
                "annotations": {
                    "value": "15.4s",
                    "threshold": "10s"
                }
            }
        ]
    }

    res = client.post("/api/services/lab14/webhook", json=payload)
    assert res.status_code == 200
    data = res.json()
    assert data.get("status") == "success"
    assert data.get("ingestedCount") >= 1

    # Verify alert appears in live alerts
    services = client.get("/api/services/lab14").json()
    alert_names = [a.get("metricName") for a in services.get("liveAlerts", [])]
    assert "MongoDBTestExternalAlert" in alert_names


# -----------------------------------------------------------------------------
# 4. Moderation & Alert Acknowledgement Tests
# -----------------------------------------------------------------------------
def test_moderation_alerts_requires_authentication():
    """GET /api/moderation/alerts must require moderator or admin credentials."""
    unauth = client.get("/api/moderation/alerts")
    assert unauth.status_code == 401


def test_moderation_alerts_authorized_and_acknowledgement():
    """Moderator with admin key must list alerts and acknowledge open warnings."""
    headers = {"X-Admin-Key": ADMIN_API_KEY}
    res = client.get("/api/moderation/alerts", headers=headers)
    assert res.status_code == 200
    data = res.json()

    assert data.get("status") == "success"
    assert "openCount" in data
    assert "alerts" in data
    initial_open = data["openCount"]

    if initial_open > 0:
        # Find an unacknowledged alert
        unacked = next((a for a in data["alerts"] if not a.get("acknowledged")), None)
        assert unacked is not None

        # Acknowledge the alert
        ack_res = client.post(
            "/api/moderation/alerts/ack",
            json={"alertId": unacked["id"]},
            headers=headers
        )
        assert ack_res.status_code == 200
        ack_data = ack_res.json()
        assert ack_data.get("status") == "success"
        assert ack_data.get("openCount") == initial_open - 1

        # Check acknowledged properties
        acked_alert = ack_data["acknowledgedAlerts"][0]
        assert acked_alert["acknowledged"] is True
        assert acked_alert["acknowledgedAt"] is not None
        assert acked_alert["acknowledgedBy"] is not None


# -----------------------------------------------------------------------------
# 5. Real Backup Execution & File Existence Tests
# -----------------------------------------------------------------------------
def test_backup_requires_admin_and_confirmation():
    """Manual backup endpoint must require admin credentials and confirmation."""
    unauth = client.post("/api/ops/lab14/backup")
    assert unauth.status_code == 401

    headers_no_confirm = {"X-Admin-Key": ADMIN_API_KEY}
    unconfirmed = client.post("/api/ops/lab14/backup", headers=headers_no_confirm)
    assert unconfirmed.status_code == 400


def test_real_backup_creates_physical_file_on_disk():
    """POST /api/ops/lab14/backup must write a real gzip file to disk with real size and metadata."""
    headers = {
        "X-Admin-Key": ADMIN_API_KEY,
        "X-Admin-Confirm": "true"
    }

    res = client.post("/api/ops/lab14/backup", json={"confirmed": True}, headers=headers)
    assert res.status_code == 200
    data = res.json()
    assert data.get("status") == "success"

    b = data.get("backup", {})
    assert "id" in b
    assert "name" in b
    assert "path" in b
    assert "sizeMB" in b
    assert "sizeBytes" in b
    assert "checksum" in b
    assert b["status"] == "COMPLETED"

    # Verify physical file existence on disk
    file_path = b["path"]
    assert os.path.exists(file_path), f"Backup file '{file_path}' must exist on disk!"
    actual_disk_size = os.path.getsize(file_path)
    assert actual_disk_size > 0, "Backup file on disk must not be empty!"
    assert b["sizeBytes"] == actual_disk_size


# -----------------------------------------------------------------------------
# 6. Isolated Restore Verification Tests
# -----------------------------------------------------------------------------
def test_restore_verification_requires_admin():
    """Restore verification must require admin authentication."""
    unauth = client.post("/api/ops/lab14/verify")
    assert unauth.status_code == 401


def test_isolated_restore_verification_success():
    """Restore verification must test restore in isolated temporary database without overwriting production."""
    headers = {
        "X-Admin-Key": ADMIN_API_KEY,
        "X-Admin-Confirm": "true"
    }

    res = client.post("/api/ops/lab14/verify", json={"confirmed": True}, headers=headers)
    assert res.status_code == 200
    data = res.json()
    assert data.get("status") == "success"

    v = data.get("verification", {})
    assert v.get("verified") is True
    assert v.get("isolatedDatabase") == "threat_intel_verify_restore"
    assert v.get("dataIntact") is True
    assert "restoreDurationSec" in v
    assert v["restoreDurationSec"] >= 0.0
    assert "rtoMet" in v
    assert v["rtoMet"] is True


# -----------------------------------------------------------------------------
# 7. RPO & RTO SLA Telemetry Tests
# -----------------------------------------------------------------------------
def test_rpo_and_rto_telemetry_reporting():
    """Services endpoint must accurately audit RPO and RTO SLA status."""
    res = client.get("/api/services/lab14")
    assert res.status_code == 200
    data = res.json()

    # RPO: Target 60m (3600s)
    rpo = data.get("rpo", {})
    assert rpo.get("targetSeconds") == 3600
    assert rpo.get("targetMinutes") == 60.0
    assert rpo.get("status") in ("WITHIN_SLA", "PENDING_FIRST_BACKUP", "BREACHED")
    assert "currentSeconds" in rpo

    # RTO: Target 5m (300s)
    rto = data.get("rto", {})
    assert rto.get("targetSeconds") == 300
    assert rto.get("targetMinutes") == 5.0
    assert rto.get("status") in ("WITHIN_SLA", "BREACHED")
    assert "measuredBenchmarkSeconds" in rto
    assert rto["measuredBenchmarkSeconds"] > 0


# -----------------------------------------------------------------------------
# 8. Monitoring Metrics Time-Series & Charts Tests
# -----------------------------------------------------------------------------
def test_monitoring_metrics_period_filters_and_charts():
    """GET /api/ops/metrics/monitoring must support 30, 120, 720 minutes and return 5 required charts."""
    for period in [30, 120, 720]:
        res = client.get(f"/api/ops/metrics/monitoring?minutes={period}")
        assert res.status_code == 200
        data = res.json()

        assert data.get("status") == "success"
        assert data.get("periodMinutes") == period
        assert data.get("samplingIntervalSeconds") == 30

        # Statistics tiles
        stats = data.get("statistics", {})
        assert "cacheHitRatio" in stats
        assert "replicationLag" in stats
        assert "alertsDuringPeriod" in stats
        assert "newestBackupAge" in stats
        assert "rpo" in stats
        assert "rto" in stats

        # 5 Required Charts
        charts = data.get("charts", {})
        
        # 1. Cache hit ratio (0-100% with warning line at 80%)
        chr_chart = charts.get("cacheHitRatio", {})
        assert "values" in chr_chart
        assert "warningLine" in chr_chart
        assert chr_chart.get("warningThreshold") == 80.0
        assert chr_chart.get("min") == 0
        assert chr_chart.get("max") == 100

        # 2. Replication lag per secondary (with warning line at 10s)
        lag_chart = charts.get("replicationLag", {})
        assert "series" in lag_chart
        assert "warningLine" in lag_chart
        assert lag_chart.get("warningThresholdSec") == 10.0

        # 3. Operations per second
        ops_chart = charts.get("opsByType", {})
        assert "total" in ops_chart
        assert "query" in ops_chart
        assert "insert" in ops_chart
        assert "command" in ops_chart

        # 4. Connections
        conns_chart = charts.get("connections", {})
        assert "current" in conns_chart
        assert "available" in conns_chart

        # 5. Backup size over time (dd/mm hh:mm)
        backup_chart = charts.get("backupSizeOverTime", {})
        assert "labels" in backup_chart
        assert "sizesMB" in backup_chart


# -----------------------------------------------------------------------------
# 9. Frontend HTML & Workspace Integration Tests
# -----------------------------------------------------------------------------
def test_frontend_routes_serve_chapter14_and_moderation():
    """Both /extras/lab14 and /moderation must serve HTTP 200 with full frontend HTML."""
    res_lab14 = client.get("/extras/lab14")
    assert res_lab14.status_code == 200
    assert "text/html" in res_lab14.headers["content-type"]
    assert "tab-lab14" in res_lab14.text

    res_mod = client.get("/moderation")
    assert res_mod.status_code == 200
    assert "text/html" in res_mod.headers["content-type"]
    assert "tab-moderation" in res_mod.text


def test_frontend_html_has_chapter14_five_subtabs():
    """Chapter 14 dedicated workspace must contain all 5 subtabs in HTML."""
    res = client.get("/extras/lab14")
    html = res.text

    assert 'data-subtab="overview"' in html
    assert 'data-subtab="metrics"' in html
    assert 'data-subtab="alerts"' in html
    assert 'data-subtab="backups"' in html
    assert 'data-subtab="recovery"' in html


def test_frontend_html_has_adminops_backups_card_and_five_canvases():
    """Admin operations dashboard must contain canvases for all 5 Chapter 14 charts."""
    res = client.get("/admin/ops")
    html = res.text

    assert 'id="chart14CacheHitRatio"' in html
    assert 'id="chart14ReplicationLag"' in html
    assert 'id="chart14OpsSec"' in html
    assert 'id="chart14Connections"' in html
    assert 'id="chart14BackupSize"' in html


# -----------------------------------------------------------------------------
# 10. Lab Executor & Runner Integration Tests
# -----------------------------------------------------------------------------
def test_lab_executor_lab14_registered():
    """Lab 14 must be registered in LabExecutionManager."""
    status = executor.get_status()
    labs = status.get("labs", {})
    assert "14" in labs
    lab14 = labs["14"]
    assert lab14["id"] == "14"
    assert "Lab 14" in lab14["name"]


def test_lab_executor_run_lab14():
    """Executing run_lab14() must succeed and populate results and summary."""
    result = executor.run_lab14()
    assert result.get("success") is True

    status = executor.get_status()
    lab14 = status["labs"]["14"]
    assert lab14["status"] == "SUCCESS"
    assert lab14["results"] is not None
    assert "liveMetrics" in lab14["results"]
    assert "latestBackup" in lab14["results"]
    assert "restoreVerification" in lab14["results"]
    assert "rpo" in lab14["results"]
    assert "rto" in lab14["results"]


def test_lab14_results_endpoint():
    """GET /api/labs/results/14 must return Lab 14 structured results."""
    executor.run_lab14()
    res = client.get("/api/labs/results/14")
    assert res.status_code == 200
    data = res.json()
    assert data.get("id") == "14"
    assert data.get("results") is not None

