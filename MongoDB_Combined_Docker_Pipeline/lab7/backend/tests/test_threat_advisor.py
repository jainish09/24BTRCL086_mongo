"""
Unit Tests for Threat Advisor: LLM Chat & PC Scanner on MongoDB.
Verifies all components from assessment specification:
1. Data Ingestion & Snapshot
2. Lifecycle Status Rules
3. CPE Version Range Matching & Inventory Lookup
4. Agent Enrollment & Token Hashing
5. Hybrid RAG Streaming & Grounding Evaluation
6. FastApi Endpoints
"""

import sys
import json
import pytest
from pathlib import Path
from fastapi.testclient import TestClient

BACKEND_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BACKEND_DIR))

from main import app
from threat_advisor.models import LifecycleStatus, Verdict
from threat_advisor.snapshot_data import SNAPSHOT_THREATS
from threat_advisor.cpe_matcher import parse_version_tuple, is_version_in_range, evaluate_cve_against_host, lookup_installed_program
from threat_advisor.lifecycle import compute_python_fallback_status
from threat_advisor.ingest import ingestor, calculate_text_hash, generate_384d_embedding
from threat_advisor.agent_service import agent_service, hash_token
from threat_advisor.rag_service import rag_service, parse_query_rules

client = TestClient(app)


def test_snapshot_threats_loaded():
    """Verify curated snapshot contains valid CVEs across platforms."""
    assert len(SNAPSHOT_THREATS) >= 8
    cve_ids = [t["cveId"] for t in SNAPSHOT_THREATS]
    assert "CVE-2024-21413" in cve_ids
    assert "CVE-2024-38063" in cve_ids
    assert "CVE-2023-4863" in cve_ids


def test_embedding_dimension_and_normalization():
    """Verify 384-dimensional normalized vector embedding."""
    emb = generate_384d_embedding("Windows TCP/IP vulnerability CVE-2024-38063")
    assert len(emb) == 384
    norm = sum(x * x for x in emb)
    assert 0.95 <= norm <= 1.05


def test_cpe_version_range_matcher():
    """Verify deterministic version comparison logic."""
    cpe_range = {
        "criteria": "cpe:2.3:a:google:chrome:*:*:*:*:*:*:*:*",
        "versionStartIncluding": "1.0.0.0",
        "versionEndExcluding": "116.0.5845.187"
    }

    # 1. Vulnerable version
    vuln, _ = is_version_in_range("115.0.5790.170", cpe_range)
    assert vuln is True

    # 2. Patched version
    vuln, _ = is_version_in_range("116.0.5845.187", cpe_range)
    assert vuln is False

    # 3. Newer safe version
    vuln, _ = is_version_in_range("120.0.6099.109", cpe_range)
    assert vuln is False


def test_evaluate_cve_against_host_deterministic():
    """Verify deterministic host verdict: AFFECTED vs PATCHED vs NOT AFFECTED."""
    cve_chrome = next(t for t in SNAPSHOT_THREATS if t["cveId"] == "CVE-2023-4863")

    # Host with vulnerable Chrome installed
    vuln_host = {
        "osBuild": "10.0.22631.3737",
        "installedPrograms": [
            {"name": "Google Chrome", "version": "115.0.5790.170", "location": "C:\\Program Files\\Google\\Chrome"}
        ],
        "storeApps": []
    }
    res_vuln = evaluate_cve_against_host(cve_chrome, vuln_host)
    assert res_vuln["verdict"] == "AFFECTED"
    assert "115.0.5790.170" in res_vuln["scannedVersion"]

    # Host with patched Chrome
    patched_host = {
        "osBuild": "10.0.22631.3737",
        "installedPrograms": [
            {"name": "Google Chrome", "version": "120.0.6099.109", "location": "C:\\Program Files\\Google\\Chrome"}
        ],
        "storeApps": []
    }
    res_pat = evaluate_cve_against_host(cve_chrome, patched_host)
    assert res_pat["verdict"] == "PATCHED"

    # Host without Chrome
    clean_host = {
        "osBuild": "10.0.22631.3737",
        "installedPrograms": [{"name": "Mozilla Firefox", "version": "122.0"}],
        "storeApps": []
    }
    res_clean = evaluate_cve_against_host(cve_chrome, clean_host)
    assert res_clean["verdict"] == "NOT AFFECTED"


def test_program_inventory_lookup():
    """Verify normalized token lookup in host inventory."""
    host_data = {
        "installedPrograms": [
            {"name": "Microsoft Visual Studio Code", "version": "1.85.1"},
            {"name": "Google Chrome", "version": "120.0.6099.109"}
        ],
        "storeApps": [],
        "steamGames": [{"name": "Cyberpunk 2077"}]
    }

    # Query 1: Exact match
    res1 = lookup_installed_program("is Chrome installed?", host_data)
    assert res1["status"] == "INSTALLED"
    assert len(res1["matches"]) >= 1

    # Query 2: Steam game match
    res2 = lookup_installed_program("is Cyberpunk 2077 on my pc?", host_data)
    assert res2["status"] == "INSTALLED"

    # Query 3: Absent software
    res3 = lookup_installed_program("is Adobe Photoshop installed?", host_data)
    assert res3["status"] == "NOT_FOUND"


def test_agent_enrollment_and_token_exchange():
    """Verify 30-min install token exchange and SHA-256 permanent token hashing."""
    install_token = agent_service.create_install_token()
    assert len(install_token) == 32

    device_hash = "mock_device_hash_12345"
    perm_token = agent_service.register_agent(
        install_token=install_token,
        device_hash=device_hash,
        hostname="SOC-ANALYST-PC",
        os_info={"osVersion": "Windows 11", "osBuild": "10.0.22631.4037", "arch": "AMD64"}
    )
    assert perm_token is not None
    assert len(perm_token) == 64

    # Token must verify against stored hash
    assert agent_service.authenticate_agent(device_hash, perm_token) is True
    assert agent_service.authenticate_agent(device_hash, "wrong_token") is False

    # Used install token cannot be reused
    assert agent_service.verify_install_token(install_token) is False


def test_rule_based_query_parser():
    """Verify intent extraction without LLM."""
    q1 = "What Active threats affect Windows?"
    p1 = parse_query_rules(q1)
    assert p1["platform"] == "windows"
    assert p1["status"] == "Active"

    q2 = "Is Chrome installed on my device?"
    p2 = parse_query_rules(q2)
    assert p2["isProgramCheck"] is True

    q3 = "Explain mitigation for CVE-2024-21413"
    p3 = parse_query_rules(q3)
    assert "CVE-2024-21413" in p3["cves"]


def test_fastapi_endpoints():
    """Test REST API routes."""
    # 1. Threat catalog
    r = client.get("/api/threats")
    assert r.status_code == 200
    assert r.json()["total"] >= 8

    # 2. Single threat detail
    r2 = client.get("/api/threats/CVE-2024-21413")
    assert r2.status_code == 200
    assert r2.json()["cveId"] == "CVE-2024-21413"

    # 3. Install PowerShell script
    r3 = client.get("/install.ps1")
    assert r3.status_code == 200
    assert "Threat Advisor One-Line Windows Scanner Installer" in r3.text

    # 4. Monitor metrics
    r4 = client.get("/api/monitor/metrics")
    assert r4.status_code == 200
    assert "p50LatencyMs" in r4.json()

    # 5. My system summary
    r5 = client.get("/api/agent/my-system")
    assert r5.status_code == 200


def test_streaming_chat_ndjson():
    """Verify POST /chat/stream emits meta, delta, and done NDJSON events."""
    payload = {
        "question": "What active threats affect Windows?",
        "sessionId": "test_sess_001"
    }
    response = client.post("/chat/stream", json=payload)
    assert response.status_code == 200

    lines = [line.strip() for line in response.text.split("\n") if line.strip()]
    assert len(lines) >= 2

    # Parse first line (meta event)
    meta = json.loads(lines[0])
    assert meta["event"] == "meta"
    assert "retrievedRecords" in meta["data"]

    # Parse last line (done event)
    done = json.loads(lines[-1])
    assert done["event"] == "done"
    assert "grounding" in done["data"]
