"""
ThreatPulse SOC Platform - Chapter 15 Automated Test Suite.
Validates multi-tenant case management, organisation membership, role scoping,
cross-tenant isolation, negative security boundaries, rate limiting, and privacy analytics.
"""

import os
import sys
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
from routes.cases import (
    _ORGANIZATIONS,
    _ORG_MEMBERS,
    _CASES,
    RATE_LIMIT_PER_MINUTE
)

client = TestClient(app)

# Helper fixtures for user sessions
ADMIN_HEADERS = {"X-Admin-Key": ADMIN_API_KEY}

# Create test sessions
_acme_admin_session = create_user_session(user_id="admin_01", email="admin@threatpulse.io", role="admin")
_acme_member_session = create_user_session(user_id="analyst_01", email="analyst@threatpulse.io", role="analyst")
_globex_admin_session = create_user_session(user_id="user_globex_01", email="secops@globex.io", role="user")
_unassigned_user_session = create_user_session(user_id="user_solo", email="solo@freelance.org", role="user")

ACME_ADMIN_COOKIE = {"tp_session": _acme_admin_session["token"]}
ACME_MEMBER_COOKIE = {"tp_session": _acme_member_session["token"]}
GLOBEX_ADMIN_COOKIE = {"tp_session": _globex_admin_session["token"]}
UNASSIGNED_COOKIE = {"tp_session": _unassigned_user_session["token"]}


# -----------------------------------------------------------------------------
# 1. Route Registration Tests
# -----------------------------------------------------------------------------
def test_fastapi_route_registration_lab15():
    """Verifies all Chapter 15 multi-tenant routes are registered in FastAPI."""
    routes = [r.path for r in app.routes]

    # Required API routes
    assert "/api/cases/me" in routes
    assert "/api/cases" in routes
    assert "/api/cases/{case_id}" in routes
    assert "/api/cases/org/members" in routes
    assert "/api/moderation/organisations" in routes
    assert "/api/services/lab15" in routes
    assert "/api/labs/15/run" in routes

    # Client application routes
    assert "/cases" in routes
    assert "/extras/lab15" in routes


# -----------------------------------------------------------------------------
# 2. Organisation Membership & Empty State Tests
# -----------------------------------------------------------------------------
def test_cases_me_authenticated_user_with_org():
    """GET /api/cases/me must return organisation membership, role, and permissions."""
    res = client.get("/api/cases/me", cookies=ACME_ADMIN_COOKIE)
    assert res.status_code == 200
    data = res.json()

    assert data.get("status") == "success"
    assert data.get("hasOrganization") is True
    assert "organization" in data
    assert data["organization"]["id"] == "org_acme_corp"
    assert data["organization"]["role"] == "org_admin"
    assert data["permissions"]["canCreateCase"] is True
    assert data["permissions"]["canViewAllOrgCases"] is True
    assert data["permissions"]["canAssignCases"] is True


def test_cases_me_user_without_org_empty_state():
    """Unassigned user must receive hasOrganization: false and guidance message."""
    res = client.get("/api/cases/me", cookies=UNASSIGNED_COOKIE)
    assert res.status_code == 200
    data = res.json()

    assert data.get("status") == "success"
    assert data.get("hasOrganization") is False
    assert data.get("organization") is None
    assert "Ask an administrator to add you to an organisation." in data.get("message", "")


# -----------------------------------------------------------------------------
# 3. Case Creation & Threat/Event Linking Tests
# -----------------------------------------------------------------------------
def test_case_creation_with_threat_and_event_linking():
    """POST /api/cases must create case with links and partition strictly to caller's org."""
    payload = {
        "title": "Suspected LockBit 3.0 Lateral Movement via PsExec",
        "description": "Lateral traversal detected between workstations 192.168.1.10 and 192.168.1.25.",
        "priority": "HIGH",
        "assignedTo": "analyst_01",
        "linkedThreat": "THREAT-LOCKBIT-3",
        "linkedEvent": "EVT-88123-SMB"
    }

    res = client.post("/api/cases", json=payload, cookies=ACME_ADMIN_COOKIE)
    assert res.status_code == 200
    data = res.json()

    assert data.get("status") == "success"
    created = data.get("case", {})
    assert created.get("id") is not None
    assert created.get("caseNumber") is not None
    assert created.get("orgId") == "org_acme_corp"
    assert created.get("title") == payload["title"]
    assert created.get("description") == payload["description"]
    assert created.get("priority") == "HIGH"
    assert created.get("status") == "Open"
    assert created.get("linkedThreat") == "THREAT-LOCKBIT-3"
    assert created.get("linkedEvent") == "EVT-88123-SMB"
    assert created.get("assignedTo") == "analyst_01"


# -----------------------------------------------------------------------------
# 4. Scoped Case Listing: Org Admin vs Regular Member
# -----------------------------------------------------------------------------
def test_case_listing_scoping_org_admin_sees_all():
    """Organisation administrator must receive 'All cases of the organisation'."""
    res = client.get("/api/cases", cookies=ACME_ADMIN_COOKIE)
    assert res.status_code == 200
    data = res.json()

    assert data.get("status") == "success"
    assert data.get("heading") == "All cases of the organisation"
    assert data.get("viewMode") == "all_org_cases"

    # All returned cases must strictly belong to Acme Corp
    for c in data.get("cases", []):
        assert c["orgId"] == "org_acme_corp"


def test_case_listing_scoping_org_member_sees_own_cases():
    """Organisation member must receive 'Your cases' (assigned to or created by user)."""
    res = client.get("/api/cases", cookies=ACME_MEMBER_COOKIE)
    assert res.status_code == 200
    data = res.json()

    assert data.get("status") == "success"
    assert data.get("heading") == "Your cases"
    assert data.get("viewMode") == "your_cases"

    # Returned cases must belong to Acme Corp AND be assigned to or created by analyst_01
    for c in data.get("cases", []):
        assert c["orgId"] == "org_acme_corp"
        assert c.get("assignedTo") == "analyst_01" or c.get("createdBy") == "analyst_01"


# -----------------------------------------------------------------------------
# 5. Negative Security Tests: Cross-Tenant Access Prevention
# -----------------------------------------------------------------------------
def test_cross_tenant_access_prevention_get_foreign_case_fails():
    """
    NEGATIVE TEST: Acme user attempting to fetch a Globex case (case_globex_201)
    MUST fail with HTTP 404 to prevent ID enumeration.
    """
    res = client.get("/api/cases/case_globex_201", cookies=ACME_ADMIN_COOKIE)
    assert res.status_code == 404
    err_detail = str(res.json().get("detail", ""))
    assert "not found" in err_detail.lower()


def test_cross_tenant_access_prevention_patch_foreign_case_fails():
    """
    NEGATIVE TEST: Acme user attempting to modify a Globex case
    MUST fail with HTTP 404.
    """
    payload = {"status": "Closed"}
    res = client.patch("/api/cases/case_globex_201", json=payload, cookies=ACME_ADMIN_COOKIE)
    assert res.status_code == 404


def test_cross_tenant_access_prevention_delete_foreign_case_fails():
    """
    NEGATIVE TEST: Acme admin attempting to delete a Globex case
    MUST fail with HTTP 404.
    """
    res = client.delete("/api/cases/case_globex_201", cookies=ACME_ADMIN_COOKIE)
    assert res.status_code == 404


def test_cross_tenant_assignment_prevention():
    """
    NEGATIVE TEST: Assigning a case to a user belonging to another organisation
    MUST fail with HTTP 400 Bad Request.
    """
    payload = {
        "title": "Cross-Tenant User Assignment Probe",
        "description": "Attempting to assign Acme case to Globex user.",
        "priority": "LOW",
        "assignedTo": "user_globex_01"  # User belongs to Globex!
    }

    res = client.post("/api/cases", json=payload, cookies=ACME_ADMIN_COOKIE)
    assert res.status_code == 400
    err_detail = str(res.json().get("detail", ""))
    assert "not an active member of organisation" in err_detail


# -----------------------------------------------------------------------------
# 6. Inline Status Update & Workload Tests
# -----------------------------------------------------------------------------
def test_inline_status_update_open_in_progress_closed():
    """PATCH /api/cases/{id} must transition case through valid statuses."""
    # Create test case
    create_res = client.post(
        "/api/cases",
        json={"title": "Status Transition Probe", "description": "Testing lifecycle.", "priority": "MEDIUM"},
        cookies=ACME_ADMIN_COOKIE
    )
    assert create_res.status_code == 200
    case_id = create_res.json()["case"]["id"]

    for st in ["In Progress", "Closed", "Open"]:
        res = client.patch(f"/api/cases/{case_id}", json={"status": st}, cookies=ACME_ADMIN_COOKIE)
        assert res.status_code == 200
        assert res.json()["case"]["status"] == st


def test_org_members_endpoint_with_case_counts():
    """GET /api/cases/org/members must return members and case workload metrics."""
    res = client.get("/api/cases/org/members", cookies=ACME_ADMIN_COOKIE)
    assert res.status_code == 200
    data = res.json()

    assert data.get("status") == "success"
    assert "members" in data
    assert len(data["members"]) >= 2

    for m in data["members"]:
        assert "userId" in m
        assert "name" in m
        assert "email" in m
        assert "orgRole" in m
        assert "openCases" in m
        assert "inProgressCases" in m
        assert "closedCases" in m
        assert "totalCases" in m


# -----------------------------------------------------------------------------
# 7. Rate Limiting Tests (HTTP 429 & Response Message Format)
# -----------------------------------------------------------------------------
def test_rate_limiting_enforcement_and_http_429_format():
    """
    Rate limiter must reject excessive requests with HTTP 429, Retry-After header,
    and message: 'Rate limit reached: N requests per minute. Try again in X seconds.'
    """
    # Trigger simulation header
    res = client.post(
        "/api/cases",
        json={"title": "Rate Limit Probe", "description": "Triggering 429.", "priority": "LOW"},
        headers={"X-Simulate-Rate-Limit": "true"},
        cookies=ACME_ADMIN_COOKIE
    )

    assert res.status_code == 429
    assert "Retry-After" in res.headers
    retry_sec = res.headers["Retry-After"]
    assert int(retry_sec) > 0

    detail = str(res.json().get("detail", ""))
    assert "Rate limit reached:" in detail
    assert "requests per minute. Try again in" in detail
    assert "seconds." in detail


# -----------------------------------------------------------------------------
# 8. Moderator Analytics & Privacy Tests
# -----------------------------------------------------------------------------
def test_moderation_organisations_requires_moderator_or_admin():
    """GET /api/moderation/organisations must reject unauthenticated requests with HTTP 401."""
    res = client.get("/api/moderation/organisations")
    assert res.status_code == 401


def test_moderation_organisations_analytics_and_counts():
    """GET /api/moderation/organisations must return 4 tiles, charts data, and summary list."""
    res = client.get("/api/moderation/organisations", headers=ADMIN_HEADERS)
    assert res.status_code == 200
    data = res.json()

    assert data.get("status") == "success"
    tiles = data.get("tiles", {})
    assert tiles.get("totalOrganisations") >= 3
    assert tiles.get("totalMembers") >= 5
    assert tiles.get("totalCases") >= 4
    assert "requestsRefusedByRateLimiter" in tiles

    # Check charts structure
    charts = data.get("charts", {})
    assert "casesPerOrganisation" in charts
    assert "membersPerOrganisation" in charts


def test_privacy_rule_analytics_never_exposes_case_descriptions():
    """
    CRITICAL PRIVACY RULE: Organisation analytics must NEVER expose case descriptions,
    threat details, indicators, or private contents in organisation responses.
    """
    res = client.get("/api/moderation/organisations", headers=ADMIN_HEADERS)
    assert res.status_code == 200
    data = res.json()

    for org in data.get("organisations", []):
        # Must only contain permitted metadata & counts
        assert "id" in org
        assert "name" in org
        assert "tier" in org
        assert "memberCount" in org
        assert "totalCases" in org
        assert "openCases" in org
        assert "inProgressCases" in org
        assert "closedCases" in org

        # STRICT PRIVACY INVARIANTS: Ensure zero private content exposure
        assert "description" not in org
        assert "cases" not in org
        assert "linkedThreat" not in org
        assert "linkedEvent" not in org
        assert "private_message" not in org


# -----------------------------------------------------------------------------
# 9. Frontend HTML & Route Tests
# -----------------------------------------------------------------------------
def test_frontend_routes_serve_cases_and_lab15():
    """GET /cases and GET /extras/lab15 must return HTML (index.html)."""
    res_cases = client.get("/cases")
    assert res_cases.status_code == 200
    assert "text/html" in res_cases.headers.get("content-type", "")

    res_lab15 = client.get("/extras/lab15")
    assert res_lab15.status_code == 200
    assert "text/html" in res_lab15.headers.get("content-type", "")


def test_frontend_html_has_chapter15_elements_and_charts():
    """index.html must contain all Chapter 15 UI workspaces, tables, and canvases."""
    res = client.get("/cases")
    html = res.text

    # Section IDs
    assert 'id="tab-cases"' in html
    assert 'id="tab-lab15"' in html
    assert 'id="adminOpsViewOrgsPane"' in html
    assert 'id="moderationOrgsPane"' in html

    # Cases components
    assert 'id="casesOrgBanner"' in html
    assert 'id="casesOrgName"' in html
    assert 'id="casesOrgRoleBadge"' in html
    assert 'id="casesEmptyOrgState"' in html
    assert 'Ask an administrator to add you to an organisation.' in html
    assert 'id="casesRateLimitAlert"' in html
    assert 'id="formCreateCase"' in html
    assert 'id="casesListHeading"' in html
    assert 'id="tblCasesBody"' in html
    assert 'id="tblCasesMembersBody"' in html

    # Lab 15 Subtabs
    assert 'data-subtab="overview"' in html
    assert 'data-subtab="cases"' in html
    assert 'data-subtab="orgs"' in html
    assert 'data-subtab="members"' in html
    assert 'data-subtab="limits"' in html

    # Chart canvases
    assert 'id="chart15CasesPerOrg"' in html
    assert 'id="chart15MembersPerOrg"' in html


# -----------------------------------------------------------------------------
# 10. Lab Runner & Executor Integration Tests
# -----------------------------------------------------------------------------
def test_lab_executor_lab15_registered_and_run():
    """Lab 15 must be registered in lab_executor and execute successfully."""
    status = executor.get_status()
    assert "15" in status.get("labs", {})
    assert status["labs"]["15"]["name"] == "Lab 15 — Multi-Tenant Case Management"

    # Execute Lab 15 directly
    res = executor.run_lab15()
    assert res.get("success") is True
    assert "Tenants:" in res.get("summary", "")
    assert "Isolation: VERIFIED" in res.get("summary", "")

    # Execute via API endpoint
    api_res = client.post("/api/labs/15/run")
    assert api_res.status_code in (200, 409)

    # Check results endpoint
    results_res = client.get("/api/labs/results/15")
    assert results_res.status_code == 200
    lab_data = results_res.json()
    assert lab_data.get("status") == "SUCCESS"
    assert "results" in lab_data

