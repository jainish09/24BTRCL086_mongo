"""
ThreatPulse SOC Platform - Chapter 15: Multi-Tenant Case Management Router.
Provides server-side organisation scoping, role-based case access control,
case lifecycle management, threat/event linking, rate limiting, and privacy-safe
organisation analytics.
"""

import os
import time
import secrets
import logging
from datetime import datetime, timezone
from typing import Optional, Dict, Any, List
from collections import defaultdict, deque
from threading import Lock

from fastapi import APIRouter, HTTPException, Depends, Request, Response, Query, Header
from pydantic import BaseModel, Field

from auth import (
    get_current_user_optional,
    get_current_user,
    require_admin,
    require_moderator_or_admin,
    ADMIN_API_KEY
)
from database import get_database

logger = logging.getLogger("threat_intel.routes.cases")
router = APIRouter(prefix="", tags=["Chapter 15: Multi-Tenant Case Management"])

# -----------------------------------------------------------------------------
# Rate Limiting Engine
# -----------------------------------------------------------------------------
# Standard rate limit: 30 case operations per minute per client
RATE_LIMIT_PER_MINUTE = 30
_rate_limits_refused_total = 0
_rate_limit_lock = Lock()
_rate_limit_history = defaultdict(lambda: deque(maxlen=RATE_LIMIT_PER_MINUTE * 2))


def check_case_rate_limit(request: Request, client_id: str) -> None:
    """
    Enforces sliding-window rate limit for case operations.
    Returns HTTP 429 with 'Retry-After' header and explicit message:
    'Rate limit reached: N requests per minute. Try again in X seconds.'
    """
    global _rate_limits_refused_total

    # Header-based simulation trigger for testing rate limiting
    simulate_429 = request.headers.get("X-Simulate-Rate-Limit", "").lower() in ("true", "1", "yes")

    now = time.time()
    one_minute_ago = now - 60.0

    with _rate_limit_lock:
        if simulate_429:
            _rate_limits_refused_total += 1
            retry_after = 45
            raise HTTPException(
                status_code=429,
                detail=f"Rate limit reached: {RATE_LIMIT_PER_MINUTE} requests per minute. Try again in {retry_after} seconds.",
                headers={"Retry-After": str(retry_after)}
            )

        window = _rate_limit_history[client_id]
        # Purge timestamps older than 60 seconds
        while window and window[0] < one_minute_ago:
            window.popleft()

        if len(window) >= RATE_LIMIT_PER_MINUTE:
            _rate_limits_refused_total += 1
            oldest_in_window = window[0]
            retry_after = max(1, int(60.0 - (now - oldest_in_window)))
            logger.warning(f"Rate limit exceeded for client {client_id}: {len(window)} reqs in 60s")
            raise HTTPException(
                status_code=429,
                detail=f"Rate limit reached: {RATE_LIMIT_PER_MINUTE} requests per minute. Try again in {retry_after} seconds.",
                headers={"Retry-After": str(retry_after)}
            )

        window.append(now)


# -----------------------------------------------------------------------------
# In-Memory Seed / Fallback Multi-Tenant Data Store
# -----------------------------------------------------------------------------
# Organisations
_ORGANIZATIONS: Dict[str, Dict[str, Any]] = {
    "org_acme_corp": {
        "id": "org_acme_corp",
        "name": "Acme Cybersecurity Corp",
        "slug": "acme-corp",
        "tier": "Enterprise",
        "maxCases": 1000,
        "createdAt": "2026-01-15T08:00:00Z"
    },
    "org_globex_sec": {
        "id": "org_globex_sec",
        "name": "Globex Defense Systems",
        "slug": "globex-sec",
        "tier": "Professional",
        "maxCases": 500,
        "createdAt": "2026-02-01T10:30:00Z"
    },
    "org_stark_net": {
        "id": "org_stark_net",
        "name": "Stark Advanced Cyber Threat Team",
        "slug": "stark-net",
        "tier": "Enterprise",
        "maxCases": 2000,
        "createdAt": "2026-02-20T12:00:00Z"
    }
}

# Organisation Memberships (maps user_id -> { org_id, org_role, email, name })
_ORG_MEMBERS: List[Dict[str, Any]] = [
    # Acme Corp Members
    {
        "userId": "admin_01",
        "email": "admin@threatpulse.io",
        "name": "SOC Platform Administrator",
        "orgId": "org_acme_corp",
        "orgRole": "org_admin",
        "joinedAt": "2026-01-15T08:00:00Z"
    },
    {
        "userId": "analyst_01",
        "email": "analyst@threatpulse.io",
        "name": "Security Analyst",
        "orgId": "org_acme_corp",
        "orgRole": "org_member",
        "joinedAt": "2026-01-16T09:00:00Z"
    },
    {
        "userId": "user_acme_02",
        "email": "sarah.chen@acme.com",
        "name": "Sarah Chen",
        "orgId": "org_acme_corp",
        "orgRole": "org_member",
        "joinedAt": "2026-01-20T11:30:00Z"
    },
    # Globex Members
    {
        "userId": "user_globex_01",
        "email": "secops@globex.io",
        "name": "Globex SecOps Lead",
        "orgId": "org_globex_sec",
        "orgRole": "org_admin",
        "joinedAt": "2026-02-01T10:30:00Z"
    },
    {
        "userId": "user_globex_02",
        "email": "analyst@globex.io",
        "name": "Globex SOC Analyst",
        "orgId": "org_globex_sec",
        "orgRole": "org_member",
        "joinedAt": "2026-02-05T14:15:00Z"
    },
    # Stark Net Members
    {
        "userId": "user_stark_01",
        "email": "jarvis@stark.io",
        "name": "Tony Stark",
        "orgId": "org_stark_net",
        "orgRole": "org_admin",
        "joinedAt": "2026-02-20T12:00:00Z"
    }
]

# Baseline Cases
_CASES: List[Dict[str, Any]] = [
    # Acme Cases
    {
        "id": "case_acme_101",
        "caseNumber": "CASE-2026-101",
        "orgId": "org_acme_corp",
        "title": "Cobalt Strike C2 Beaconing via Port 443",
        "description": "Workstation communicating with 185.220.101.5 on a 60s jitter interval.",
        "priority": "HIGH",
        "status": "In Progress",
        "assignedTo": "analyst_01",
        "assignedToName": "Security Analyst",
        "createdBy": "admin_01",
        "createdByName": "SOC Platform Administrator",
        "linkedThreat": "THREAT-APT29-BEACON",
        "linkedEvent": "EVT-90214-DNS",
        "createdAt": "2026-11-10T14:30:00Z",
        "updatedAt": "2026-11-12T09:15:00Z"
    },
    {
        "id": "case_acme_102",
        "caseNumber": "CASE-2026-102",
        "orgId": "org_acme_corp",
        "title": "Ransomware Canary Token Triggered on File Server",
        "description": "Canary share file modified by compromised service account svc_backup.",
        "priority": "CRITICAL",
        "status": "Open",
        "assignedTo": "analyst_01",
        "assignedToName": "Security Analyst",
        "createdBy": "analyst_01",
        "createdByName": "Security Analyst",
        "linkedThreat": "THREAT-LOCKBIT-3",
        "linkedEvent": "EVT-88123-SMB",
        "createdAt": "2026-11-14T11:00:00Z",
        "updatedAt": "2026-11-14T11:00:00Z"
    },
    {
        "id": "case_acme_103",
        "caseNumber": "CASE-2026-103",
        "orgId": "org_acme_corp",
        "title": "Phishing Campaign Targeting Finance Executives",
        "description": "Credential harvesting campaign using spoofed Microsoft 365 login portals.",
        "priority": "MEDIUM",
        "status": "Closed",
        "assignedTo": "user_acme_02",
        "assignedToName": "Sarah Chen",
        "createdBy": "admin_01",
        "createdByName": "SOC Platform Administrator",
        "linkedThreat": "THREAT-PHISH-O365",
        "linkedEvent": "EVT-71932-MAIL",
        "createdAt": "2026-11-05T08:00:00Z",
        "updatedAt": "2026-11-08T16:45:00Z"
    },
    # Globex Cases
    {
        "id": "case_globex_201",
        "caseNumber": "CASE-GLX-201",
        "orgId": "org_globex_sec",
        "title": "Unauthorized SSH Brute-Force against Bastion Host",
        "description": "Distributed dictionary attack detected against bastion-01.globex.io.",
        "priority": "HIGH",
        "status": "In Progress",
        "assignedTo": "user_globex_01",
        "assignedToName": "Globex SecOps Lead",
        "createdBy": "user_globex_01",
        "createdByName": "Globex SecOps Lead",
        "linkedThreat": "THREAT-SSH-BRUTE",
        "linkedEvent": "EVT-SSH-001",
        "createdAt": "2026-11-13T10:00:00Z",
        "updatedAt": "2026-11-13T10:30:00Z"
    }
]

_cases_lock = Lock()


# -----------------------------------------------------------------------------
# Multi-Tenant Organization Resolver Helper
# -----------------------------------------------------------------------------
def resolve_user_org(user: Dict[str, Any], request: Request) -> Optional[Dict[str, Any]]:
    """
    Resolves the organization context for the authenticated user.
    Supports multi-tenant scoping and explicit tenant switching for platform admins.
    """
    user_id = str(user.get("id", ""))
    email = user.get("email", "").lower()
    user_global_role = user.get("role", "user")

    # Check X-Organization-Id override header
    requested_org_id = request.headers.get("X-Organization-Id")
    if requested_org_id and requested_org_id in _ORGANIZATIONS:
        # Platform admins may act across tenants for operational validation
        if user_global_role == "admin" or user_id == "admin_key_user":
            org = _ORGANIZATIONS[requested_org_id]
            return {
                "orgId": org["id"],
                "orgName": org["name"],
                "orgSlug": org["slug"],
                "orgRole": "org_admin"
            }
        # Regular users can only select an org if they are an active member of it
        mem = next((m for m in _ORG_MEMBERS if m["orgId"] == requested_org_id and (m["userId"] == user_id or m["email"].lower() == email)), None)
        if mem:
            org = _ORGANIZATIONS[requested_org_id]
            return {
                "orgId": org["id"],
                "orgName": org["name"],
                "orgSlug": org["slug"],
                "orgRole": mem["orgRole"]
            }

    # Find user's default membership
    membership = next(
        (m for m in _ORG_MEMBERS if m["userId"] == user_id or (email and m["email"].lower() == email)),
        None
    )

    if membership:
        org = _ORGANIZATIONS.get(membership["orgId"])
        if org:
            return {
                "orgId": org["id"],
                "orgName": org["name"],
                "orgSlug": org["slug"],
                "orgRole": membership["orgRole"]
            }

    # Fallback for platform admin key user -> default to Acme Corp as org_admin
    if user_global_role == "admin" or user_id == "admin_key_user":
        org = _ORGANIZATIONS["org_acme_corp"]
        return {
            "orgId": org["id"],
            "orgName": org["name"],
            "orgSlug": org["slug"],
            "orgRole": "org_admin"
        }

    # User has no assigned organisation
    return None


# -----------------------------------------------------------------------------
# Pydantic Request Models
# -----------------------------------------------------------------------------
class CaseCreateRequest(BaseModel):
    title: str = Field(..., min_length=3, max_length=200)
    description: str = Field(..., min_length=5, max_length=4000)
    priority: str = Field("MEDIUM", pattern="^(LOW|MEDIUM|HIGH|CRITICAL)$")
    assignedTo: Optional[str] = None
    linkedThreat: Optional[str] = None
    linkedEvent: Optional[str] = None


class CaseUpdateRequest(BaseModel):
    title: Optional[str] = Field(None, min_length=3, max_length=200)
    description: Optional[str] = Field(None, min_length=5, max_length=4000)
    priority: Optional[str] = Field(None, pattern="^(LOW|MEDIUM|HIGH|CRITICAL)$")
    status: Optional[str] = Field(None, pattern="^(Open|In Progress|Closed)$")
    assignedTo: Optional[str] = None
    linkedThreat: Optional[str] = None
    linkedEvent: Optional[str] = None


# -----------------------------------------------------------------------------
# Case Management API Endpoints
# -----------------------------------------------------------------------------

@router.get("/cases/me")
def get_cases_me(request: Request, user: Dict[str, Any] = Depends(get_current_user)):
    """
    Returns the current user profile, organization membership, and role permissions.
    If the user has no organization, returns hasOrganization: false for empty-state rendering.
    """
    org_ctx = resolve_user_org(user, request)
    client_ip = request.client.host if request.client else "127.0.0.1"

    if not org_ctx:
        return {
            "status": "success",
            "authenticated": True,
            "hasOrganization": False,
            "user": {
                "id": user.get("id"),
                "email": user.get("email"),
                "name": user.get("name", "Platform User"),
                "role": user.get("role")
            },
            "organization": None,
            "message": "Ask an administrator to add you to an organisation."
        }

    is_admin = org_ctx["orgRole"] == "org_admin" or user.get("role") == "admin"

    return {
        "status": "success",
        "authenticated": True,
        "hasOrganization": True,
        "user": {
            "id": user.get("id"),
            "email": user.get("email"),
            "name": user.get("name", "Platform User"),
            "role": user.get("role")
        },
        "organization": {
            "id": org_ctx["orgId"],
            "name": org_ctx["orgName"],
            "slug": org_ctx["orgSlug"],
            "role": org_ctx["orgRole"],
            "roleLabel": "Organization Administrator" if is_admin else "Member"
        },
        "permissions": {
            "canCreateCase": True,
            "canViewAllOrgCases": is_admin,
            "canAssignCases": is_admin,
            "canDeleteCases": is_admin,
            "canManageMembers": is_admin
        },
        "rateLimit": {
            "limitPerMinute": RATE_LIMIT_PER_MINUTE,
            "client": client_ip
        }
    }


@router.get("/cases")
def list_cases(
    request: Request,
    status: Optional[str] = Query(None),
    priority: Optional[str] = Query(None),
    search: Optional[str] = Query(None),
    user: Dict[str, Any] = Depends(get_current_user)
):
    """
    Returns cases strictly scoped to the user's organization.
    - Organisation Administrators see 'All cases of the organisation'.
    - Regular members see 'Your cases' (assigned to or created by them).
    """
    org_ctx = resolve_user_org(user, request)
    if not org_ctx:
        raise HTTPException(
            status_code=403,
            detail={"error": "User does not belong to any organisation. Ask an administrator to add you to an organisation."}
        )

    org_id = org_ctx["orgId"]
    org_role = org_ctx["orgRole"]
    user_id = str(user.get("id", ""))
    is_org_admin = org_role == "org_admin" or user.get("role") == "admin"

    with _cases_lock:
        # 1. Server-side scoping: strict filter by orgId
        scoped_cases = [c for c in _CASES if c["orgId"] == org_id]

        # 2. Role-based scoping: regular members see 'Your cases'
        if not is_org_admin:
            scoped_cases = [c for c in scoped_cases if c.get("assignedTo") == user_id or c.get("createdBy") == user_id]

        # 3. Query filters
        if status and status != "All":
            scoped_cases = [c for c in scoped_cases if c["status"].lower() == status.lower()]
        if priority and priority != "All":
            scoped_cases = [c for c in scoped_cases if c["priority"].upper() == priority.upper()]
        if search:
            q = search.lower().strip()
            scoped_cases = [
                c for c in scoped_cases
                if q in c["title"].lower() or q in c["caseNumber"].lower() or q in c["description"].lower()
            ]

        # Clone and return sorted by updatedAt descending
        result = [c.copy() for c in sorted(scoped_cases, key=lambda x: x.get("updatedAt", ""), reverse=True)]

    view_mode = "all_org_cases" if is_org_admin else "your_cases"
    heading = "All cases of the organisation" if is_org_admin else "Your cases"

    return {
        "status": "success",
        "organization": {
            "id": org_ctx["orgId"],
            "name": org_ctx["orgName"],
            "role": org_ctx["orgRole"]
        },
        "viewMode": view_mode,
        "heading": heading,
        "total": len(result),
        "cases": result
    }


@router.post("/cases")
def create_case(
    payload: CaseCreateRequest,
    request: Request,
    user: Dict[str, Any] = Depends(get_current_user)
):
    """
    Creates a new case strictly scoped to the user's organization.
    Rate-limited. Validates that the assignee belongs to the same organization.
    """
    user_id = str(user.get("id", ""))
    client_ip = request.client.host if request.client else user_id
    check_case_rate_limit(request, client_ip)

    org_ctx = resolve_user_org(user, request)
    if not org_ctx:
        raise HTTPException(
            status_code=403,
            detail={"error": "User does not belong to any organisation. Ask an administrator to add you to an organisation."}
        )

    org_id = org_ctx["orgId"]

    # Validate assignee belongs to the same organization
    assigned_to_id = payload.assignedTo or user_id
    assigned_member = next(
        (m for m in _ORG_MEMBERS if m["orgId"] == org_id and (m["userId"] == assigned_to_id or m["email"] == assigned_to_id)),
        None
    )
    if not assigned_member:
        # Check if assigning to current user
        if assigned_to_id == user_id:
            assigned_member_name = user.get("name", "Security Analyst")
        else:
            raise HTTPException(
                status_code=400,
                detail={"error": f"Assignee '{assigned_to_id}' is not an active member of organisation '{org_ctx['orgName']}'."}
            )
    else:
        assigned_member_name = assigned_member.get("name", "Analyst")

    now_iso = datetime.now(timezone.utc).isoformat()
    case_id = f"case_{secrets.token_hex(6)}"
    case_number = f"CASE-{datetime.now().year}-{secrets.randbelow(900) + 100}"

    new_case = {
        "id": case_id,
        "caseNumber": case_number,
        "orgId": org_id,
        "title": payload.title.strip(),
        "description": payload.description.strip(),
        "priority": payload.priority,
        "status": "Open",
        "assignedTo": assigned_to_id,
        "assignedToName": assigned_member_name,
        "createdBy": user_id,
        "createdByName": user.get("name") or user.get("email") or "Analyst",
        "linkedThreat": payload.linkedThreat.strip() if payload.linkedThreat else None,
        "linkedEvent": payload.linkedEvent.strip() if payload.linkedEvent else None,
        "createdAt": now_iso,
        "updatedAt": now_iso
    }

    with _cases_lock:
        _CASES.insert(0, new_case)

    # Persist in MongoDB if online
    db = get_database()
    if db is not None:
        try:
            db["cases"].insert_one(new_case.copy())
        except Exception as e:
            logger.warning(f"Failed to persist case in MongoDB: {e}")

    logger.info(f"Created case {case_id} ({case_number}) in {org_id} by {user_id}")
    return {
        "status": "success",
        "message": f"Case {case_number} created successfully.",
        "case": new_case
    }


@router.get("/cases/{case_id}")
def get_case_by_id(
    case_id: str,
    request: Request,
    user: Dict[str, Any] = Depends(get_current_user)
):
    """
    Fetches a specific case strictly scoped to the user's organization.
    Returns HTTP 404 if the case does not exist or belongs to another organization.
    Returns HTTP 403 if the user is a regular member without access.
    """
    org_ctx = resolve_user_org(user, request)
    if not org_ctx:
        raise HTTPException(status_code=403, detail={"error": "User does not belong to any organisation."})

    org_id = org_ctx["orgId"]
    org_role = org_ctx["orgRole"]
    user_id = str(user.get("id", ""))
    is_org_admin = org_role == "org_admin" or user.get("role") == "admin"

    with _cases_lock:
        case = next((c for c in _CASES if c["id"] == case_id), None)

    # Cross-tenant data isolation: return 404 if case belongs to a different organisation
    if not case or case["orgId"] != org_id:
        raise HTTPException(
            status_code=404,
            detail={"error": f"Case '{case_id}' not found."}
        )

    # If regular member, check assignment or creation
    if not is_org_admin and case.get("assignedTo") != user_id and case.get("createdBy") != user_id:
        raise HTTPException(
            status_code=403,
            detail={"error": "Access denied. You do not have permission to access this case."}
        )

    return {
        "status": "success",
        "case": case
    }


@router.patch("/cases/{case_id}")
def update_case(
    case_id: str,
    payload: CaseUpdateRequest,
    request: Request,
    user: Dict[str, Any] = Depends(get_current_user)
):
    """
    Updates case status, assignee, priority, title, or description.
    Rate-limited. Strictly scoped to the user's organisation.
    Prevents cross-tenant edits and unauthorized status changes.
    """
    user_id = str(user.get("id", ""))
    client_ip = request.client.host if request.client else user_id
    check_case_rate_limit(request, client_ip)

    org_ctx = resolve_user_org(user, request)
    if not org_ctx:
        raise HTTPException(status_code=403, detail={"error": "User does not belong to any organisation."})

    org_id = org_ctx["orgId"]
    org_role = org_ctx["orgRole"]
    is_org_admin = org_role == "org_admin" or user.get("role") == "admin"

    with _cases_lock:
        case = next((c for c in _CASES if c["id"] == case_id), None)
        if not case or case["orgId"] != org_id:
            raise HTTPException(status_code=404, detail={"error": f"Case '{case_id}' not found."})

        # Permission checks for regular members
        if not is_org_admin:
            is_assigned = case.get("assignedTo") == user_id
            is_creator = case.get("createdBy") == user_id
            if not (is_assigned or is_creator):
                raise HTTPException(status_code=403, detail={"error": "Access denied. Cannot modify this case."})

            # Regular members cannot reassign cases to other users
            if payload.assignedTo and payload.assignedTo != case.get("assignedTo"):
                raise HTTPException(
                    status_code=403,
                    detail={"error": "Only organisation administrators can reassign cases."}
                )

        # Validate assignee belongs to same organisation if changing
        if payload.assignedTo and payload.assignedTo != case.get("assignedTo"):
            assigned_member = next(
                (m for m in _ORG_MEMBERS if m["orgId"] == org_id and (m["userId"] == payload.assignedTo or m["email"] == payload.assignedTo)),
                None
            )
            if not assigned_member:
                raise HTTPException(
                    status_code=400,
                    detail={"error": f"Assignee '{payload.assignedTo}' is not a member of organisation '{org_ctx['orgName']}'."}
                )
            case["assignedTo"] = payload.assignedTo
            case["assignedToName"] = assigned_member.get("name", "Analyst")

        if payload.title is not None:
            case["title"] = payload.title.strip()
        if payload.description is not None:
            case["description"] = payload.description.strip()
        if payload.priority is not None:
            case["priority"] = payload.priority
        if payload.status is not None:
            case["status"] = payload.status
        if payload.linkedThreat is not None:
            case["linkedThreat"] = payload.linkedThreat.strip() if payload.linkedThreat else None
        if payload.linkedEvent is not None:
            case["linkedEvent"] = payload.linkedEvent.strip() if payload.linkedEvent else None

        case["updatedAt"] = datetime.now(timezone.utc).isoformat()
        updated_case = case.copy()

    # Sync to MongoDB if available
    db = get_database()
    if db is not None:
        try:
            db["cases"].update_one({"id": case_id, "orgId": org_id}, {"$set": updated_case})
        except Exception as e:
            logger.warning(f"Failed to update case in MongoDB: {e}")

    logger.info(f"Updated case {case_id} in {org_id} by {user_id}")
    return {
        "status": "success",
        "message": f"Case {updated_case['caseNumber']} updated successfully.",
        "case": updated_case
    }


@router.delete("/cases/{case_id}")
def delete_case(
    case_id: str,
    request: Request,
    user: Dict[str, Any] = Depends(get_current_user)
):
    """
    Deletes a case strictly scoped to the user's organisation.
    Requires organisation administrator or platform administrator role.
    Rate-limited.
    """
    user_id = str(user.get("id", ""))
    client_ip = request.client.host if request.client else user_id
    check_case_rate_limit(request, client_ip)

    org_ctx = resolve_user_org(user, request)
    if not org_ctx:
        raise HTTPException(status_code=403, detail={"error": "User does not belong to any organisation."})

    org_id = org_ctx["orgId"]
    org_role = org_ctx["orgRole"]
    is_org_admin = org_role == "org_admin" or user.get("role") == "admin"

    if not is_org_admin:
        raise HTTPException(
            status_code=403,
            detail={"error": "Access denied. Only organisation administrators can delete cases."}
        )

    with _cases_lock:
        idx = next((i for i, c in enumerate(_CASES) if c["id"] == case_id and c["orgId"] == org_id), None)
        if idx is None:
            raise HTTPException(status_code=404, detail={"error": f"Case '{case_id}' not found."})
        deleted_case = _CASES.pop(idx)

    # Remove from MongoDB if available
    db = get_database()
    if db is not None:
        try:
            db["cases"].delete_one({"id": case_id, "orgId": org_id})
        except Exception as e:
            logger.warning(f"Failed to delete case from MongoDB: {e}")

    logger.info(f"Deleted case {case_id} in {org_id} by {user_id}")
    return {
        "status": "success",
        "message": f"Case {deleted_case['caseNumber']} deleted successfully.",
        "deletedCaseId": case_id
    }


@router.get("/cases/org/members")
def get_org_members(
    request: Request,
    user: Dict[str, Any] = Depends(get_current_user)
):
    """
    Returns list of members for the signed-in user's organisation with case workload stats:
    - Member name & email
    - Organisation role (org_admin, org_member)
    - Open cases count
    - In-progress cases count
    - Closed cases count
    """
    org_ctx = resolve_user_org(user, request)
    if not org_ctx:
        raise HTTPException(status_code=403, detail={"error": "User does not belong to any organisation."})

    org_id = org_ctx["orgId"]

    # Filter members for this organisation
    members = [m.copy() for m in _ORG_MEMBERS if m["orgId"] == org_id]

    # Calculate workload per member within this organisation
    with _cases_lock:
        org_cases = [c for c in _CASES if c["orgId"] == org_id]

    member_stats = []
    for m in members:
        uid = m["userId"]
        user_cases = [c for c in org_cases if c.get("assignedTo") == uid]
        open_cnt = sum(1 for c in user_cases if c.get("status") == "Open")
        in_prog_cnt = sum(1 for c in user_cases if c.get("status") == "In Progress")
        closed_cnt = sum(1 for c in user_cases if c.get("status") == "Closed")

        member_stats.append({
            "userId": uid,
            "name": m["name"],
            "email": m["email"],
            "orgRole": m["orgRole"],
            "orgRoleLabel": "Administrator" if m["orgRole"] == "org_admin" else "Member",
            "openCases": open_cnt,
            "inProgressCases": in_prog_cnt,
            "closedCases": closed_cnt,
            "totalCases": len(user_cases),
            "joinedAt": m.get("joinedAt")
        })

    return {
        "status": "success",
        "organization": {
            "id": org_ctx["orgId"],
            "name": org_ctx["orgName"]
        },
        "totalMembers": len(member_stats),
        "members": member_stats
    }


# -----------------------------------------------------------------------------
# Moderator & Admin Multi-Tenant Analytics (Privacy-Safe)
# -----------------------------------------------------------------------------
@router.get("/moderation/organisations")
def get_moderation_organisations(
    request: Request,
    user: Dict[str, Any] = Depends(require_moderator_or_admin)
):
    """
    Returns platform-wide organisation statistics for admin and moderator dashboards.
    PRIVACY RULE: Shows counts and permitted organisation metadata only.
    NEVER exposes case descriptions, threat details, or private contents.
    """
    with _cases_lock:
        all_cases = list(_CASES)

    org_summaries = []
    for org_id, org in _ORGANIZATIONS.items():
        m_count = sum(1 for m in _ORG_MEMBERS if m["orgId"] == org_id)
        org_cases = [c for c in all_cases if c["orgId"] == org_id]
        open_c = sum(1 for c in org_cases if c.get("status") == "Open")
        in_prog_c = sum(1 for c in org_cases if c.get("status") == "In Progress")
        closed_c = sum(1 for c in org_cases if c.get("status") == "Closed")

        # PRIVACY AUDIT: Metadata and counts only - no case descriptions, titles or threat details
        org_summaries.append({
            "id": org["id"],
            "name": org["name"],
            "slug": org["slug"],
            "tier": org["tier"],
            "memberCount": m_count,
            "totalCases": len(org_cases),
            "openCases": open_c,
            "inProgressCases": in_prog_c,
            "closedCases": closed_c,
            "createdAt": org["createdAt"]
        })

    total_cases = len(all_cases)
    total_members = len(_ORG_MEMBERS)
    total_orgs = len(_ORGANIZATIONS)

    # Pre-formatted chart data for Admin Ops & Moderation
    chart_cases_per_org = {
        "labels": [o["name"] for o in org_summaries],
        "datasets": [
            {
                "label": "Total Cases",
                "data": [o["totalCases"] for o in org_summaries],
                "backgroundColor": "rgba(168, 85, 247, 0.6)",
                "borderColor": "#a855f7",
                "borderWidth": 1
            },
            {
                "label": "Open Cases",
                "data": [o["openCases"] for o in org_summaries],
                "backgroundColor": "rgba(239, 68, 68, 0.6)",
                "borderColor": "#ef4444",
                "borderWidth": 1
            }
        ]
    }

    chart_members_per_org = {
        "labels": [o["name"] for o in org_summaries],
        "datasets": [
            {
                "label": "Members",
                "data": [o["memberCount"] for o in org_summaries],
                "backgroundColor": [
                    "rgba(0, 242, 254, 0.7)",
                    "rgba(168, 85, 247, 0.7)",
                    "rgba(16, 185, 129, 0.7)"
                ],
                "borderWidth": 0
            }
        ]
    }

    return {
        "status": "success",
        "tiles": {
            "totalOrganisations": total_orgs,
            "totalMembers": total_members,
            "totalCases": total_cases,
            "requestsRefusedByRateLimiter": _rate_limits_refused_total
        },
        "organisations": org_summaries,
        "charts": {
            "casesPerOrganisation": chart_cases_per_org,
            "membersPerOrganisation": chart_members_per_org
        },
        "privacyVerified": True,
        "operator": {
            "name": user.get("name", "Platform Operator"),
            "role": user.get("role")
        }
    }


# -----------------------------------------------------------------------------
# Chapter 15 Dedicated Workspace Telemetry
# -----------------------------------------------------------------------------
@router.get("/services/lab15")
def get_lab15_services(
    request: Request,
    user: Optional[Dict[str, Any]] = Depends(get_current_user_optional)
):
    """
    Returns telemetry and operational status for Chapter 15 Multi-Tenant Case Management.
    """
    with _cases_lock:
        total_cases = len(_CASES)
        cases_by_status = {
            "Open": sum(1 for c in _CASES if c["status"] == "Open"),
            "In Progress": sum(1 for c in _CASES if c["status"] == "In Progress"),
            "Closed": sum(1 for c in _CASES if c["status"] == "Closed")
        }

    user_org_info = resolve_user_org(user, request) if user else None

    return {
        "status": "success",
        "chapter": 15,
        "title": "Multi-Tenant Case Management",
        "activeTenantsCount": len(_ORGANIZATIONS),
        "totalMembersCount": len(_ORG_MEMBERS),
        "totalCasesCount": total_cases,
        "casesByStatus": cases_by_status,
        "rateLimit": {
            "limitPerMinute": RATE_LIMIT_PER_MINUTE,
            "requestsRefusedTotal": _rate_limits_refused_total,
            "windowSeconds": 60,
            "policy": "Sliding window per client token/IP"
        },
        "currentUserContext": {
            "authenticated": user is not None,
            "user": user,
            "organization": user_org_info
        },
        "features": [
            "Server-Side Tenant Data Scoping",
            "Role-Based Access Control (org_admin vs org_member)",
            "Cross-Tenant Access Denial (404/403)",
            "Threat & Event Linking",
            "Sliding-Window Rate Limiting (HTTP 429)",
            "Privacy-Safe Organisation Analytics"
        ],
        "timestamp": datetime.now(timezone.utc).isoformat()
    }

