"""
ThreatPulse SOC Platform - Authentication & RBAC Authorization Layer.
Enforces admin authentication and confirmation for sensitive deployment operations.
"""

import os
import hashlib
import secrets
from datetime import datetime, timezone, timedelta
from typing import Optional, Dict, Any
from fastapi import Request, HTTPException, Depends, Header
from config import ADMIN_API_KEY
from database import get_database

SESSION_DURATION_HOURS = 24 * 7

# Default in-memory active session store fallback
_in_memory_sessions: Dict[str, Dict[str, Any]] = {}


def hash_password(password: str, salt: Optional[str] = None) -> Dict[str, str]:
    if not salt:
        salt = secrets.token_hex(16)
    dk = hashlib.pbkdf2_hmac(
        'sha256',
        password.encode('utf-8'),
        salt.encode('utf-8'),
        iterations=600000
    )
    return {
        "hash": dk.hex(),
        "salt": salt
    }


def verify_password(plain_password: str, stored_hash: str, salt: str) -> bool:
    computed = hash_password(plain_password, salt)["hash"]
    return secrets.compare_digest(computed, stored_hash)


def create_user_session(user_id: str, email: str, role: str) -> Dict[str, Any]:
    token = secrets.token_urlsafe(32)
    now = datetime.now(timezone.utc)
    expires_at = now + timedelta(hours=SESSION_DURATION_HOURS)

    doc = {
        "token": token,
        "user_id": user_id,
        "email": email,
        "role": role,
        "created_at": now.isoformat(),
        "expires_at": expires_at
    }

    db = get_database()
    if db is not None:
        try:
            db["sessions"].insert_one(doc.copy())
        except Exception:
            pass

    _in_memory_sessions[token] = doc
    return doc


def get_current_user_optional(request: Request) -> Optional[Dict[str, Any]]:
    # Check X-Admin-Key header
    admin_key = request.headers.get("X-Admin-Key")
    if admin_key and secrets.compare_digest(admin_key.strip(), ADMIN_API_KEY.strip()):
        return {
            "id": "admin_key_user",
            "email": "admin@threatpulse.io",
            "role": "admin",
            "name": "SOC Platform Administrator (API Key)"
        }

    # Check cookie or Bearer token
    token = request.cookies.get("tp_session") or request.cookies.get("threatpulse_session")
    if not token:
        auth_hdr = request.headers.get("Authorization", "")
        if auth_hdr.startswith("Bearer "):
            token = auth_hdr.split(" ")[1].strip()

    if not token:
        return None

    # Check MongoDB sessions
    db = get_database()
    session = None
    if db is not None:
        try:
            session = db["sessions"].find_one({"token": token})
        except Exception:
            session = None

    if not session:
        session = _in_memory_sessions.get(token)

    if not session:
        return None

    # Check expiration
    expires = session.get("expires_at")
    if isinstance(expires, datetime):
        if expires.tzinfo is None:
            expires = expires.replace(tzinfo=timezone.utc)
        if expires < datetime.now(timezone.utc):
            return None

    return {
        "id": str(session.get("user_id")),
        "email": session.get("email", ""),
        "role": session.get("role", "user"),
        "name": session.get("name", "Platform User")
    }


def get_current_user(request: Request) -> Dict[str, Any]:
    user = get_current_user_optional(request)
    if not user:
        raise HTTPException(
            status_code=401,
            detail={"error": "Authentication required. Please authenticate to access this feature.", "authRequired": True}
        )
    return user


def require_admin(request: Request) -> Dict[str, Any]:
    """Dependency strictly enforcing admin privileges."""
    user = get_current_user_optional(request)
    if not user:
        raise HTTPException(
            status_code=401,
            detail={"error": "Authentication required. Administrator credentials needed.", "authRequired": True}
        )

    if user.get("role") != "admin":
        raise HTTPException(
            status_code=403,
            detail={"error": "Access denied. Administrator privileges required.", "role": user.get("role")}
        )
    return user


def require_moderator_or_admin(request: Request) -> Dict[str, Any]:
    """Dependency enforcing moderator or administrator privileges."""
    user = get_current_user_optional(request)
    if not user:
        raise HTTPException(
            status_code=401,
            detail={"error": "Authentication required. Moderator or Administrator credentials needed.", "authRequired": True}
        )

    if user.get("role") not in ("admin", "moderator"):
        raise HTTPException(
            status_code=403,
            detail={"error": "Access denied. Moderator or Administrator privileges required.", "role": user.get("role")}
        )
    return user


def verify_admin_confirmation(request: Request, body_confirm: Optional[bool] = None) -> bool:
    """
    Ensures that an admin action is explicitly confirmed, either via
    X-Admin-Confirm header or confirmation flag.
    """
    header_confirm = request.headers.get("X-Admin-Confirm", "").lower() in ("true", "1", "yes")
    query_confirm = request.query_params.get("confirm", "").lower() in ("true", "1", "yes")
    if not (body_confirm or header_confirm or query_confirm):
        raise HTTPException(
            status_code=400,
            detail={
                "error": "Confirmation required for destructive or infrastructure operations.",
                "confirmationRequired": True,
                "hint": "Provide 'confirm=true' parameter, 'X-Admin-Confirm: true' header, or confirmed: true in request payload."
            }
        )
    return True


require_auth = get_current_user

