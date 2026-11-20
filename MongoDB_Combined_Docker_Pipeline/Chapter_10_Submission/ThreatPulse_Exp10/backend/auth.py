import os
import hashlib
import secrets
from datetime import datetime, timezone, timedelta
from typing import Optional, Dict, Any
from fastapi import Request, HTTPException, Depends
from database import col_users, col_sessions

SESSION_DURATION_HOURS = 24


def hash_password(password: str, salt: Optional[str] = None) -> Dict[str, str]:
    """
    Hashes password using PBKDF2-HMAC-SHA256 with a 32-byte cryptographically secure salt.
    """
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
    """Verifies plain password against stored PBKDF2 hash using constant-time comparison."""
    computed = hash_password(plain_password, salt)["hash"]
    return secrets.compare_digest(computed, stored_hash)


def create_user_session(user_id: str, email: str, role: str) -> Dict[str, Any]:
    """
    Creates a new authenticated session stored in MongoDB with a TTL index.
    """
    token = secrets.token_urlsafe(32)
    now = datetime.now(timezone.utc)
    expires_at = now + timedelta(hours=SESSION_DURATION_HOURS)

    doc = {
        "token": token,
        "user_id": user_id,
        "email": email,
        "role": role,
        "created_at": now.isoformat(),
        "expires_at": expires_at  # MongoDB TTL index auto-deletes when expired
    }
    col_sessions().insert_one(doc)
    return doc


SESSION_DURATION_DAYS = 7
SESSION_DURATION_HOURS = 24 * SESSION_DURATION_DAYS


def create_session(user_id: Any, email: str = "", role: str = "") -> str:
    from database import col_users
    u = col_users().find_one({"_id": user_id})
    if u:
        email = email or u.get("email", "")
        role = role or u.get("role", "user")
    doc = create_user_session(user_id, email, role)
    return doc["token"]


def destroy_session(token: str):
    col_sessions().delete_one({"token": token})


def get_current_user_optional(request: Request) -> Optional[Dict[str, Any]]:
    """
    Retrieves user from HttpOnly session cookie or Bearer token header if present.
    """
    token = request.cookies.get("tp_session") or request.cookies.get("threatpulse_session")
    if not token:
        auth_hdr = request.headers.get("Authorization", "")
        if auth_hdr.startswith("Bearer "):
            token = auth_hdr.split(" ")[1].strip()

    if not token:
        return None

    session = col_sessions().find_one({"token": token})
    if not session:
        return None

    # Verify expiration
    expires = session.get("expires_at")
    if isinstance(expires, datetime) and expires < datetime.now(timezone.utc):
        col_sessions().delete_one({"token": token})
        return None

    user = col_users().find_one({"_id": session["user_id"]}, {"password_hash": 0, "salt": 0})
    if not user:
        return None

    user["id"] = str(user["_id"])
    return user


def get_current_user(request: Request) -> Dict[str, Any]:
    """Dependency that enforces active authentication."""
    user = get_current_user_optional(request)
    if not user:
        raise HTTPException(
            status_code=401,
            detail={"error": "Authentication required. Please sign in to access this feature.", "authRequired": True}
        )
    return user


def require_admin(user: Dict[str, Any] = Depends(get_current_user)) -> Dict[str, Any]:
    """Dependency that strictly enforces admin role."""
    if user.get("role") != "admin":
        raise HTTPException(
            status_code=403,
            detail={"error": "Access denied. Administrator privileges required."}
        )
    return user


# Alias for dependency injection
require_auth = get_current_user

