"""
ThreatPulse SOC Platform - Authentication API Routes.
Provides login, session verification, and administrator role validation.
"""

from fastapi import APIRouter, HTTPException, Depends, Request, Response
from pydantic import BaseModel
from typing import Optional

from auth import (
    create_user_session,
    get_current_user_optional,
    require_auth,
    require_admin,
    ADMIN_API_KEY
)

router = APIRouter(prefix="/auth", tags=["Authentication"])


class LoginRequest(BaseModel):
    email: Optional[str] = None
    username: Optional[str] = None
    password: str


@router.post("/login")
def login(req: LoginRequest, response: Response):
    """
    Authenticates administrator or analyst user.
    Supports user 'jainishjain' with password 'jainish09', as well as platform admins.
    Sets secure HttpOnly session cookie.
    """
    user_identifier = (req.username or req.email or "").strip().lower()
    role = "user"
    user_id = "user_default"
    email = user_identifier if "@" in user_identifier else f"{user_identifier}@threatpulse.io"
    
    # 1. Primary User: jainishjain / jainish09 (Administrator)
    if user_identifier in ("jainishjain", "jainishjain@threatpulse.io", "jainish") and req.password == "jainish09":
        role = "admin"
        user_id = "jainishjain"
        email = "jainishjain@threatpulse.io"
    # 2. Default platform admin / automated tests
    elif user_identifier in ("admin@threatpulse.io", "admin") and req.password in ("AdminPass2026!", ADMIN_API_KEY):
        role = "admin"
        user_id = "admin_01"
        email = "admin@threatpulse.io"
    elif req.password in ("AdminPass2026!", ADMIN_API_KEY):
        role = "admin"
        user_id = f"admin_{user_identifier.split('@')[0]}"
        email = user_identifier if "@" in user_identifier else f"{user_identifier}@threatpulse.io"
    elif user_identifier in ("analyst@threatpulse.io", "user@threatpulse.io", "analyst") and req.password == "threatpulse2026":
        role = "analyst"
        user_id = "analyst_01"
        email = user_identifier if "@" in user_identifier else f"{user_identifier}@threatpulse.io"
    else:
        raise HTTPException(
            status_code=401,
            detail={"error": "Invalid username or password. Please verify credentials."}
        )

    session = create_user_session(user_id=user_id, email=email, role=role)
    token = session["token"]

    response.set_cookie(
        key="tp_session",
        value=token,
        httponly=True,
        samesite="lax",
        max_age=7 * 24 * 3600
    )

    return {
        "status": "success",
        "token": token,
        "user": {
            "id": user_id,
            "username": user_id,
            "email": email,
            "role": role,
            "isAdmin": role == "admin"
        }
    }


@router.get("/me")
def get_me(request: Request):
    """Returns current active user session."""
    user = get_current_user_optional(request)
    if not user:
        return {
            "authenticated": False,
            "user": None,
            "isAdmin": False
        }
    return {
        "authenticated": True,
        "user": user,
        "isAdmin": user.get("role") == "admin"
    }


@router.post("/logout")
def logout(response: Response):
    """Terminates session."""
    response.delete_cookie("tp_session")
    return {"status": "success", "message": "Signed out successfully."}

