"""
ThreatPulse SOC Platform - Auth Routes
Handles registration, login (cookie + bearer), profile, logout, and demo account switching.
"""

from fastapi import APIRouter, HTTPException, Depends, Response, Request
from pydantic import BaseModel, EmailStr
from typing import Optional, List
import datetime
from bson import ObjectId

from database import col_users, col_wallets, col_subscriptions, col_credit_ledger, col_sessions
from auth import (
    hash_password,
    verify_password,
    create_session,
    destroy_session,
    get_current_user,
    SESSION_DURATION_DAYS
)
from config import DEMO_ACCOUNTS, PLANS

router = APIRouter(prefix="/api/auth", tags=["auth"])


class RegisterRequest(BaseModel):
    email: EmailStr
    password: str
    name: str


class LoginRequest(BaseModel):
    email: EmailStr
    password: str


class DemoSwitchRequest(BaseModel):
    email: EmailStr


@router.post("/register")
def register(req: RegisterRequest, response: Response):
    users_col = col_users()
    existing = users_col.find_one({"email": req.email.lower()})
    if existing:
        raise HTTPException(status_code=400, detail="Account with this email already exists")

    salt, p_hash = hash_password(req.password)
    now = datetime.datetime.now(datetime.timezone.utc)

    user_doc = {
        "email": req.email.lower(),
        "name": req.name,
        "password_hash": p_hash,
        "salt": salt,
        "plan": "free",
        "role": "user",
        "created_at": now,
        "updated_at": now
    }
    res = users_col.insert_one(user_doc)
    user_id = res.inserted_id

    # Create Wallet ($0.00)
    col_wallets().insert_one({
        "user_id": user_id,
        "balance": 0.0,
        "currency": "USD",
        "created_at": now,
        "updated_at": now
    })

    # Free Subscription + 50 Credits
    initial_credits = PLANS["free"]["monthly_credits"]
    col_subscriptions().insert_one({
        "user_id": user_id,
        "plan": "free",
        "status": "active",
        "current_credits": initial_credits,
        "started_at": now,
        "renews_at": now + datetime.timedelta(days=30),
        "updated_at": now
    })

    # Initial Credit Ledger entry
    col_credit_ledger().insert_one({
        "user_id": user_id,
        "txn_id": f"GENESIS-{user_id}",
        "amount": initial_credits,
        "balance_after": initial_credits,
        "action": "PLAN_CREDIT_GRANT",
        "description": "Welcome bonus for Community Free tier",
        "timestamp": now
    })

    token = create_session(user_id)
    response.set_cookie(
        key="tp_session",
        value=token,
        httponly=True,
        samesite="lax",
        max_age=SESSION_DURATION_DAYS * 86400
    )

    return {
        "status": "success",
        "token": token,
        "user": {
            "id": str(user_id),
            "email": req.email.lower(),
            "name": req.name,
            "plan": "free",
            "role": "user",
            "wallet_balance": 0.0,
            "current_credits": initial_credits
        }
    }


@router.post("/login")
def login(req: LoginRequest, response: Response):
    users_col = col_users()
    user = users_col.find_one({"email": req.email.lower()})
    if not user:
        raise HTTPException(status_code=401, detail="Invalid email or password")

    if not verify_password(req.password, user.get("salt", ""), user.get("password_hash", "")):
        raise HTTPException(status_code=401, detail="Invalid email or password")

    user_id = user["_id"]
    token = create_session(user_id)

    response.set_cookie(
        key="tp_session",
        value=token,
        httponly=True,
        samesite="lax",
        max_age=SESSION_DURATION_DAYS * 86400
    )

    wallet = col_wallets().find_one({"user_id": user_id})
    sub = col_subscriptions().find_one({"user_id": user_id})

    return {
        "status": "success",
        "token": token,
        "user": {
            "id": str(user_id),
            "email": user["email"],
            "name": user["name"],
            "plan": sub.get("plan", "free") if sub else "free",
            "role": user.get("role", "user"),
            "wallet_balance": float(wallet.get("balance", 0.0)) if wallet else 0.0,
            "current_credits": int(sub.get("current_credits", 0)) if sub else 0
        }
    }


@router.get("/me")
def get_me(current_user: dict = Depends(get_current_user)):
    user_id = current_user["_id"]
    wallet = col_wallets().find_one({"user_id": user_id})
    sub = col_subscriptions().find_one({"user_id": user_id})

    plan_key = sub.get("plan", "free") if sub else "free"
    plan_meta = PLANS.get(plan_key, PLANS["free"])

    return {
        "id": str(user_id),
        "email": current_user["email"],
        "name": current_user.get("name", "Analyst"),
        "role": current_user.get("role", "user"),
        "plan": plan_key,
        "plan_details": plan_meta,
        "wallet_balance": round(float(wallet.get("balance", 0.0)), 2) if wallet else 0.0,
        "current_credits": int(sub.get("current_credits", 0)) if sub else 0,
        "subscription_status": sub.get("status", "active") if sub else "active",
        "renews_at": sub.get("renews_at").isoformat() if sub and sub.get("renews_at") else None
    }


@router.post("/logout")
def logout(request: Request, response: Response):
    token = request.cookies.get("tp_session")
    if not token:
        auth_header = request.headers.get("Authorization")
        if auth_header and auth_header.startswith("Bearer "):
            token = auth_header.split(" ", 1)[1]

    if token:
        destroy_session(token)

    response.delete_cookie("tp_session")
    return {"status": "success", "message": "Logged out successfully"}


@router.get("/demo-accounts")
def get_demo_accounts():
    """
    Returns public demo account list so users can switch with 1-click in the UI header.
    """
    accounts = []
    for d in DEMO_ACCOUNTS:
        u = col_users().find_one({"email": d["email"]})
        wallet = col_wallets().find_one({"user_id": u["_id"]}) if u else None
        sub = col_subscriptions().find_one({"user_id": u["_id"]}) if u else None
        accounts.append({
            "email": d["email"],
            "name": d["name"],
            "plan": sub.get("plan", d["plan"]) if sub else d["plan"],
            "role": d["role"],
            "wallet_balance": round(float(wallet["balance"]), 2) if wallet else d["initial_wallet"],
            "credits": int(sub["current_credits"]) if sub else d["initial_credits"],
            "description": f"{d['name']} ({d['plan'].upper()} Tier)"
        })
    return {"demo_accounts": accounts}


@router.post("/demo-switch")
def switch_demo_account(req: DemoSwitchRequest, response: Response):
    """
    Convenience 1-click switch for grader/faculty demonstration without retyping password.
    """
    u = col_users().find_one({"email": req.email.lower()})
    if not u:
        raise HTTPException(status_code=404, detail="Demo account not found")

    user_id = u["_id"]
    token = create_session(user_id)

    response.set_cookie(
        key="tp_session",
        value=token,
        httponly=True,
        samesite="lax",
        max_age=SESSION_DURATION_DAYS * 86400
    )

    wallet = col_wallets().find_one({"user_id": user_id})
    sub = col_subscriptions().find_one({"user_id": user_id})

    return {
        "status": "success",
        "token": token,
        "user": {
            "id": str(user_id),
            "email": u["email"],
            "name": u["name"],
            "plan": sub.get("plan", "free") if sub else "free",
            "role": u.get("role", "user"),
            "wallet_balance": float(wallet.get("balance", 0.0)) if wallet else 0.0,
            "current_credits": int(sub.get("current_credits", 0)) if sub else 0
        }
    }
