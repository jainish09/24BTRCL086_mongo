"""
ThreatPulse SOC Platform - Billing & Subscription Routes
Implements transactional plan checkout, coupon validation, wallet funding,
and full printable invoice/receipt generation.
"""

from fastapi import APIRouter, HTTPException, Depends
from pydantic import BaseModel, Field
from typing import Optional, List
import datetime
from bson import ObjectId

from config import PLANS
from database import (
    col_wallets,
    col_wallet_tx,
    col_subscriptions,
    col_payments,
    col_coupons,
    col_receipts
)
from auth import require_auth
from transactions import (
    subscribe_to_plan_transactional,
    top_up_wallet_transactional,
    InsufficientFundsError,
    CouponInvalidError
)

router = APIRouter(prefix="/api/billing", tags=["billing"])


class TopUpRequest(BaseModel):
    amount: float = Field(..., gt=0, le=5000, description="Amount to fund in USD")


class SubscribeRequest(BaseModel):
    plan_id: str = Field(..., description="Target plan ID ('plus' or 'pro')")
    coupon_code: Optional[str] = Field(None, description="Optional promotional discount code")


class ValidateCouponRequest(BaseModel):
    code: str
    plan_id: str


@router.get("/plans")
def get_plans():
    """
    Returns available subscription tiers with pricing and credit allocations.
    """
    return {
        "status": "success",
        "plans": list(PLANS.values())
    }


@router.get("/wallet")
def get_wallet(current_user: dict = Depends(require_auth)):
    """
    Returns current user's wallet balance and recent ledger history.
    """
    user_id = current_user["_id"]
    wallet = col_wallets().find_one({"user_id": user_id})
    balance = float(wallet.get("balance", 0.0)) if wallet else 0.0

    recent_tx = list(col_wallet_tx().find(
        {"user_id": user_id}
    ).sort("timestamp", -1).limit(10))

    tx_list = []
    for tx in recent_tx:
        tx_list.append({
            "tx_id": tx.get("tx_id"),
            "amount": tx.get("amount"),
            "balance_after": tx.get("balance_after"),
            "direction": tx.get("direction"),
            "category": tx.get("category"),
            "description": tx.get("description"),
            "timestamp": tx.get("timestamp").isoformat() if tx.get("timestamp") else None
        })

    return {
        "user_id": str(user_id),
        "balance": round(balance, 2),
        "currency": "USD",
        "recent_transactions": tx_list
    }


@router.post("/top-up")
def top_up_wallet(req: TopUpRequest, current_user: dict = Depends(require_auth)):
    """
    Adds funds to the user's SOC platform wallet using a MongoDB multi-document transaction.
    """
    user_id = current_user["_id"]
    try:
        receipt = top_up_wallet_transactional(
            user_id=user_id,
            amount=req.amount,
            payment_method="SIMULATED_SOC_CARD"
        )
        return {
            "status": "success",
            "message": f"Successfully added ${req.amount:.2f} to wallet",
            "receipt": receipt
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to fund wallet: {str(e)}")


@router.post("/coupon/validate")
def validate_coupon(req: ValidateCouponRequest, current_user: dict = Depends(require_auth)):
    """
    Checks if a coupon is valid, not exhausted, and computes the discounted price.
    """
    plan = PLANS.get(req.plan_id)
    if not plan:
        raise HTTPException(status_code=400, detail="Invalid plan selected")

    base_price = float(plan["price"])
    coupon = col_coupons().find_one({"code": req.code.strip().upper(), "is_active": True})

    if not coupon:
        raise HTTPException(status_code=404, detail="Coupon code not found or expired")

    if coupon.get("used_count", 0) >= coupon.get("max_uses", 999999):
        raise HTTPException(status_code=400, detail="Coupon code redemption limit reached")

    disc_type = coupon.get("discount_type")
    disc_val = float(coupon.get("discount_value", 0.0))

    if disc_type == "percentage":
        discount_amount = round(base_price * (disc_val / 100.0), 2)
    elif disc_type == "flat":
        discount_amount = min(base_price, disc_val)
    else:
        discount_amount = 0.0

    final_price = max(0.0, round(base_price - discount_amount, 2))

    return {
        "status": "valid",
        "code": coupon["code"],
        "description": coupon.get("description", ""),
        "base_price": base_price,
        "discount_amount": discount_amount,
        "final_price": final_price,
        "remaining_uses": coupon.get("max_uses", 0) - coupon.get("used_count", 0)
    }


@router.post("/subscribe")
def subscribe(req: SubscribeRequest, current_user: dict = Depends(require_auth)):
    """
    Upgrades user subscription via atomic MongoDB Multi-Document Transaction:
    1. Snapshot read wallet, plan, coupon
    2. Debit user wallet
    3. Credit platform revenue
    4. Decrement coupon inventory (if used)
    5. Update subscription & deposit plan credits
    6. Insert credit ledger entry
    7. Generate payment invoice record
    8. Write audit receipt
    All or nothing!
    """
    user_id = current_user["_id"]
    try:
        receipt = subscribe_to_plan_transactional(
            user_id=user_id,
            target_plan_id=req.plan_id,
            coupon_code=req.coupon_code
        )
        return {
            "status": "success",
            "message": f"Successfully upgraded to {receipt.get('plan_name')} tier!",
            "receipt": receipt
        }
    except InsufficientFundsError as e:
        raise HTTPException(status_code=402, detail=str(e))
    except CouponInvalidError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Transaction Failed: {str(e)}")


@router.get("/invoices")
def get_invoices(current_user: dict = Depends(require_auth)):
    """
    Returns payment invoices / history for current user.
    """
    user_id = current_user["_id"]
    payments = list(col_payments().find({"user_id": user_id}).sort("timestamp", -1))
    
    invoices = []
    for p in payments:
        invoices.append({
            "payment_id": p.get("payment_id"),
            "plan_id": p.get("plan_id"),
            "plan_name": p.get("plan_name"),
            "amount_paid": p.get("amount_paid"),
            "credits_granted": p.get("credits_granted"),
            "coupon_code": p.get("coupon_code"),
            "discount_applied": p.get("discount_applied", 0.0),
            "status": p.get("status"),
            "timestamp": p.get("timestamp").isoformat() if p.get("timestamp") else None
        })

    return {"status": "success", "invoices": invoices}


@router.get("/receipts/{receipt_id}")
def get_receipt(receipt_id: str, current_user: dict = Depends(require_auth)):
    """
    Returns full cryptographic & audit timeline receipt for any transaction.
    """
    receipt = col_receipts().find_one({"receipt_id": receipt_id})
    if not receipt:
        raise HTTPException(status_code=404, detail="Receipt not found")

    # Only owner or admin can view
    if receipt.get("user_id") != current_user["_id"] and current_user.get("role") != "admin":
        raise HTTPException(status_code=403, detail="Unauthorized to view this receipt")

    # Serialize ObjectId and datetime
    receipt_copy = dict(receipt)
    if "_id" in receipt_copy:
        receipt_copy["_id"] = str(receipt_copy["_id"])
    if "user_id" in receipt_copy and isinstance(receipt_copy["user_id"], ObjectId):
        receipt_copy["user_id"] = str(receipt_copy["user_id"])
    if "timestamp" in receipt_copy and isinstance(receipt_copy["timestamp"], datetime.datetime):
        receipt_copy["timestamp"] = receipt_copy["timestamp"].isoformat()

    return {"status": "success", "receipt": receipt_copy}
