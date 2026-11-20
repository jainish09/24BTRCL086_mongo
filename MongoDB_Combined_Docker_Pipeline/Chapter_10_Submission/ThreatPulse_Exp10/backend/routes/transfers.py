"""
ThreatPulse SOC Platform - Peer-to-Peer Credit Transfer Routes
Implements atomic P2P credit transfer between analysts (Part 10.1 Bank Transfer):
Debit sender -> Credit recipient -> Dual credit ledgers -> Transfer audit log.
Rolls back completely if recipient is not found or sender has insufficient credits.
"""

from fastapi import APIRouter, HTTPException, Depends
from pydantic import BaseModel, Field, EmailStr
from typing import Optional, List
import datetime
from bson import ObjectId

from database import col_credit_transfers
from auth import require_auth
from transactions import (
    peer_to_peer_transfer_transactional,
    InsufficientCreditsError,
    AccountNotFoundError
)

router = APIRouter(prefix="/api/transfers", tags=["transfers"])


class P2PTransferRequest(BaseModel):
    recipient_email: EmailStr = Field(..., description="Destination analyst email address")
    amount: int = Field(..., gt=0, le=10000, description="Amount of credits to send")
    memo: Optional[str] = Field("Threat Intel collaborative task sharing", description="Optional transfer note")
    simulate_receiver_failure: bool = Field(False, description="Simulate unknown receiver / crash to prove rollback")


@router.post("/send")
def send_credits(req: P2PTransferRequest, current_user: dict = Depends(require_auth)):
    """
    Executes a P2P credit transfer inside a MongoDB multi-document transaction.
    """
    sender_id = current_user["_id"]
    try:
        receipt = peer_to_peer_transfer_transactional(
            sender_user_id=sender_id,
            recipient_email=req.recipient_email,
            amount=req.amount,
            memo=req.memo,
            simulate_receiver_failure=req.simulate_receiver_failure
        )
        return {
            "status": "success",
            "message": f"Successfully transferred {req.amount} credits to {req.recipient_email}",
            "receipt": receipt
        }
    except InsufficientCreditsError as e:
        raise HTTPException(status_code=402, detail=str(e))
    except AccountNotFoundError as e:
        raise HTTPException(status_code=404, detail=str(e))
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Transfer Failed: {str(e)}")


@router.get("/history")
def get_transfer_history(current_user: dict = Depends(require_auth)):
    """
    Returns P2P transfer log where current user is either sender or recipient.
    """
    user_id = current_user["_id"]
    transfers = list(col_credit_transfers().find({
        "$or": [
            {"sender_id": user_id},
            {"recipient_id": user_id}
        ]
    }).sort("timestamp", -1).limit(25))

    formatted = []
    for t in transfers:
        is_sender = (t.get("sender_id") == user_id)
        formatted.append({
            "transfer_id": t.get("transfer_id"),
            "amount": t.get("amount"),
            "sender_email": t.get("sender_email"),
            "recipient_email": t.get("recipient_email"),
            "role": "SENDER" if is_sender else "RECIPIENT",
            "memo": t.get("memo"),
            "status": t.get("status"),
            "timestamp": t.get("timestamp").isoformat() if t.get("timestamp") else None
        })

    return {"status": "success", "transfers": formatted}
