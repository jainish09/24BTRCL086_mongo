"""
ThreatPulse SOC Platform - Multi-Document Transaction Engine
Core transactional business logic for Experiment 10:
- 10.1 Bank Transfer (Atomicity): Subscribing to plans, P2P credit transfers
- 10.1-try Retry: Exponential backoff & jitter for TransientTransactionError
- 10.2 Inventory Reservation: Anti-overselling of limited quota stock
- 10.2-bench Throughput: Operations/sec with increasing parallel workers
"""

import time
import random
import secrets
import inspect
from datetime import datetime, timezone, timedelta
from typing import Dict, Any, Optional, List, Callable
from bson import ObjectId

from pymongo.errors import PyMongoError
from pymongo.read_concern import ReadConcern
from pymongo.write_concern import WriteConcern
from pymongo.read_preferences import ReadPreference

from config import (
    PLANS,
    FEATURE_CREDIT_COSTS,
    PLATFORM_WALLET_ID,
    INITIAL_COUPONS
)
from database import (
    get_client,
    col_users,
    col_wallets,
    col_wallet_tx,
    col_subscriptions,
    col_credit_ledger,
    col_payments,
    col_credit_transfers,
    col_usage_log,
    col_stock,
    col_coupons,
    col_receipts
)


def to_oid(val: Any) -> Any:
    """Safely converts string to ObjectId if applicable."""
    if isinstance(val, ObjectId):
        return val
    try:
        return ObjectId(str(val))
    except Exception:
        return val


class TransactionError(Exception):
    """Base exception for application transaction failures."""
    pass


class InsufficientFundsError(TransactionError):
    pass


class InsufficientCreditsError(TransactionError):
    pass


class OutOfStockError(TransactionError):
    pass


# Alias for compatibility
InventoryOutOfStockError = OutOfStockError


class CouponInvalidError(TransactionError):
    pass


class AccountNotFoundError(TransactionError):
    pass


class ReceiptLogger:
    """Helper logger for step-by-step transaction timeline recording."""
    def __init__(self, action: str, user_id: Any):
        self.receipt_id = f"rcpt_{secrets.token_hex(6)}"
        self.context = {
            "receipt_id": self.receipt_id,
            "type": action,
            "user_id": user_id,
            "steps": [],
            "status": "IN_PROGRESS",
            "retry_attempts": 0,
            "started_at": datetime.now(timezone.utc).isoformat()
        }

    def step(self, name: str, detail: str = ""):
        self.context["steps"].append({
            "step": name,
            "detail": detail,
            "timestamp": datetime.now(timezone.utc).isoformat()
        })

    def finish(self, status: str = "COMMITTED") -> Dict[str, Any]:
        self.context["status"] = status
        self.context["completed_at"] = datetime.now(timezone.utc).isoformat()
        try:
            col_receipts().insert_one({**self.context})
        except Exception:
            pass
        return self.context


def commit_with_retry(session, receipt_context: Dict[str, Any]):
    """Retries committing if UnknownTransactionCommitResult occurs."""
    while True:
        try:
            session.commit_transaction()
            receipt_context["steps"].append({
                "step": "TRANSACTION_COMMIT",
                "status": "SUCCESS",
                "timestamp": datetime.now(timezone.utc).isoformat()
            })
            break
        except PyMongoError as exc:
            if exc.has_error_label("UnknownTransactionCommitResult"):
                receipt_context["steps"].append({
                    "step": "UNKNOWN_COMMIT_RETRY",
                    "status": "RETRYING",
                    "timestamp": datetime.now(timezone.utc).isoformat()
                })
                time.sleep(0.04)
                continue
            else:
                receipt_context["steps"].append({
                    "step": "COMMIT_FAILURE",
                    "error": str(exc),
                    "timestamp": datetime.now(timezone.utc).isoformat()
                })
                raise


def run_transaction_with_retry(*args, **kwargs) -> Dict[str, Any]:
    """
    Executes a multi-document transaction with exponential backoff & jitter for TransientTransactionError,
    and commit retry for UnknownTransactionCommitResult.
    Accepts flexible calling conventions:
      run_transaction_with_retry(txn_func, receipt_context)
      run_transaction_with_retry(client, txn_func, logger=...)
    """
    if len(args) > 0 and not callable(args[0]):
        client = args[0]
        txn_func = args[1]
        raw_context = args[2] if len(args) > 2 else kwargs.get("receipt_context", {})
    else:
        client = get_client()
        txn_func = args[0]
        raw_context = args[1] if len(args) > 1 else kwargs.get("receipt_context", {})

    logger_inst = kwargs.get("logger")
    if isinstance(raw_context, ReceiptLogger):
        receipt_context = raw_context.context
    elif isinstance(logger_inst, ReceiptLogger):
        receipt_context = logger_inst.context
    elif isinstance(raw_context, dict):
        receipt_context = raw_context
    else:
        receipt_context = {}

    max_retries = kwargs.get("max_retries", 5)
    initial_backoff = kwargs.get("initial_backoff", 0.05)
    t_start = time.time()

    receipt_context.setdefault("receipt_id", f"rcpt_{secrets.token_hex(6)}")
    receipt_context["started_at"] = datetime.now(timezone.utc).isoformat()
    receipt_context.setdefault("steps", [])
    receipt_context["retries"] = 0

    # Determine if txn_func accepts 1 or 2 parameters
    try:
        sig = inspect.signature(txn_func)
        accepts_context = len(sig.parameters) >= 2
    except Exception:
        accepts_context = True

    with client.start_session() as session:
        for attempt in range(max_retries):
            try:
                receipt_context["steps"].append({
                    "step": "TRANSACTION_START",
                    "status": "INITIATED",
                    "attempt": attempt + 1,
                    "timestamp": datetime.now(timezone.utc).isoformat()
                })

                session.start_transaction(
                    read_concern=ReadConcern("snapshot"),
                    write_concern=WriteConcern("majority"),
                    read_preference=ReadPreference.PRIMARY
                )

                # Execute callback logic
                if accepts_context:
                    result = txn_func(session, receipt_context)
                else:
                    result = txn_func(session)

                # Commit transaction with commit retry
                commit_with_retry(session, receipt_context)

                # Finalize receipt
                receipt_context["status"] = "COMMITTED"
                receipt_context["completed_at"] = datetime.now(timezone.utc).isoformat()
                receipt_context["duration_ms"] = round((time.time() - t_start) * 1000, 2)
                receipt_context["retries"] = attempt
                receipt_context["retry_attempts"] = attempt + 1
                if result is not None and isinstance(result, dict):
                    receipt_context.update({k: v for k, v in result.items() if k not in receipt_context})

                try:
                    col_receipts().update_one(
                        {"receipt_id": receipt_context["receipt_id"]},
                        {"$set": receipt_context},
                        upsert=True
                    )
                except Exception:
                    pass

                return receipt_context

            except PyMongoError as exc:
                if session.in_transaction:
                    try:
                        session.abort_transaction()
                    except Exception:
                        pass

                if exc.has_error_label("TransientTransactionError"):
                    backoff = initial_backoff * (2 ** attempt) + random.uniform(0.01, 0.05)
                    receipt_context["steps"].append({
                        "step": "TRANSIENT_WRITE_CONFLICT_RETRY",
                        "attempt": attempt + 1,
                        "error_label": "TransientTransactionError",
                        "backoff_sec": round(backoff, 4),
                        "timestamp": datetime.now(timezone.utc).isoformat()
                    })
                    time.sleep(backoff)
                    continue
                else:
                    receipt_context["status"] = "ABORTED"
                    receipt_context["error"] = str(exc)
                    receipt_context["duration_ms"] = round((time.time() - t_start) * 1000, 2)
                    receipt_context["steps"].append({
                        "step": "TRANSACTION_ABORTED_ON_ERROR",
                        "error": str(exc),
                        "timestamp": datetime.now(timezone.utc).isoformat()
                    })
                    try:
                        col_receipts().insert_one({**receipt_context})
                    except Exception:
                        pass
                    raise TransactionError(f"Database transaction aborted: {exc}")

            except (TransactionError, ValueError) as exc:
                if session.in_transaction:
                    try:
                        session.abort_transaction()
                    except Exception:
                        pass
                receipt_context["status"] = "ROLLED_BACK"
                receipt_context["error"] = str(exc)
                receipt_context["duration_ms"] = round((time.time() - t_start) * 1000, 2)
                receipt_context["steps"].append({
                    "step": "BUSINESS_RULE_ROLLBACK",
                    "reason": str(exc),
                    "proof_of_reversal": "All temporary modifications discarded. Zero state change.",
                    "timestamp": datetime.now(timezone.utc).isoformat()
                })
                try:
                    col_receipts().insert_one({**receipt_context})
                except Exception:
                    pass
                raise

            except Exception as exc:
                if session.in_transaction:
                    try:
                        session.abort_transaction()
                    except Exception:
                        pass
                receipt_context["status"] = "SYSTEM_FAULT_ROLLBACK"
                receipt_context["error"] = str(exc)
                receipt_context["duration_ms"] = round((time.time() - t_start) * 1000, 2)
                try:
                    col_receipts().insert_one({**receipt_context})
                except Exception:
                    pass
                raise TransactionError(f"Unexpected fault during transaction: {exc}")

        raise TransactionError(f"Transaction exceeded maximum retry limit ({max_retries}) on contention.")


# =========================================================================
# EXPERIMENT 10.1: BANK TRANSFER & PLAN SUBSCRIPTION (ATOMICITY)
# =========================================================================

def subscribe_to_plan_transactional(
    user_id: Any,
    plan_id: Optional[str] = None,
    coupon_code: Optional[str] = None,
    target_plan_id: Optional[str] = None
) -> Dict[str, Any]:
    """
    Subscribes a user to a plan atomically in ONE transaction:
    1. Validate plan and calculate final price (applying coupon if present)
    2. Debit user's wallet with {balance: {$gte: final_price}}
    3. Credit platform's revenue wallet
    4. Record payment record with invoice ID
    5. Update user's active subscription & plan level
    6. Deposit monthly plan credits to user account (both users and subscriptions)
    7. Write immutable credit ledger record
    8. Decrement coupon usage atomically if coupon used
    """
    plan_id = plan_id or target_plan_id
    plan = PLANS.get(plan_id)
    if not plan:
        raise TransactionError(f"Invalid plan ID: {plan_id}")

    uid = to_oid(user_id)
    receipt_id = f"rcpt_sub_{secrets.token_hex(6)}"
    invoice_id = f"INV-2026-{secrets.token_hex(4).upper()}"
    base_price = float(plan["price"])
    final_price = base_price
    coupon_applied = None

    context = {
        "receipt_id": receipt_id,
        "type": "SUBSCRIPTION_PAYMENT",
        "user_id": uid,
        "plan_id": plan_id,
        "target_plan": plan_id,
        "plan_name": plan["name"],
        "invoice_id": invoice_id,
        "base_price": base_price,
        "final_price": final_price,
        "credits_awarded": plan["monthly_credits"]
    }

    def _txn_body(session, rcpt):
        now_dt = datetime.now(timezone.utc)
        now_iso = now_dt.isoformat()

        # Step A: Validate and apply coupon inside transaction if provided
        nonlocal final_price, coupon_applied
        if coupon_code:
            c_code = coupon_code.strip().upper()
            c_res = col_coupons().update_one(
                {"code": c_code, "$expr": {"$lt": ["$used_count", "$max_uses"]}},
                {"$inc": {"used_count": 1}},
                session=session
            )
            if c_res.matched_count == 0:
                raise CouponInvalidError(f"Coupon '{c_code}' is invalid, expired, or fully redeemed.")
            
            coupon_doc = col_coupons().find_one({"code": c_code}, session=session)
            if coupon_doc:
                disc_type = coupon_doc.get("discount_type") or coupon_doc.get("type")
                disc_val = float(coupon_doc.get("discount_value") or coupon_doc.get("value", 0))
                if disc_type == "percentage":
                    discount = round(base_price * (disc_val / 100.0), 2)
                    final_price = max(0.0, round(base_price - discount, 2))
                elif disc_type == "flat":
                    final_price = max(0.0, round(base_price - disc_val, 2))
                coupon_applied = c_code

        rcpt["final_price"] = final_price
        rcpt["coupon_applied"] = coupon_applied
        rcpt["steps"].append({
            "step": "PRICE_CALCULATION",
            "base_price": base_price,
            "final_price": final_price,
            "coupon": coupon_applied,
            "timestamp": now_iso
        })

        # Step B: Read user's current wallet balance
        user_wallet = col_wallets().find_one({"user_id": uid}, session=session)
        if not user_wallet:
            raise AccountNotFoundError(f"Wallet not found for user {user_id}")
        wallet_before = float(user_wallet.get("balance", 0.0))

        # Step C: Debit User Wallet (Filter enforces balance >= final_price)
        if final_price > 0.0:
            w_res = col_wallets().update_one(
                {"user_id": uid, "balance": {"$gte": final_price}},
                {"$inc": {"balance": -final_price}, "$set": {"updated_at": now_dt}},
                session=session
            )
            if w_res.matched_count == 0:
                raise InsufficientFundsError(
                    f"Insufficient funds in wallet! Required: ${final_price:.2f}, Available: ${wallet_before:.2f}"
                )
        
        wallet_after = wallet_before - final_price
        rcpt["steps"].append({
            "step": "WALLET_DEBIT",
            "user_id": str(uid),
            "amount_debited": final_price,
            "wallet_before": wallet_before,
            "wallet_after": wallet_after,
            "timestamp": now_iso
        })

        # Step D: Credit Platform Revenue Account
        if final_price > 0.0:
            col_wallets().update_one(
                {"user_id": PLATFORM_WALLET_ID},
                {"$inc": {"balance": final_price}, "$set": {"updated_at": now_dt}},
                upsert=True,
                session=session
            )
            rcpt["steps"].append({
                "step": "PLATFORM_REVENUE_CREDIT",
                "credited_to": PLATFORM_WALLET_ID,
                "amount": final_price,
                "timestamp": now_iso
            })

        # Step E: Insert Payment Record with Invoice
        col_payments().insert_one({
            "payment_id": invoice_id,
            "user_id": uid,
            "plan_id": plan_id,
            "plan_name": plan["name"],
            "amount_paid": final_price,
            "credits_granted": plan["monthly_credits"],
            "coupon_code": coupon_applied,
            "status": "COMPLETED",
            "receipt_id": receipt_id,
            "timestamp": now_dt
        }, session=session)

        # Step F: Update User Plan & Add Monthly Credits on BOTH col_users & col_subscriptions
        col_users().update_one(
            {"_id": uid},
            {
                "$set": {"plan": plan_id, "updated_at": now_dt},
                "$inc": {"credits": plan["monthly_credits"]}
            },
            session=session
        )

        user_doc_after = col_users().find_one({"_id": uid}, session=session)
        credits_after = user_doc_after.get("credits", 0) if user_doc_after else plan["monthly_credits"]

        renewal_date = now_dt + timedelta(days=30)
        col_subscriptions().update_one(
            {"user_id": uid},
            {
                "$set": {
                    "plan": plan_id,
                    "status": "active",
                    "started_at": now_dt,
                    "renews_at": renewal_date,
                    "updated_at": now_dt
                },
                "$inc": {"current_credits": plan["monthly_credits"]}
            },
            upsert=True,
            session=session
        )

        # Step G: Append Credit Ledger Line
        col_credit_ledger().insert_one({
            "txn_id": receipt_id,
            "user_id": uid,
            "amount": plan["monthly_credits"],
            "delta": plan["monthly_credits"],
            "balance_after": credits_after,
            "action": "PLAN_UPGRADE_GRANT",
            "reason": f"Plan Subscription: {plan['name']} (Invoice {invoice_id})",
            "timestamp": now_dt
        }, session=session)

        rcpt["steps"].append({
            "step": "SUBSCRIPTION_AND_CREDITS_DEPOSITED",
            "plan": plan_id,
            "credits_added": plan["monthly_credits"],
            "credits_total_after": credits_after,
            "renewal_date": renewal_date.isoformat(),
            "timestamp": now_iso
        })

        return {
            "invoice_id": invoice_id,
            "plan": plan,
            "amount_paid": final_price,
            "new_wallet_balance": wallet_after,
            "new_credits_balance": credits_after,
            "renewal_date": renewal_date.isoformat()
        }

    return run_transaction_with_retry(_txn_body, context)


def top_up_wallet_transactional(user_id: Any, amount: float, **kwargs) -> Dict[str, Any]:
    """Adds balance to user wallet in a structured transaction."""
    if amount <= 0:
        raise TransactionError("Top-up amount must be greater than zero.")

    uid = to_oid(user_id)
    receipt_id = f"rcpt_top_{secrets.token_hex(6)}"
    context = {
        "receipt_id": receipt_id,
        "type": "WALLET_TOP_UP",
        "user_id": uid,
        "amount": amount
    }

    def _txn_body(session, rcpt):
        now_dt = datetime.now(timezone.utc)
        user_wallet = col_wallets().find_one({"user_id": uid}, session=session)
        if not user_wallet:
            raise AccountNotFoundError("Wallet not found.")
        before = float(user_wallet.get("balance", 0.0))

        col_wallets().update_one(
            {"user_id": uid},
            {"$inc": {"balance": amount}, "$set": {"updated_at": now_dt}},
            session=session
        )
        after = round(before + amount, 2)

        col_wallet_tx().insert_one({
            "tx_id": f"tx_{secrets.token_hex(6)}",
            "user_id": uid,
            "amount": amount,
            "direction": "CREDIT",
            "category": "WALLET_TOP_UP",
            "description": f"Funded ${amount:.2f} via SOC Credit Portal",
            "receipt_id": receipt_id,
            "balance_after": after,
            "timestamp": now_dt
        }, session=session)

        rcpt["steps"].append({
            "step": "WALLET_FUNDS_ADDED",
            "amount": amount,
            "before": before,
            "after": after,
            "timestamp": now_dt.isoformat()
        })
        return {"amount": amount, "balance_after": after}

    return run_transaction_with_retry(_txn_body, context)


def peer_to_peer_transfer_transactional(
    sender_id: Any = None,
    receiver_email: Optional[str] = None,
    credits_to_send: Optional[int] = None,
    sender_user_id: Any = None,
    recipient_email: Optional[str] = None,
    amount: Optional[int] = None,
    memo: Optional[str] = None,
    simulate_receiver_failure: bool = False
) -> Dict[str, Any]:
    """
    P2P Credit Transfer:
    1. Debit sender credits {credits: {$gte: credits_to_send}}
    2. Lookup receiver by email. If not found, raise AccountNotFoundError & ROLLBACK!
    3. Credit receiver credits (both col_users & col_subscriptions)
    4. Write sender and receiver ledger entries
    5. Log transfer record
    """
    sid = to_oid(sender_id or sender_user_id)
    r_email = (receiver_email or recipient_email or "").strip().lower()
    qty = credits_to_send or amount or 0

    if qty <= 0:
        raise TransactionError("Credits to transfer must be greater than zero.")

    receipt_id = f"rcpt_p2p_{secrets.token_hex(6)}"
    context = {
        "receipt_id": receipt_id,
        "type": "PEER_TO_PEER_TRANSFER",
        "sender_id": sid,
        "receiver_email": r_email,
        "credits": qty,
        "memo": memo or "SOC Threat Intel Sharing"
    }

    def _txn_body(session, rcpt):
        now_dt = datetime.now(timezone.utc)
        now_str = now_dt.isoformat()

        # 1. Debit sender
        sender = col_users().find_one({"_id": sid}, session=session)
        if not sender:
            raise AccountNotFoundError("Sender account does not exist.")

        sender_before = sender.get("credits", 0)
        s_res = col_users().update_one(
            {"_id": sid, "credits": {"$gte": qty}},
            {"$inc": {"credits": -qty}, "$set": {"updated_at": now_dt}},
            session=session
        )
        if s_res.matched_count == 0:
            raise InsufficientCreditsError(f"Insufficient credits. Balance: {sender_before}, Required: {qty}")

        # Keep subscriptions in sync
        col_subscriptions().update_one(
            {"user_id": sid},
            {"$inc": {"current_credits": -qty}, "$set": {"updated_at": now_dt}},
            session=session
        )

        sender_after = sender_before - qty
        rcpt["steps"].append({
            "step": "SENDER_CREDITS_DEBITED",
            "sender_id": str(sid),
            "credits_debited": qty,
            "sender_before": sender_before,
            "sender_after": sender_after,
            "timestamp": now_str
        })

        # 2. Simulated failure or receiver lookup
        if simulate_receiver_failure:
            raise AccountNotFoundError(f"Simulated receiver connection timeout to '{r_email}'. Complete rollback triggered.")

        # Lookup receiver by email inside transaction
        receiver = col_users().find_one({"email": r_email}, session=session)
        if not receiver:
            # THIS INTENTIONALLY TRIGGERS A FULL ROLLBACK IF RECEIVER IS UNKNOWN!
            raise AccountNotFoundError(f"Receiver account with email '{r_email}' does not exist. Full rollback executed.")

        receiver_id = receiver["_id"]
        receiver_before = receiver.get("credits", 0)

        # 3. Credit receiver on both users and subscriptions
        col_users().update_one(
            {"_id": receiver_id},
            {"$inc": {"credits": qty}, "$set": {"updated_at": now_dt}},
            session=session
        )
        col_subscriptions().update_one(
            {"user_id": receiver_id},
            {"$inc": {"current_credits": qty}, "$set": {"updated_at": now_dt}},
            session=session
        )
        receiver_after = receiver_before + qty

        rcpt["steps"].append({
            "step": "RECEIVER_CREDITS_DEPOSITED",
            "receiver_id": str(receiver_id),
            "receiver_email": r_email,
            "receiver_before": receiver_before,
            "receiver_after": receiver_after,
            "timestamp": now_str
        })

        # 4. Write Ledgers for both accounts
        transfer_id = f"TRF-{secrets.token_hex(4).upper()}"
        col_credit_ledger().insert_one({
            "txn_id": receipt_id,
            "user_id": sid,
            "amount": -qty,
            "delta": -qty,
            "balance_after": sender_after,
            "action": "P2P_TRANSFER_OUT",
            "reason": f"P2P Transfer to {r_email} ({transfer_id})",
            "timestamp": now_dt
        }, session=session)

        col_credit_ledger().insert_one({
            "txn_id": receipt_id,
            "user_id": receiver_id,
            "amount": qty,
            "delta": qty,
            "balance_after": receiver_after,
            "action": "P2P_TRANSFER_IN",
            "reason": f"P2P Transfer from {sender.get('email')} ({transfer_id})",
            "timestamp": now_dt
        }, session=session)

        col_credit_transfers().insert_one({
            "transfer_id": transfer_id,
            "receipt_id": receipt_id,
            "sender_id": sid,
            "sender_email": sender.get("email"),
            "receiver_id": receiver_id,
            "recipient_id": receiver_id,
            "receiver_email": r_email,
            "recipient_email": r_email,
            "amount": qty,
            "credits": qty,
            "memo": memo or "",
            "status": "COMPLETED",
            "timestamp": now_dt
        }, session=session)

        return {
            "transfer_id": transfer_id,
            "credits_sent": qty,
            "receiver_email": r_email,
            "sender_credits_left": sender_after
        }

    return run_transaction_with_retry(_txn_body, context)


# =========================================================================
# EXPERIMENT 10.2: INVENTORY RESERVATION & PAID FEATURE EXECUTION
# =========================================================================

def execute_paid_feature_transactional(
    user_id: Any,
    feature_key: str,
    payload: Optional[Dict[str, Any]] = None,
    simulate_failure: bool = False,
    item_key: Optional[str] = None,
    target_observable: Optional[str] = None,
    credit_cost_override: Optional[int] = None,
    **kwargs
) -> Dict[str, Any]:
    """
    Executes a paid feature (VirusTotal live scan, Verifier check, or IOC export):
    1. Checks and debits credits {credits: {$gte: cost}}
    2. If feature requires limited inventory stock (e.g. VirusTotal daily quota slots),
       atomically reserves slot: {item_key: "vt_quota", available_units: {$gte: 1}}
    3. Writes credit ledger entry
    4. Writes usage log
    5. If feature execution fails or simulate_failure=True, ROLLS BACK EVERYTHING (no credit or stock loss)!
    """
    uid = to_oid(user_id)
    if credit_cost_override is not None:
        cost = credit_cost_override
    else:
        cost = FEATURE_CREDIT_COSTS.get(feature_key, 2)

    receipt_id = f"rcpt_feat_{secrets.token_hex(6)}"
    stock_item = item_key or ("vt_quota" if feature_key == "vt_scan" else None)

    context = {
        "receipt_id": receipt_id,
        "type": "FEATURE_EXECUTION",
        "user_id": uid,
        "feature_key": feature_key,
        "credit_cost": cost,
        "item_key": stock_item,
        "target_observable": target_observable,
        "payload": payload or {}
    }

    def _txn_body(session, rcpt):
        now_dt = datetime.now(timezone.utc)
        now_str = now_dt.isoformat()

        # Step 1: Debit credits
        user = col_users().find_one({"_id": uid}, session=session)
        if not user:
            raise AccountNotFoundError("User not found.")
        c_before = user.get("credits", 0)

        u_res = col_users().update_one(
            {"_id": uid, "credits": {"$gte": cost}},
            {"$inc": {"credits": -cost}, "$set": {"updated_at": now_dt}},
            session=session
        )
        if u_res.matched_count == 0:
            raise InsufficientCreditsError(f"Feature '{feature_key}' requires {cost} credits. Current balance: {c_before}")

        # Keep subscriptions collection in sync
        col_subscriptions().update_one(
            {"user_id": uid},
            {"$inc": {"current_credits": -cost}, "$set": {"updated_at": now_dt}},
            session=session
        )

        c_after = c_before - cost
        rcpt["steps"].append({
            "step": "FEATURE_CREDIT_DEBIT",
            "credits_deducted": cost,
            "before": c_before,
            "after": c_after,
            "timestamp": now_str
        })

        # Step 2: Atomic Inventory Reservation (if stock item specified or VirusTotal scan)
        stock_after = None
        if stock_item:
            s_res = col_stock().update_one(
                {"item_key": stock_item, "available_units": {"$gte": 1}},
                {"$inc": {"available_units": -1, "reserved_units": 1}, "$set": {"updated_at": now_dt}},
                session=session
            )
            if s_res.matched_count == 0:
                raise OutOfStockError(f"Daily quota slots for '{stock_item}' are completely exhausted! Zero overselling enforced.")
            stock_doc = col_stock().find_one({"item_key": stock_item}, session=session)
            stock_after = stock_doc.get("available_units", 0) if stock_doc else 0
            rcpt["steps"].append({
                "step": "QUOTA_INVENTORY_RESERVED",
                "item_key": stock_item,
                "reserved": 1,
                "slots_remaining": stock_after,
                "timestamp": now_str
            })

        # Step 3: Write usage log & credit ledger
        log_id = f"log_{secrets.token_hex(6)}"
        col_usage_log().insert_one({
            "log_id": log_id,
            "user_id": uid,
            "feature": feature_key,
            "credits_cost": cost,
            "target": target_observable or "",
            "status": "EXECUTED",
            "timestamp": now_dt
        }, session=session)

        col_credit_ledger().insert_one({
            "txn_id": receipt_id,
            "user_id": uid,
            "amount": -cost,
            "delta": -cost,
            "balance_after": c_after,
            "action": "FEATURE_CHARGE",
            "reason": f"Feature Charge: {feature_key.upper()}",
            "timestamp": now_dt
        }, session=session)

        # Step 4: Simulated failure check to test automatic refund/rollback
        if simulate_failure:
            raise TransactionError("Simulated external API gateway timeout during execution. Transaction aborted and credits fully refunded!")

        return {
            "feature": feature_key,
            "credits_charged": cost,
            "credits_remaining": c_after,
            "quota_slots_remaining": stock_after,
            "timestamp": now_str
        }

    return run_transaction_with_retry(_txn_body, context)


def reserve_inventory_item_transactional(user_id: Any, item_key: str, credit_cost: int = 100) -> Dict[str, Any]:
    """Reserves an item from stock inventory (Anti-overselling)."""
    return execute_paid_feature_transactional(
        user_id=user_id,
        feature_key=item_key,
        item_key=item_key,
        credit_cost_override=credit_cost
    )
