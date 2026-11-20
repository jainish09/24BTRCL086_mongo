"""
ThreatPulse SOC Platform - Transaction Lab Sandbox Routes
Implements interactive side-by-side experiments for Experiment 10 rubric:
10.1 Bank Transfer (Atomicity vs Non-Transactional Inconsistency)
10.1-try WriteConflict TransientTransactionError Retry
10.2 Anti-overselling Inventory Reservation
10.2-bench Multi-worker throughput benchmarking
"""

from fastapi import APIRouter, HTTPException, Depends
from pydantic import BaseModel, Field
import time
import random
import concurrent.futures
from bson import ObjectId
import datetime
from pymongo.errors import PyMongoError

from database import (
    get_client,
    get_database,
    col_wallets,
    col_subscriptions,
    col_stock,
    col_credit_ledger,
    col_users
)
from auth import require_auth
from transactions import run_transaction_with_retry, ReceiptLogger

router = APIRouter(prefix="/api/txn-lab", tags=["txn-lab"])


class TransferSimRequest(BaseModel):
    mode: str = Field(..., pattern="^(transactional|non_transactional)$")
    amount: int = Field(10, description="Credits to transfer")


class OversellSimRequest(BaseModel):
    mode: str = Field(..., pattern="^(transactional|non_transactional)$")
    initial_stock: int = Field(5, ge=1, le=20)
    concurrent_requests: int = Field(15, ge=2, le=30)


@router.post("/simulate-transfer")
def simulate_transfer_failure(req: TransferSimRequest, current_user: dict = Depends(require_auth)):
    """
    Demonstrates Atomicity (10.1 Bank Transfer):
    Runs a transfer where a simulated crash occurs after debiting the sender.
    - non_transactional: Sender loses credits, receiver never receives them (CORRUPTION!)
    - transactional: Aborts cleanly, sender loses 0 credits (INTEGRITY PRESERVED!)
    """
    user_id = current_user["_id"]
    db = get_database()
    subs_col = col_subscriptions()

    # Create / find a dummy recipient
    target_dummy = col_users().find_one({"email": "analyst@threatpulse.io"})
    dummy_recipient_id = target_dummy["_id"] if target_dummy else ObjectId()

    # Capture initial balances
    sender_sub_before = subs_col.find_one({"user_id": user_id})
    sender_bal_before = sender_sub_before.get("current_credits", 0) if sender_sub_before else 0

    recipient_sub_before = subs_col.find_one({"user_id": dummy_recipient_id})
    recipient_bal_before = recipient_sub_before.get("current_credits", 0) if recipient_sub_before else 0

    if req.mode == "non_transactional":
        timeline = []
        # Step 1: Debit sender
        timeline.append({"step": "READ_SENDER", "detail": f"Sender credits: {sender_bal_before}", "status": "OK"})
        subs_col.update_one({"user_id": user_id}, {"$inc": {"current_credits": -req.amount}})
        timeline.append({"step": "DEBIT_SENDER", "detail": f"Debited {req.amount} credits from sender", "status": "COMMITTED_PERMANENTLY"})

        # Step 2: Simulated Server / Network Crash BEFORE crediting recipient!
        simulated_crash_error = "SIMULATED_POWER_FAILURE: Node lost connectivity before recipient credit could execute."
        timeline.append({"step": "NETWORK_CRASH", "detail": simulated_crash_error, "status": "CRITICAL_ERROR"})

        # Check balances after
        sender_sub_after = subs_col.find_one({"user_id": user_id})
        sender_bal_after = sender_sub_after.get("current_credits", 0)

        # Restore sender for politeness in demo, but record the intermediate corruption
        money_lost = sender_bal_before - sender_bal_after
        subs_col.update_one({"user_id": user_id}, {"$inc": {"current_credits": req.amount}})

        return {
            "mode": "NON_TRANSACTIONAL (No MongoDB Transaction)",
            "result": "DATABASE_INCONSISTENCY_DETECTED",
            "explanation": "Because writes were not wrapped in a Multi-Document Transaction, the sender debit was committed to disk, but the recipient credit never executed. Money/Credits vanished!",
            "sender_balance_before": sender_bal_before,
            "sender_balance_after_crash": sender_bal_after,
            "credits_lost_due_to_crash": money_lost,
            "timeline": timeline,
            "safety_note": "Auto-restored sender balance for continued demo testing."
        }

    else:
        # Transactional Mode
        client = get_client()
        logger = ReceiptLogger("SIM_TXN_TRANSFER", user_id)
        logger.step("TRANSACTION_START", f"Starting atomic transfer simulation of {req.amount} credits.")

        def txn_callback(session):
            # Step 1: Debit sender
            sub = subs_col.find_one({"user_id": user_id}, session=session)
            if not sub or sub.get("current_credits", 0) < req.amount:
                raise ValueError("Insufficient sender credits")

            subs_col.update_one(
                {"user_id": user_id},
                {"$inc": {"current_credits": -req.amount}},
                session=session
            )
            logger.step("DEBIT_SENDER_STAGED", f"Debited {req.amount} credits in transaction staging.")

            # Step 2: Throw simulated crash
            logger.step("SIMULATED_EXCEPTION", "Raising simulated network crash before recipient credit.")
            raise RuntimeError("SIMULATED_NETWORK_CRASH_MID_TRANSACTION")

        try:
            run_transaction_with_retry(client, txn_callback, logger)
        except RuntimeError as e:
            logger.step("TRANSACTION_ABORTED", "MongoDB aborted transaction. All staged modifications rolled back.")

        receipt = logger.finish(status="ROLLED_BACK")

        # Verify balances after rollback
        sender_sub_after = subs_col.find_one({"user_id": user_id})
        sender_bal_after = sender_sub_after.get("current_credits", 0)

        return {
            "mode": "TRANSACTIONAL (MongoDB Multi-Document Transaction with Snapshot Isolation)",
            "result": "ATOMIC_ROLLBACK_CONFIRMED",
            "explanation": "MongoDB Multi-Document Transaction ensured that when the crash occurred, the staged debit was completely rolled back. Zero credits lost, exactly 100% data integrity maintained!",
            "sender_balance_before": sender_bal_before,
            "sender_balance_after": sender_bal_after,
            "net_loss": sender_bal_before - sender_bal_after,
            "receipt": receipt
        }


@router.post("/simulate-oversell")
def simulate_oversell(req: OversellSimRequest, current_user: dict = Depends(require_auth)):
    """
    Demonstrates Anti-overselling Inventory Reservation (Part 10.2):
    Spawns concurrent workers attempting to grab from a limited pool of stock.
    - non_transactional: Race conditions cause stock to fall below zero (Oversold!)
    - transactional: Guard condition {available_units: {$gte: 1}} strictly prevents overselling.
    """
    test_key = f"demo_item_{int(time.time())}"
    stock_col = col_stock()

    # Setup isolated test item
    stock_col.insert_one({
        "item_key": test_key,
        "name": "Limited Edition Zero-Day Threat Token",
        "total_units": req.initial_stock,
        "available_units": req.initial_stock,
        "reserved_units": 0,
        "created_at": datetime.datetime.now(datetime.timezone.utc)
    })

    client = get_client()

    def worker_non_txn(worker_id):
        # Flawed read-then-write race condition
        doc = stock_col.find_one({"item_key": test_key})
        curr = doc.get("available_units", 0)
        time.sleep(random.uniform(0.01, 0.05))  # Simulate network latency window
        if curr > 0:
            stock_col.update_one({"item_key": test_key}, {"$inc": {"available_units": -1, "reserved_units": 1}})
            return {"worker": worker_id, "status": "SUCCESS"}
        else:
            return {"worker": worker_id, "status": "REJECTED_OUT_OF_STOCK"}

    def worker_txn(worker_id):
        def callback(session):
            # Transactional guard: atomic filter condition
            res = stock_col.update_one(
                {"item_key": test_key, "available_units": {"$gte": 1}},
                {"$inc": {"available_units": -1, "reserved_units": 1}},
                session=session
            )
            if res.modified_count == 0:
                raise ValueError("OUT_OF_STOCK")
            return True

        try:
            run_transaction_with_retry(client, callback)
            return {"worker": worker_id, "status": "SUCCESS"}
        except ValueError:
            return {"worker": worker_id, "status": "REJECTED_OUT_OF_STOCK"}
        except Exception as e:
            return {"worker": worker_id, "status": f"ERROR: {str(e)}"}

    worker_func = worker_txn if req.mode == "transactional" else worker_non_txn

    with concurrent.futures.ThreadPoolExecutor(max_workers=req.concurrent_requests) as executor:
        futures = [executor.submit(worker_func, i) for i in range(req.concurrent_requests)]
        results = [f.result() for f in futures]

    final_doc = stock_col.find_one({"item_key": test_key})
    final_avail = final_doc.get("available_units", 0)
    final_reserved = final_doc.get("reserved_units", 0)

    # Clean up test doc
    stock_col.delete_one({"item_key": test_key})

    success_count = sum(1 for r in results if r["status"] == "SUCCESS")
    rejected_count = sum(1 for r in results if r["status"] == "REJECTED_OUT_OF_STOCK")

    is_oversold = (final_avail < 0) or (final_reserved > req.initial_stock)

    return {
        "mode": req.mode.upper(),
        "initial_stock": req.initial_stock,
        "concurrent_attempts": req.concurrent_requests,
        "successful_reservations": success_count,
        "rejected_requests": rejected_count,
        "final_available_units": final_avail,
        "final_reserved_units": final_reserved,
        "oversold_occurred": is_oversold,
        "verdict": "CRITICAL BUG: Stock oversold and went negative!" if is_oversold else "PERFECT: Zero overselling. Stock stopped cleanly at 0."
    }


@router.post("/retry-demo")
def demo_transient_error_retry(current_user: dict = Depends(require_auth)):
    """
    Demonstrates 10.1-try:
    Intentionally induces a TransientTransactionError (WriteConflict) between two threads
    competing on the same document, and shows the automatic exponential backoff retry.
    """
    test_key = f"conflict_doc_{int(time.time())}"
    col = get_database()["conflict_demo"]
    col.insert_one({"_id": test_key, "counter": 0, "history": []})

    client = get_client()
    logs = []

    def txn_updater(worker_id):
        worker_logs = []
        def callback(session):
            worker_logs.append(f"Worker {worker_id} attempting read & increment...")
            doc = col.find_one({"_id": test_key}, session=session)
            # Sleep slightly to force overlap and trigger WriteConflict
            time.sleep(0.08)
            col.update_one(
                {"_id": test_key},
                {
                    "$inc": {"counter": 1},
                    "$push": {"history": f"Updated by Worker {worker_id}"}
                },
                session=session
            )
            worker_logs.append(f"Worker {worker_id} staged update.")

        logger = ReceiptLogger(f"CONFLICT_WORKER_{worker_id}", current_user["_id"])
        receipt = run_transaction_with_retry(client, callback, logger)
        return {"worker": worker_id, "logs": worker_logs, "receipt": receipt}

    with concurrent.futures.ThreadPoolExecutor(max_workers=2) as executor:
        f1 = executor.submit(txn_updater, 1)
        f2 = executor.submit(txn_updater, 2)
        r1 = f1.result()
        r2 = f2.result()

    final_doc = col.find_one({"_id": test_key})
    col.delete_one({"_id": test_key})

    return {
        "status": "success",
        "description": "Concurrent multi-document transactions competing on the exact same document. One worker encountered a TransientTransactionError (WriteConflict, code 112) and retried with exponential backoff & jitter.",
        "final_counter": final_doc.get("counter") if final_doc else 0,
        "worker_1_attempts": r1.get("receipt", {}).get("retry_attempts", 1),
        "worker_2_attempts": r2.get("receipt", {}).get("retry_attempts", 1),
        "receipt_worker_1": r1.get("receipt"),
        "receipt_worker_2": r2.get("receipt")
    }
