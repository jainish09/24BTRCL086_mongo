"""
ThreatPulse SOC Platform - Comprehensive Automated Test Suite
Verifies all 4 parts of Experiment 10 directly against the database and transaction engine.
"""

import sys
import os
import datetime

# Ensure backend directory is in python path
sys.path.insert(0, os.path.dirname(__file__))

from database import (
    get_client,
    get_database,
    col_users,
    col_wallets,
    col_subscriptions,
    col_stock,
    col_receipts,
    col_credit_transfers
)
from transactions import (
    subscribe_to_plan_transactional,
    peer_to_peer_transfer_transactional,
    execute_paid_feature_transactional,
    top_up_wallet_transactional,
    InsufficientFundsError,
    InsufficientCreditsError,
    AccountNotFoundError
)
from config import PLATFORM_WALLET_ID


def run_tests():
    print("=" * 70)
    print("THREATPULSE EXP 10: AUTOMATED TRANSACTION INTEGRITY TEST SUITE")
    print("=" * 70)

    # 1. Connection & Replica Set Test
    print("\n[TEST 1] Testing MongoDB Replica Set Connection...")
    client = get_client()
    hello = client.admin.command("hello")
    is_primary = hello.get("isWritablePrimary", False) or hello.get("ismaster", False)
    assert is_primary, "Error: Must be connected to a writable primary!"
    print(f"  [PASS] Connected to Primary Node: {hello.get('primary', 'local')}")

    # 2. Lookup Alex Vance (Free Tier Demo User)
    user_free = col_users().find_one({"email": "free@threatpulse.io"})
    assert user_free is not None, "Free demo user must exist"
    user_id = user_free["_id"]

    # Ensure wallet has at least $35 for upgrade test
    col_wallets().update_one({"user_id": user_id}, {"$set": {"balance": 35.0}})
    col_subscriptions().update_one({"user_id": user_id}, {"$set": {"plan": "free", "current_credits": 50}})
    print("  [PASS] Free demo user initialized with $35.00 wallet & 50 credits.")

    # 3. Test 10.1 Bank Transfer / Multi-Document Subscription Upgrade
    print("\n[TEST 2] Testing Atomic Plan Subscription Upgrade ($29.00 to Analyst)...")
    platform_before = col_wallets().find_one({"user_id": PLATFORM_WALLET_ID}).get("balance", 0.0)

    receipt = subscribe_to_plan_transactional(
        user_id=user_id,
        target_plan_id="plus",
        coupon_code=None
    )

    assert receipt["status"] == "COMMITTED", "Transaction must commit"
    assert receipt["target_plan"] == "plus"
    print(f"  [PASS] Subscription transaction COMMITTED. Receipt ID: {receipt['receipt_id']}")

    # Verify wallet balances after
    user_wallet_after = col_wallets().find_one({"user_id": user_id}).get("balance", 0.0)
    platform_after = col_wallets().find_one({"user_id": PLATFORM_WALLET_ID}).get("balance", 0.0)
    user_sub_after = col_subscriptions().find_one({"user_id": user_id})

    assert round(user_wallet_after, 2) == 6.00, f"Expected $6.00 remaining, got {user_wallet_after}"
    assert round(platform_after - platform_before, 2) == 29.00, f"Platform should have gained $29, got {platform_after - platform_before}"
    assert user_sub_after["current_credits"] == 550, f"Expected 50 + 500 = 550 credits, got {user_sub_after['current_credits']}"
    print(f"  [PASS] Balance Invariants Verified: User Wallet = ${user_wallet_after:.2f}, Platform Revenue = +$29.00, Credits = {user_sub_after['current_credits']}.")

    # 4. Test Insufficient Funds Rollback
    print("\n[TEST 3] Testing Insufficient Funds Rollback (Attempt $99 Pro with only $6)...")
    rollback_caught = False
    try:
        subscribe_to_plan_transactional(user_id=user_id, target_plan_id="pro")
    except InsufficientFundsError as e:
        rollback_caught = True
        print(f"  [PASS] Caught expected InsufficientFundsError: {e}")

    assert rollback_caught, "Must raise InsufficientFundsError"
    # Verify user wallet still has exact $6.00 (Zero loss)
    user_wallet_check = col_wallets().find_one({"user_id": user_id}).get("balance", 0.0)
    assert round(user_wallet_check, 2) == 6.00, "Wallet balance must remain unchanged after abort!"
    print("  [PASS] Transaction Atomicity Proven: User wallet remained exactly $6.00 after rollback.")

    # 5. Test P2P Credit Transfer
    print("\n[TEST 4] Testing Peer-to-Peer Credit Transfer (50 credits to analyst@threatpulse.io)...")
    analyst_sub_before = col_subscriptions().find_one({"user_id": col_users().find_one({"email": "analyst@threatpulse.io"})["_id"]})
    analyst_credits_before = analyst_sub_before["current_credits"]

    p2p_receipt = peer_to_peer_transfer_transactional(
        sender_user_id=user_id,
        recipient_email="analyst@threatpulse.io",
        amount=50,
        memo="Collab incident triage"
    )
    assert p2p_receipt["status"] == "COMMITTED"

    sender_credits_now = col_subscriptions().find_one({"user_id": user_id})["current_credits"]
    analyst_credits_now = col_subscriptions().find_one({"user_id": col_users().find_one({"email": "analyst@threatpulse.io"})["_id"]})["current_credits"]

    assert sender_credits_now == 500, f"Expected 550 - 50 = 500, got {sender_credits_now}"
    assert analyst_credits_now == analyst_credits_before + 50, f"Expected {analyst_credits_before + 50}, got {analyst_credits_now}"
    print(f"  [PASS] P2P Transfer Complete. Sender = {sender_credits_now} cr, Recipient = {analyst_credits_now} cr.")

    # 6. Test P2P Transfer Rollback on Unknown Recipient
    print("\n[TEST 5] Testing P2P Rollback on Unknown Recipient (fake_ghost@unknown.org)...")
    p2p_rollback_caught = False
    try:
        peer_to_peer_transfer_transactional(
            sender_user_id=user_id,
            recipient_email="fake_ghost@unknown.org",
            amount=50
        )
    except AccountNotFoundError as e:
        p2p_rollback_caught = True
        print(f"  [PASS] Caught expected AccountNotFoundError: {e}")

    assert p2p_rollback_caught, "Must raise AccountNotFoundError"
    # Sender credits must still be 500!
    sender_credits_verify = col_subscriptions().find_one({"user_id": user_id})["current_credits"]
    assert sender_credits_verify == 500, "Sender credits must NOT be deducted if receiver is unknown!"
    print("  [PASS] P2P Rollback Proven: Sender credits untouched at 500.")

    # 7. Test Paid Feature with Inventory Reservation (Part 10.2 Anti-overselling)
    print("\n[TEST 6] Testing Paid Feature with Stock Reservation (VirusTotal Scan: 5 cr + 1 quota slot)...")
    stock_before = col_stock().find_one({"item_key": "vt_quota"})["available_units"]

    vt_receipt = execute_paid_feature_transactional(
        user_id=user_id,
        feature_key="vt_scan",
        item_key="vt_quota",
        target_observable="194.26.29.112"
    )
    assert vt_receipt["status"] == "COMMITTED"

    stock_after = col_stock().find_one({"item_key": "vt_quota"})["available_units"]
    user_credits_after_vt = col_subscriptions().find_one({"user_id": user_id})["current_credits"]

    assert stock_after == stock_before - 1, f"Expected stock {stock_before - 1}, got {stock_after}"
    assert user_credits_after_vt == 495, f"Expected 500 - 5 = 495, got {user_credits_after_vt}"
    print(f"  [PASS] Stock Decremented from {stock_before} -> {stock_after}. User credits: {user_credits_after_vt}.")

    # 8. Test Mathematical Conservation Audit
    print("\n[TEST 7] Testing Mathematical Conservation Audit...")
    from routes.admin import perform_accounting_audit
    audit_res = perform_accounting_audit(current_user={"role": "admin"})
    assert audit_res["status"] == "PASS", f"Audit failed: {audit_res}"
    print(f"  [PASS] Accounting Audit Passed: {audit_res['verdict']}")

    print("\n" + "=" * 70)
    print("ALL 7 TEST SUITES PASSED WITH 100% SUCCESS!")
    print("=" * 70)


if __name__ == "__main__":
    run_tests()
