"""
ThreatPulse SOC Platform - Database Seeder for Exp 10
Seeds initial demo users, wallets, subscriptions, credit ledgers, stock inventory,
promotional coupons, and threat intelligence reports.
"""

import datetime
import logging
from config import DEMO_ACCOUNTS, INITIAL_STOCK, INITIAL_COUPONS, PLATFORM_WALLET_ID
from database import (
    get_database,
    col_users,
    col_wallets,
    col_subscriptions,
    col_credit_ledger,
    col_stock,
    col_coupons,
    col_reports
)
from auth import hash_password

logger = logging.getLogger("threatpulse.seed")
logging.basicConfig(level=logging.INFO)


SAMPLE_THREAT_REPORTS = [
    {
        "report_id": "TR-2026-001",
        "title": "Volt Typhoon Living-off-the-Land Exploitation in Critical Infrastructure",
        "threat_actor": "Volt Typhoon (UNC3236)",
        "severity": "CRITICAL",
        "cvss": 9.8,
        "tlp": "AMBER",
        "summary": "State-sponsored actor targeting critical router firmware using stealthy built-in admin tools (wmic, netsh) avoiding file-based detections.",
        "tags": ["Living-off-the-Land", "Critical Infrastructure", "Router Firmware", "APT"],
        "mitre_attack": ["T1059.001", "T1047", "T1562.001", "T1078"],
        "iocs": [
            {"type": "ip", "value": "194.26.29.112", "threat": "C2 Node"},
            {"type": "domain", "value": "telemetry-sync-cdn.net", "threat": "Exfiltration Endpoint"},
            {"type": "sha256", "value": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", "threat": "Reverse Proxy Loader"}
        ],
        "vt_score": "58/72 Malicious",
        "status": "ACTIVE_INVESTIGATION",
        "published_at": datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(hours=2)
    },
    {
        "report_id": "TR-2026-002",
        "title": "LockBit 4.0 'Green' Ransomware Variant with Kernel Driver BYOVD",
        "threat_actor": "LockBit Syndicate",
        "severity": "CRITICAL",
        "cvss": 9.6,
        "tlp": "RED",
        "summary": "Novel variant utilizing a vulnerable signed Microsoft-compatible anti-cheat kernel driver to blind EDR agents before encrypting VHDX volumes.",
        "tags": ["Ransomware", "BYOVD", "Kernel Exploitation", "EDR Bypass"],
        "mitre_attack": ["T1068", "T1486", "T1562.001"],
        "iocs": [
            {"type": "sha256", "value": "8f4e66299d67169d10be07223b5f9227fb385207c4d52bc5a7fb4c09d3b19011", "threat": "Malicious Kernel Driver"},
            {"type": "ip", "value": "45.154.255.88", "threat": "LockBit Negotiation Portal"}
        ],
        "vt_score": "64/72 Malicious",
        "status": "MITIGATED",
        "published_at": datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(hours=6)
    },
    {
        "report_id": "TR-2026-003",
        "title": "Midnight Blizzard / APT29 OAuth Application Token Theft",
        "threat_actor": "Midnight Blizzard (Nobelium / APT29)",
        "severity": "HIGH",
        "cvss": 8.4,
        "tlp": "AMBER",
        "summary": "Compromised legacy test tenants leveraged to grant high-privilege permissions to illicit OAuth enterprise apps for persistent email exfiltration.",
        "tags": ["OAuth Abuse", "Cloud Security", "APT29", "Email Interception"],
        "mitre_attack": ["T1098.005", "T1114.002", "T1566.002"],
        "iocs": [
            {"type": "domain", "value": "identity-verify-service.com", "threat": "Phishing OAuth Consent"},
            {"type": "ip", "value": "185.220.101.5", "threat": "Residential Proxy Exit"}
        ],
        "vt_score": "42/72 Malicious",
        "status": "CONFIRMED",
        "published_at": datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(hours=14)
    },
    {
        "report_id": "TR-2026-004",
        "title": "Lazarus SubZero Cross-Platform PyPI Supply Chain Poisoning",
        "threat_actor": "Lazarus Group (Hidden Cobra)",
        "severity": "HIGH",
        "cvss": 8.7,
        "tlp": "WHITE",
        "summary": "Trojanized machine learning utility packages distributed on PyPI that load encrypted payloads executing on both Linux containers and Windows workstations.",
        "tags": ["Supply Chain", "PyPI", "DevSecOps", "Lazarus Group"],
        "mitre_attack": ["T1195.001", "T1059.006", "T1140"],
        "iocs": [
            {"type": "domain", "value": "pkg-mirrors-pypi.org", "threat": "Stage 2 Dropper"},
            {"type": "sha256", "value": "3b7c8914b53e7789218209e9921bcffef5689008234abcf29188209511119283", "threat": "Obfuscated PyPI Wheel"}
        ],
        "vt_score": "49/72 Malicious",
        "status": "PUBLIC_DISCLOSURE",
        "published_at": datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(days=1)
    },
    {
        "report_id": "TR-2026-005",
        "title": "BlackCat / ALPHV Sphinx Zero-Day Exploit Against Virtual Appliances",
        "threat_actor": "BlackCat Syndicate",
        "severity": "CRITICAL",
        "cvss": 9.9,
        "tlp": "RED",
        "summary": "Unauthenticated remote code execution targeting enterprise VPN gateways allowing full gateway takeovers within seconds.",
        "tags": ["Zero-Day", "Edge Devices", "Ransomware", "RCE"],
        "mitre_attack": ["T1190", "T1078.001", "T1021.002"],
        "iocs": [
            {"type": "ip", "value": "91.240.118.172", "threat": "Scanner & Exploit Origin"},
            {"type": "domain", "value": "alphv-leak-node99.onion", "threat": "Data Extortion Shard"}
        ],
        "vt_score": "68/72 Malicious",
        "status": "ACTIVE_INVESTIGATION",
        "published_at": datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(days=2)
    },
    {
        "report_id": "TR-2026-006",
        "title": "Sandworm C2 Mesh Operating Through Compromised Edge MikroTik Routers",
        "threat_actor": "Sandworm (TeleBots / Unit 74455)",
        "severity": "HIGH",
        "cvss": 8.1,
        "tlp": "AMBER",
        "summary": "Decentralized mesh tunnel architecture chaining modified RouterOS daemons to mask tactical command instructions to SCADA endpoints.",
        "tags": ["SCADA", "Sandworm", "Mesh C2", "OT Threat"],
        "mitre_attack": ["T1573.002", "T1090.003", "T0885"],
        "iocs": [
            {"type": "ip", "value": "89.44.9.22", "threat": "Mesh Relay Node"},
            {"type": "ip", "value": "193.109.69.18", "threat": "Mesh Relay Node"}
        ],
        "vt_score": "51/72 Malicious",
        "status": "CONFIRMED",
        "published_at": datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(days=3)
    }
]


def seed_database(force: bool = False):
    """
    Populates replica set database with demo accounts, wallets, stock, and threat intelligence.
    """
    db = get_database()
    users_col = col_users()
    wallets_col = col_wallets()
    subs_col = col_subscriptions()
    ledger_col = col_credit_ledger()
    stock_col = col_stock()
    coupons_col = col_coupons()
    reports_col = col_reports()

    logger.info("Starting database seeding for Experiment 10...")

    # 1. Platform Wallet
    wallets_col.update_one(
        {"user_id": PLATFORM_WALLET_ID},
        {
            "$setOnInsert": {
                "user_id": PLATFORM_WALLET_ID,
                "balance": 0.0,
                "currency": "USD",
                "is_platform": True,
                "created_at": datetime.datetime.now(datetime.timezone.utc),
                "updated_at": datetime.datetime.now(datetime.timezone.utc)
            }
        },
        upsert=True
    )
    logger.info("Platform Revenue Wallet initialized.")

    # 2. Demo User Accounts
    for account in DEMO_ACCOUNTS:
        email = account["email"]
        existing = users_col.find_one({"email": email})
        if existing and not force:
            logger.info(f"Account {email} already exists. Skipping.")
            continue

        salt, p_hash = hash_password(account["password"])
        now = datetime.datetime.now(datetime.timezone.utc)

        user_doc = {
            "email": email,
            "name": account["name"],
            "password_hash": p_hash,
            "salt": salt,
            "plan": account["plan"],
            "credits": int(account["initial_credits"]),
            "role": account["role"],
            "created_at": now,
            "updated_at": now
        }

        user_res = users_col.update_one(
            {"email": email},
            {"$set": user_doc},
            upsert=True
        )
        user_id = existing["_id"] if existing else (user_res.upserted_id or users_col.find_one({"email": email})["_id"])

        # Wallet document
        wallets_col.update_one(
            {"user_id": user_id},
            {
                "$set": {
                    "user_id": user_id,
                    "balance": float(account["initial_wallet"]),
                    "currency": "USD",
                    "updated_at": now
                },
                "$setOnInsert": {
                    "created_at": now
                }
            },
            upsert=True
        )

        # Subscription document
        subs_col.update_one(
            {"user_id": user_id},
            {
                "$set": {
                    "user_id": user_id,
                    "plan": account["plan"],
                    "status": "active",
                    "current_credits": int(account["initial_credits"]),
                    "started_at": now,
                    "renews_at": now + datetime.timedelta(days=30),
                    "updated_at": now
                }
            },
            upsert=True
        )

        # Initial Credit Ledger Entry
        ledger_col.insert_one({
            "user_id": user_id,
            "txn_id": f"GENESIS-{user_id}",
            "amount": int(account["initial_credits"]),
            "balance_after": int(account["initial_credits"]),
            "action": "PLAN_CREDIT_GRANT",
            "description": f"Initial credits for {account['plan'].upper()} plan tier",
            "timestamp": now
        })

        logger.info(f"Seeded user: {email} (Wallet: ${account['initial_wallet']:.2f}, Credits: {account['initial_credits']})")

    # 3. Stock Inventory (Part 10.2 Anti-overselling)
    now = datetime.datetime.now(datetime.timezone.utc)
    for key, initial_qty in INITIAL_STOCK.items():
        name = "VirusTotal API Daily Scan Slots" if key == "vt_quota" else "Executive Zero-Day Briefing Seats"
        cost = 5 if key == "vt_quota" else 100
        stock_col.update_one(
            {"item_key": key},
            {
                "$set": {
                    "item_key": key,
                    "name": name,
                    "total_units": initial_qty,
                    "unit_credit_cost": cost,
                    "updated_at": now
                },
                "$setOnInsert": {
                    "available_units": initial_qty,
                    "reserved_units": 0,
                    "created_at": now
                }
            },
            upsert=True
        )
        logger.info(f"Initialized Stock Item: {key} ({initial_qty} units)")

    # 4. Coupons
    for code, coupon in INITIAL_COUPONS.items():
        coupons_col.update_one(
            {"code": code},
            {
                "$set": {
                    "code": code,
                    "discount_type": coupon["type"],
                    "discount_value": coupon["value"],
                    "max_uses": coupon["max_uses"],
                    "description": coupon["description"],
                    "is_active": True,
                    "updated_at": now
                },
                "$setOnInsert": {
                    "used_count": 0,
                    "created_at": now
                }
            },
            upsert=True
        )
        logger.info(f"Initialized Coupon: {code}")

    # 5. Threat Reports (CTI Feed)
    if reports_col.count_documents({}) == 0 or force:
        for r in SAMPLE_THREAT_REPORTS:
            reports_col.update_one(
                {"report_id": r["report_id"]},
                {"$set": r},
                upsert=True
            )
        logger.info(f"Seeded {len(SAMPLE_THREAT_REPORTS)} Threat Intelligence reports.")

    logger.info("ThreatPulse Experiment 10 Database Seeding Completed Successfully.")


if __name__ == "__main__":
    seed_database(force=True)
