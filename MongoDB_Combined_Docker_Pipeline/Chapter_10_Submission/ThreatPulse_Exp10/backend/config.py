import os
from dotenv import load_dotenv

load_dotenv()

# MongoDB 3-Node Replica Set rs0 Connection URI
MONGODB_URI = os.getenv(
    "MONGODB_URI",
    "mongodb://127.0.0.1:27020,127.0.0.1:27018,127.0.0.1:27019/?replicaSet=rs0"
)

DB_NAME = os.getenv("DB_NAME", "threatpulse_exp10_db")
HOST = os.getenv("HOST", "0.0.0.0")
PORT = int(os.getenv("PORT", 8095))
SECRET_KEY = os.getenv("SECRET_KEY", "threatpulse-super-secret-production-key-2026")

# Subscription Plans Definition (Option A)
PLANS = {
    "free": {
        "id": "free",
        "name": "Community",
        "badge": "Community Free",
        "price": 0.0,
        "monthly_credits": 50,
        "description": "Standard threat intelligence feed, basic taxonomy, and educational lab telemetry.",
        "features": [
            "Up to 50 Monthly Feature Credits",
            "Public Threat Feed (Capped 15 / page)",
            "OSINT Sources Directory",
            "Academic Lab Notebook (Chapters 7-12)",
            "Community Support"
        ],
        "limits": {
            "max_feed_preview": 15,
            "max_ioc_preview": 10,
            "raw_bson_access": False,
            "max_vt_scans_daily": 5
        }
    },
    "plus": {
        "id": "plus",
        "name": "Analyst",
        "badge": "Analyst Plus",
        "price": 29.0,
        "monthly_credits": 500,
        "description": "Dedicated cyber threat analyst toolkit with VirusTotal API multi-engine inspection.",
        "features": [
            "500 Monthly Feature Credits",
            "Unrestricted Threat Intelligence Feed",
            "VirusTotal Live Multi-Engine Scans (5 cr/scan)",
            "Threat Verifier Instant Truth (3 cr/check)",
            "Full IOC Observable Search & View",
            "Receipts & Printable Invoices"
        ],
        "limits": {
            "max_feed_preview": 100,
            "max_ioc_preview": 100,
            "raw_bson_access": True,
            "max_vt_scans_daily": 50
        }
    },
    "pro": {
        "id": "pro",
        "name": "SOC Enterprise",
        "badge": "SOC Enterprise Pro",
        "price": 99.0,
        "monthly_credits": 2500,
        "description": "Enterprise-grade SOC command center with priority API quota, batch exports, and P2P transfers.",
        "features": [
            "2,500 Monthly Feature Credits",
            "Priority VirusTotal Premium Quota Slots",
            "Automated Threat Verifier API Access",
            "Deep IOC Stream Batch CSV / JSON Exports",
            "Peer-to-Peer Analyst Credit Transfers",
            "Full Audited Accounting Receipts & Reports"
        ],
        "limits": {
            "max_feed_preview": 500,
            "max_ioc_preview": 500,
            "raw_bson_access": True,
            "max_vt_scans_daily": 200
        }
    }
}

# Paid Feature Costs in Credits
FEATURE_CREDIT_COSTS = {
    "vt_scan": 5,          # VirusTotal Multi-Engine Live API Scan
    "verifier": 3,         # Threat Verifier (Instant Truth Engine)
    "ioc_export": 2,       # Deep IOC Stream Batch Export
    "benchmark": 10        # On-Demand Cache & Sharding Stress Benchmark
}

# Limited Inventory Stock Settings (Part 10.2)
INITIAL_STOCK = {
    "vt_quota": 100,       # 100 Daily Premium VirusTotal API scan slots
    "briefing_seats": 25   # 25 Seats for Zero-Day Emergency SOC Flash Briefing
}

# Initial Coupons (Atomic inventory with limited redemptions)
INITIAL_COUPONS = {
    "CYBER50": {
        "code": "CYBER50",
        "type": "percentage",
        "value": 50.0,
        "max_uses": 20,
        "used_count": 0,
        "description": "50% off any plan subscription upgrade"
    },
    "THREAT20": {
        "code": "THREAT20",
        "type": "flat",
        "value": 20.0,
        "max_uses": 10,
        "used_count": 0,
        "description": "$20 Instant Wallet Credit Deposit"
    },
    "ZERODAY100": {
        "code": "ZERODAY100",
        "type": "percentage",
        "value": 100.0,
        "max_uses": 5,
        "used_count": 0,
        "description": "100% off first month of Analyst tier"
    }
}

# Demo Accounts Configuration (Option A)
DEMO_ACCOUNTS = [
    {
        "email": "free@threatpulse.io",
        "password": "Password123!",
        "name": "Alex Vance",
        "plan": "free",
        "role": "user",
        "initial_wallet": 35.0,     # Enough wallet money to test live upgrading to Analyst ($29)!
        "initial_credits": 50
    },
    {
        "email": "analyst@threatpulse.io",
        "password": "Password123!",
        "name": "Elena Rostova",
        "plan": "plus",
        "role": "user",
        "initial_wallet": 100.0,
        "initial_credits": 500
    },
    {
        "email": "pro@threatpulse.io",
        "password": "Password123!",
        "name": "Marcus Sterling",
        "plan": "pro",
        "role": "user",
        "initial_wallet": 250.0,
        "initial_credits": 2500
    },
    {
        "email": "admin@threatpulse.io",
        "password": "AdminPassword123!",
        "name": "Chief SOC Director",
        "plan": "pro",
        "role": "admin",
        "initial_wallet": 1000.0,
        "initial_credits": 10000
    }
]

# System Platform Account ID (Where revenue deposits go)
PLATFORM_WALLET_ID = "SYSTEM_PLATFORM_ACCOUNT"
