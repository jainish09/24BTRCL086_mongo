# ThreatPulse SOC - Experiment 10: Multi-Document Transactions

A production-grade Cyber Threat Intelligence (CTI) SaaS application running on a 3-node MongoDB replica set (`rs0`). This application converts the platform into an atomic, transactional subscription product where all changes to money, credits, plan tiers, and quota stock are strictly enforced using **MongoDB Multi-Document ACID Transactions**.

---

## Architecture & Replica Set Setup

- **Replica Set Name:** `rs0`
- **Topology:** 3 Nodes (`mongo1:27017`, `mongo2:27017` [PRIMARY], `mongo3:27017`)
- **Isolation Level:** `ReadConcern("snapshot")`, `WriteConcern("majority")`, `ReadPreference.PRIMARY`
- **Application Port:** `http://localhost:8095`
- **Previous Experiment 7 Backup:** Untouched and running on `http://localhost:8080`

---

## 4 Core Experiment 10 Rubrics Implemented

| Rubric Section | Feature & Implementation | Transactional Guarantee |
|---|---|---|
| **10.1 Bank Transfer (Atomicity)** | Subscribing to plans, wallet debit, platform credit, ledger line, payment record, and P2P transfers. | **All-or-Nothing:** If user funds are insufficient or recipient account does not exist, the entire transaction rolls back. Sender loses 0 credits. |
| **10.1-try Retry Logic** | Exponential backoff with jitter on `TransientTransactionError` (WriteConflict, error code 112) and commit retries on `UnknownTransactionCommitResult`. | Automatic retry loop recovers gracefully from contention without dropping user requests. |
| **10.2 Inventory Reservation** | Anti-overselling of limited quota stock (100 daily VirusTotal scan slots) using atomic `{available_units: {$gte: 1}}`. | Race condition prevention: concurrent workers are strictly prevented from overselling; stock cleanly stops at 0 and never goes negative. |
| **10.2-bench Throughput Benchmark** | Interactive multi-worker benchmarking comparing Multi-Document Transactions vs Direct Non-Transactional Writes. | Analyzes latency distribution (p50, p95), ops/sec throughput, and transactional overhead. |

---

## Demo Accounts & Option A Configuration

The system includes pre-seeded demo accounts with a **1-click switcher** directly in the UI header:

| Email | Password | Initial Wallet | Initial Credits | Active Tier | Role |
|---|---|---|---|---|---|
| `free@threatpulse.io` | `Password123!` | **$35.00** | 50 | Community Free | Analyst |
| `analyst@threatpulse.io` | `Password123!` | **$100.00** | 500 | Analyst Plus | Analyst |
| `pro@threatpulse.io` | `Password123!` | **$250.00** | 2,500 | SOC Enterprise | Enterprise |
| `admin@threatpulse.io` | `AdminPassword123!` | **$1,000.00** | 10,000 | SOC Enterprise | SOC Director |

### Subscription Tiers (Option A)
1. **Community (Free):** $0/mo, 50 monthly credits, 15 feed items, preview IOCs, max 5 VT scans/day.
2. **Analyst (Plus):** $29/mo, 500 monthly credits, unrestricted feed, full raw BSON observables, printable invoices.
3. **SOC Enterprise (Pro):** $99/mo, 2,500 monthly credits, priority quota reservation, batch IOC exports, P2P analyst transfers.

### Promotional Coupons
- `CYBER50`: 50% discount on any plan checkout.
- `THREAT20`: $20 instant flat discount.
- `ZERODAY100`: 100% off first month of Analyst tier.

---

## Verification & Evaluation Scripts

### 1. Run Complete Automated Evaluation Suite
From the `ThreatPulse_Exp10/` directory, run:
```bash
python lab_10_evaluation.py
```
**Output Scorecard:**
```
============================================================================
  EVALUATION SCORECARD SUMMARY
============================================================================
  [PASS] Replica Set rs0 Primary Discovery          : Primary: mongo2:27017
  [PASS] 10.1 Atomic Plan Subscription Upgrade      : Exact balance & credit conservation
  [PASS] 10.1 Business Rule Abort & Rollback        : 100% data integrity on abort
  [PASS] 10.1-try Transient WriteConflict Retry     : Exponential backoff & jitter verified
  [PASS] 10.2 Inventory Reservation Anti-Overselling : Zero overselling strictly enforced
  [PASS] 10.2-bench Throughput Multi-Worker Bench   : Tested 1, 2, 4 worker threads
  [PASS] Mathematical Conservation Audit            : All transactional invariants verified. Strict multi-document atomicity confirmed with zero balance leaks.
----------------------------------------------------------------------------
  FINAL SCORE: 7/7 CHECKS PASSED (100.0%)
----------------------------------------------------------------------------
```

### 2. Live Web Dashboard
Visit the web dashboard at:
```
http://localhost:8095/
```

### 3. API Health Check
```bash
curl http://localhost:8095/api/health
```

### 4. Running via Docker Container
```bash
docker-compose up -d --build
```
