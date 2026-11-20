# Chapter 16: Three-Database Architecture — MongoDB, Apache Cassandra, and Neo4j

Comprehensive documentation for Chapter 16 of the **ThreatPulse SOC Threat Intelligence Platform**. This chapter implements a high-performance, fault-tolerant, three-database model combining **MongoDB**, **Apache Cassandra**, and **Neo4j** to deliver authoritative transaction storage, high-throughput distributed audit logging, and index-free adjacency graph traversals for fraud investigations.

---

## 1. Architectural Overview & Database Specialization

Modern threat intelligence and fraud prevention platforms face divergent storage requirements that no single database engine can optimally satisfy:

1. **MongoDB (Authoritative Documents & Transactions)**
   - **Role**: Master account profiles, financial balances, KYC state, and polymorphic evidence payloads.
   - **Engine Strengths**: High write velocity, rich document indexing, WiredTiger cache isolation, dynamic schema support for arbitrary forensic evidence.
2. **Apache Cassandra (Distributed Time-Series Audit Logging)**
   - **Role**: Immutable, write-optimized audit trail recording all platform actor events, sign-ins, case mutations, and administrative operations.
   - **Engine Strengths**: Masterless ring topology, zero single point of failure, predictable partition-key queries (`audit_events_by_day` and `audit_events_by_actor`).
3. **Neo4j (Multi-Hop Graph Traversals & Device Sharing Rings)**
   - **Role**: Index-free adjacency relationship graph mapping accounts, hardware devices, and financial transfers.
   - **Engine Strengths**: Constant-time traversal irrespective of graph size, rapid identification of shared-device fraud rings and multi-hop mule networks (up to 3 hops).

---

## 2. Database Models & Schema Specifications

### 2.1 MongoDB: Collections & Schema

MongoDB acts as the single source of truth for accounts, balances, and security evidence:

* **`accounts` Collection**:
  ```json
  {
    "accountId": "ACC-89101",
    "holderName": "Alice Vance",
    "email": "alice.vance@blackmesa.org",
    "balance": 142500.00,
    "currency": "USD",
    "status": "FLAGGED",
    "riskIndicator": "CRITICAL",
    "riskScore": 94,
    "kycStatus": "VERIFIED_TIER_2",
    "registeredDevices": ["DEV-IPHONE-14", "DEV-MACBOOK-PRO-01"],
    "suspicious": true,
    "failedLogins": 5,
    "highValueTransactions": 2,
    "createdAt": "2025-10-14T08:30:00Z"
  }
  ```
* **`evidence` / Polymorphic Risk Signals**:
  ```json
  {
    "evidence": [
      {
        "type": "RISK_SIGNAL",
        "description": "Hardware device shared with multiple high-risk accounts",
        "timestamp": "2025-10-14T08:30:00Z"
      },
      {
        "type": "HIGH_RISK_TRANSACTION",
        "description": "Txn TXN-90214: $94,000.00 to WALLET-CRYPTO-0x981A (BitOffshore-Panama Tumbler)",
        "timestamp": "2026-11-14T18:45:00Z"
      }
    ]
  }
  ```

---

### 2.2 Apache Cassandra: Keyspace & Query-Driven Tables

Cassandra stores audit events optimized for specific read access patterns:

* **Keyspace**: `threatpulse_audit` (SimpleStrategy, replication_factor = 1 for local development, NetworkTopologyStrategy in cluster).
* **Table 1: `audit_events_by_day`** (Time-range partition queries):
  ```sql
  CREATE TABLE threatpulse_audit.audit_events_by_day (
      day text,
      timestamp timestamp,
      event_id text,
      actor text,
      role text,
      action text,
      category text,
      resource text,
      outcome text,
      client_ip text,
      details text,
      PRIMARY KEY ((day), timestamp, event_id)
  ) WITH CLUSTERING ORDER BY (timestamp DESC);
  ```
* **Table 2: `audit_events_by_actor`** (Per-user/actor forensic timeline queries):
  ```sql
  CREATE TABLE threatpulse_audit.audit_events_by_actor (
      actor text,
      timestamp timestamp,
      event_id text,
      role text,
      action text,
      resource text,
      outcome text,
      client_ip text,
      details text,
      PRIMARY KEY ((actor), timestamp, event_id)
  ) WITH CLUSTERING ORDER BY (timestamp DESC);
  ```

---

### 2.3 Neo4j: Nodes, Labels, and Relationships

* **Node Labels**:
  - `(:Account {id: "ACC-89101", holderName: "Alice Vance", riskScore: 94, status: "FLAGGED"})`
  - `(:Device {id: "DEV-IPHONE-14", name: "iPhone 14 Pro", fingerprint: "fp_a91b82c3", risk: "HIGH"})`
* **Relationship Types**:
  - `(:Account)-[:USED_DEVICE {since: "2026-01-10", lastActive: "2026-11-14"}]->(:Device)`
  - `(:Account)-[:TRANSFERRED_TO {amount: 7500.0, timestamp: "2026-11-13"}]->(:Account)`
* **3-Hop Traversal Query (Cypher)**:
  ```cypher
  MATCH path = (a:Account {id: $accountId})-[*1..3]-(connected)
  RETURN path, nodes(path) AS nodes, relationships(path) AS rels;
  ```

---

## 3. Circuit Breaker Design & Fault Tolerance

To ensure that optional database outages (Cassandra or Neo4j) never degrade primary MongoDB operations or stall FastAPI workers, independent circuit breakers monitor external connections:

* **States**:
  - `CLOSED`: Normal operation. Real queries route directly to the database. Failures reset on success.
  - `OPEN`: Tripped after consecutive failure threshold (default: 3 failures). Calls fail fast with immediate fallback. Outbound audit events queue into `_pending_audit_queue` (in-memory deque with 5,000 capacity).
  - `HALF_OPEN`: Transition state after recovery timeout (default: 30s). A single probe query is permitted. If successful, state resets to `CLOSED`; if failing, state trips back to `OPEN`.
* **Graceful Queuing**: When Cassandra is `OPEN` or stopped, mutating audit actions are appended to `_pending_audit_queue`. Upon service resumption, `POST /api/services/lab16/start` flushes queued entries directly into the audit store without dropping events.

---

## 4. Forensic Fraud Review & Dossier Provenance

### 4.1 Forensic Resilience Principle

> **CRITICAL ARCHITECTURAL RULE:**
> Missing data from a skipped, degraded, or offline database is **NEVER** treated as a negative fraud verdict.

If Cassandra or Neo4j are offline or their circuit breakers are `OPEN`, and MongoDB records are clean, the system assigns an **`Inconclusive`** verdict rather than declaring the account clean. This prevents sophisticated attackers from evading detection during service degradation windows.

### 4.2 Tri-Database Forensic Dossier Structure

When evaluating an account target via `GET /api/moderation/fraud/{account_id}`, the response explicitly segregates data and latency provenance:

1. **`mongoEvidence`**: Authoritative balances, suspicious flags, failed login totals, and attached forensic items.
2. **`cassandraTimeline`**: Exact CQL query executed (`SELECT * FROM threatpulse_audit.audit_events_by_actor...`) and chronological action table.
3. **`neo4jGraph`**: Discovered nodes, relationships, and shared devices detected within 3 hops.
4. **`executionTimingsMs`**: Independent millisecond response times measured per database engine (`mongoDbMs`, `cassandraMs`, `neo4jMs`, and `totalMs`).

---

## 5. REST API Reference

| Endpoint | Method | Role Required | Description |
|---|---|---|---|
| `/api/services/lab16` | `GET` | Public / Ops | Health report for MongoDB, Cassandra, Neo4j, circuit breakers, and JVM RAM notice. |
| `/api/services/lab16/start` | `POST` | Admin | Starts optional services, resets circuit breakers to `CLOSED`, flushes pending queue. |
| `/api/services/lab16/stop` | `POST` | Admin | Stops optional services, trips circuit breakers to `OPEN`, queues events safely. |
| `/api/ops/audit` | `GET` | Public / Ops | Time-based Cassandra audit query by `day`, `actor`, `role`, `action`, `outcome`, `limit`. |
| `/api/ops/audit/summary?days=7` | `GET` | Public / Ops | 7-day summary metrics (5 tiles) and daily stacked category breakdown dataset. |
| `/api/moderation/fraud` | `GET` | Moderator / Admin | Account overview list with risk indicators, shared devices count, and related accounts. |
| `/api/moderation/fraud/{account_id}` | `GET` | Moderator / Admin | Tri-database forensic dossier with explicit provenance and query timings. |
| `/api/labs/16/run` | `POST` | Public / Host | Executes automated verification run for Chapter 16. |

---

## 6. Client Interface Navigation

* **Dedicated Chapter 16 Workspace**: `/extras/lab16` (Tabs: *Overview*, *Service Management*, *Audit Log*, *Fraud Review*, *Graph Investigation*)
* **Admin Operations Audit View**: `/admin/ops?tab=audit` (Filter controls, executed CQL display, 5 statistic tiles, 7-day stacked chart, JSON export)
* **Moderation Fraud Review Console**: `/moderation?tab=fraud` (Account overview list, forensic dossier, interactive SVG Neo4j graph with node property inspector)

---

## 7. Verification & Testing

Execute the automated test suite covering all 19 Chapter 16 verifications:

```powershell
# Run Chapter 16 test suite
pytest tests/test_chapter16.py -v

# Run full cross-chapter regression suite (Chapters 14, 15, and 16)
pytest tests/test_chapter14.py tests/test_chapter15.py tests/test_chapter16.py -v
```

