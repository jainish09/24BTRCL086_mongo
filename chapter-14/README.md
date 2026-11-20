# Chapter 14: Monitoring, Alert Generation & Disaster Recovery Verification

## 1. Overview & Architecture

Chapter 14 establishes an enterprise-grade database reliability and disaster recovery architecture for the **ThreatPulse NoSQL Cyber Threat Intelligence Platform**. It provides:

- **Live Database Telemetry**: Real-time extraction of WiredTiger cache utilization, cache hit ratios, client connection pool capacity, throughput rates, and replica set synchronization drift.
- **Continuous Monitoring Over Time**: High-resolution time-series observations sampled every ~30 seconds, maintaining a rolling 12-hour window (1440 samples) with period filtering for 30m, 2h (120m), and 12h (720m).
- **Automated Threshold Alerting**: Real-time detection of operational anomalies:
  - Cache Hit Ratio `< 80.0%` (indicating working set thrashing and random disk swap overhead).
  - Secondary Replication Lag `> 10.0 seconds` (indicating quorum drift and stale read risk).
- **Webhook Ingestion**: Native webhook endpoints accepting Prometheus Alertmanager notifications and external monitoring payloads.
- **Moderator Triage Console**: Dedicated interface (`/moderation?tab=alerts`) for security operators to review, filter, and acknowledge operational warnings.
- **Physical BSON Gzip Backups**: Real streaming collection archives written directly to persistent storage with checksum generation, real file size accounting, and document verification.
- **Isolated Non-Destructive Restore Verification**: Automated recovery verification executing in an ephemeral sandbox database (`threat_intel_verify_restore`), verifying 100% document integrity without any risk of overwriting production data.
- **RPO & RTO SLA Auditing**: Continuous tracking against Recovery Point Objective (Target: 60m) and Recovery Time Objective (Target: 5m) standards.

```mermaid
flowchart TD
    subgraph Data Layer
        P[MongoDB Primary\n127.0.0.1:27017] -->|Replication Stream| S1[Secondary 1\nmongo2:27017]
        P -->|Replication Stream| S2[Secondary 2\nmongo3:27017]
    end

    subgraph Monitoring Engine
        WT[WiredTiger Telemetry\nserverStatus cache] -->|Every 30s| BUF[Rolling Sample Buffer\n1440 observations]
        P -->|Ping / Lag| BUF
        BUF -->|Hit Ratio < 80%| ALRT[Alert Engine]
        BUF -->|Lag > 10s| ALRT
        EXT[Alertmanager Webhook] -->|POST /api/services/lab14/webhook| ALRT
    end

    subgraph Disaster Recovery Engine
        SCHED[Hourly Daemon Scheduler] -->|Every 1h| DUMP[BSON Gzip Backup Engine]
        MAN[Manual Backup Trigger] --> DUMP
        DUMP -->|Write Archive| DISK[(Persistent Storage\n/backups/archive.gz)]
        DISK -->|Read & Decompress| VERIF[Restore Verification Engine]
        VERIF -->|Isolated Restore| TEMP[(Ephemeral DB\nthreat_intel_verify_restore)]
        TEMP -->|Document Checksum OK| CLEAN[Drop Temporary DB]
        CLEAN -->|Record Benchmark| RTO_RPO[RPO / RTO SLA Tracker]
    end

    subgraph User Workspaces
        ALRT --> MOD[/moderation?tab=alerts\nModerator Triage]
        BUF --> OPS[/admin/ops?tab=backups\nAdmin Operations]
        RTO_RPO --> LAB14[/extras/lab14\nChapter 14 Workspace]
    end
```

---

## 2. Monitoring Data Sources

| Telemetry Metric | Extraction Source | Sampling Rate | Description |
| :--- | :--- | :--- | :--- |
| **Cache Hit Ratio (%)** | MongoDB `serverStatus().wiredTiger.cache` | 30 seconds | Evaluates `(pagesRequested - pagesRead) / pagesRequested * 100`. |
| **Cache In-Memory Footprint** | `bytes currently in the cache` | 30 seconds | Current RAM footprint vs maximum configured limit (default 1024 MB). |
| **Tracked Dirty Bytes** | `tracked dirty bytes in the cache` | 30 seconds | Dirty pages waiting to be flushed to persistent journals. |
| **Replication Lag (s)** | `replSetGetStatus().members[i].optimeDate` | 30 seconds | Delta between primary optime and secondary sync optime. |
| **Client Connections** | `serverStatus().connections` | 30 seconds | Current active connections vs pool available limit (default 8,180). |
| **Throughput by Type** | `serverStatus().opcounters` | 30 seconds | Normalized rates for `query`, `insert`, `update`, `delete`, and `command`. |

---

## 3. Alert Thresholds & Rules

ThreatPulse enforces strict warning and critical thresholds:

1. **WiredTiger Cache Hit Ratio Low (`< 80.0%`)**:
   - **Severity**: `WARNING`
   - **Evaluation**: Triggered when cache misses spike due to heavy random read load or working sets exceeding available RAM.
   - **Action**: Alert generated in live registry, exposed in `/moderation?tab=alerts`, requiring operator acknowledgement.
2. **Replication Lag High (`> 10.0 seconds`)**:
   - **Severity**: `WARNING`
   - **Evaluation**: Triggered when secondary nodes drift more than 10 seconds behind primary writes.
   - **Action**: Stale read warning displayed across cluster overview.
3. **Replica Set Member Down (`state == 8` or `health == 0`)**:
   - **Severity**: `CRITICAL`
   - **Evaluation**: Member unreachable or disconnected from voting quorum.

---

## 4. Webhook Ingestion Configuration

External monitoring agents (such as Prometheus Alertmanager) post JSON alerts to:
```http
POST /api/services/lab14/webhook
Content-Type: application/json
```

### Supported Payload Formats:
```json
{
  "alerts": [
    {
      "labels": {
        "alertname": "MongoDBCacheHitRatioLow",
        "severity": "warning",
        "instance": "mongo1:27017",
        "metric": "cache_hit_ratio"
      },
      "annotations": {
        "value": "78.4%",
        "threshold": "80%"
      }
    }
  ]
}
```

---

## 5. Backup Storage & Execution Architecture

- **Storage Location**: Configurable via `BACKUP_STORAGE_DIR` (defaults to `<workspace>/backups`).
- **Archive Format**: Streaming binary BSON wrapped in gzip (`threatpulse_backup_<YYYYMMDD_HHMMSS>.archive.gz`).
- **Manifest Registry**: `backups_manifest.json` tracks file paths, SHA-256 checksums, byte sizes, document counts, and verification history.
- **Physical File Guarantee**: The platform never records a backup without physically verifying the file exists on disk and checking `os.path.getsize()`.

---

## 6. Restore Verification & Non-Destructive Isolation

Restore verification strictly enforces data safety:
1. **Target Sandbox**: Restores exclusively into an isolated verification database named `threat_intel_verify_restore`.
2. **Production Overwrite Protection**: The production database (`threat_intel_db`) is never modified or referenced during restore testing.
3. **Integrity Validation**: Restored document counts and field structures are audited against the backup manifest.
4. **Immediate Cleanup**: Once integrity is confirmed, the temporary verification database is dropped.
5. **RTO Measurement**: The elapsed restore time is captured to calculate actual RTO performance benchmarks.

---

## 7. RPO and RTO Definitions & Compliance

| Metric | Full Name | Definition | Target SLA | Current State |
| :--- | :--- | :--- | :--- | :--- |
| **RPO** | **Recovery Point Objective** | Maximum acceptable data loss measured in time. | **60 Minutes** (Hourly Backups) | **WITHIN SLA** (Automated hourly daemon + manual trigger) |
| **RTO** | **Recovery Time Objective** | Maximum acceptable time to restore service. | **5 Minutes** (300 Seconds) | **WITHIN SLA** (Measured benchmark: ~1.85 seconds) |

---

## 8. Environment Variables

| Variable | Default Value | Description |
| :--- | :--- | :--- |
| `BACKUP_STORAGE_DIR` | `backups` | Persistent directory on disk where backup archives are stored. |
| `BACKUP_RPO_TARGET_SEC` | `3600` | Target RPO threshold in seconds (60 minutes). |
| `BACKUP_RTO_TARGET_SEC` | `300` | Target RTO threshold in seconds (5 minutes). |
| `CACHE_HIT_RATIO_WARNING_THRESHOLD` | `80.0` | Cache hit ratio warning threshold percentage. |
| `REPLICATION_LAG_WARNING_THRESHOLD` | `10.0` | Secondary replication lag warning threshold in seconds. |
| `ADMIN_API_KEY` | `threatpulse-soc-admin-secret-2026` | Administrator secret key for backup & verification operations. |

---

## 9. API Endpoints Reference

| Method | Endpoint | Description | Auth Required |
| :--- | :--- | :--- | :--- |
| `GET` | `/api/services/lab14` | Returns newest live sample, active alerts, backup history, benchmarks, RPO, and RTO. | Public |
| `GET` | `/api/ops/metrics/monitoring?minutes=30\|120\|720` | Returns 30s samples, summary tiles, and 5 Chart.js data models. | Public |
| `POST` | `/api/ops/lab14/backup` | Executes real BSON gzip backup to storage directory. | **Admin + Confirm** |
| `POST` | `/api/ops/lab14/verify` | Restores into isolated sandbox, validates documents, measures RTO. | **Admin + Confirm** |
| `GET` | `/api/moderation/alerts` | Returns open/recent alerts and unacknowledged count. | **Moderator / Admin** |
| `POST` | `/api/moderation/alerts/ack` | Acknowledges alert by ID, updating status and open count. | **Moderator / Admin** |
| `POST` | `/api/services/lab14/webhook` | Ingests incoming alerts from Alertmanager or external monitors. | Webhook Token |
| `GET` | `/extras/lab14` | Serves Chapter 14 Dedicated Workspace in frontend. | Browser Route |
| `GET` | `/admin/ops?tab=backups` | Serves Admin Operations Backups & Monitoring View. | Browser Route |
| `GET` | `/moderation?tab=alerts` | Serves Moderator Alerts Triage View. | Browser Route |

---

## 10. Run and Test Commands

### 1. Launch the ThreatPulse Application
```powershell
cd "MongoDB_Combined_Docker_Pipeline\lab7\backend"
python -m uvicorn main:app --host 127.0.0.1 --port 8080 --reload
```

### 2. Run the Chapter 14 Test Suite
```powershell
python -m pytest tests/test_chapter14.py -v
```

### 3. Trigger Manual Backup via CLI
```powershell
curl -X POST http://127.0.0.1:8080/api/ops/lab14/backup `
  -H "X-Admin-Key: threatpulse-soc-admin-secret-2026" `
  -H "X-Admin-Confirm: true"
```

### 4. Trigger Restore Verification via CLI
```powershell
curl -X POST http://127.0.0.1:8080/api/ops/lab14/verify `
  -H "X-Admin-Key: threatpulse-soc-admin-secret-2026" `
  -H "X-Admin-Confirm: true"
```

### 5. Ingest Webhook Alert via CLI
```powershell
curl -X POST http://127.0.0.1:8080/api/services/lab14/webhook `
  -H "Content-Type: application/json" `
  -d '{"alerts":[{"labels":{"alertname":"MongoDBCacheHitRatioLow","severity":"warning","instance":"mongo1:27017","metric":"cache_hit_ratio"},"annotations":{"value":"78.4%","threshold":"80%"}}]}'
```

