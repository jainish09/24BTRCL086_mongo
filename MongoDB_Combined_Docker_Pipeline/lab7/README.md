# MongoDB Lab 7.1 & Lab 7.2 - Cyber Threat Intelligence Platform

Comprehensive full-stack Cyber Threat Intelligence SOC Dashboard & Analysis Suite covering both **Lab 7.1 (Production Schema Analysis)** and **Lab 7.2 (Working Set Analysis)**.

---

## 🎯 Lab Activities Summary

### 🛡️ Lab 7.1: Analyze a Production Schema
- **Domain Source**: [https://ctidigest.com/](https://ctidigest.com/)
- **1. Relationship Categorization**:
  - **Embedded**: Threat Indicators (`data.raw_indicators`, `hashes`), MITRE ATT&CK Tactics (`mitre_tactics`).
  - **Referenced**: Adversary Threat Groups (`organization`), Ingestion Data Feeds (`source`).
- **2. Referencing Rationale & Embedded Alternative**:
  - Explains why embedding was not used for Organizations/Sources (unbounded growth, update duplication across 100,000+ records) and provides the embedded schema alternative.
- **3. Document Size Analysis (`$bsonSize`)**:
  - Uses the MongoDB `$bsonSize` aggregation pipeline (`{"$project": {"size": {"$bsonSize": "$$ROOT"}}}`) to calculate min, max, and average document size (~2.0 KB) and proves documents are safely within the **16 MB limit** (< 0.02% of limit).
- **Activity 7.1 Try It Yourself (Redesign Benchmark)**:
  - Redesigns Threat Source/Organization from referenced to embedded.
  - Interactive live query latency benchmark in the UI.
  - **What queries become faster**: Single-report lookups (no `$lookup` join), single-pass index scans.
  - **What becomes harder**: Bulk metadata updates across 100k records, duplicate cache footprint, complex aggregations across unique sources.

---

### ⚡ Lab 7.2: Working Set Analysis
- **Dataset**: [https://github.com/jacobdjwilson/awesome-annual-security-reports/](https://github.com/jacobdjwilson/awesome-annual-security-reports/)
- **1. 100,000 Documents (~2 KB each)**:
  - Generates ~195.3 MB working set footprint in MongoDB Atlas (`threat_reports` collection).
- **2. WiredTiger Cache Monitor**:
  - Checks maximum configured cache size, current resident cache bytes, and cache hit ratio.
  - Live Chart.js graph polling telemetry every 10 seconds via `GET /api/cache`.
- **3. Random Read Workload Experiment**:
  - Executes random reads across the collection to evaluate cache fit, memory eviction pressure, and hit ratio stability over time.
  - Start & Stop experiment controls with live latency & eviction tracking.
- **4. Newer Report Detection**:
  - Live comparison between external annual security reports dataset and MongoDB records, tagging missing reports with **"Not in Database"**.

---

## 📁 Project Architecture

```
mongodb_lab_7/
├── backend/
│   ├── config.py                 # Environment configuration (Port 8080, Atlas URI)
│   ├── database.py               # PyMongo connection & WiredTiger stats extractor
│   ├── main.py                   # FastAPI application & static server
│   ├── requirements.txt          # Python dependencies
│   ├── .env                      # Live MongoDB Atlas connection string
│   ├── routes/
│   │   ├── lab71.py              # Lab 7.1: $bsonSize analysis & redesign benchmark
│   │   ├── reports.py            # 100k Threat reports (search, filters, pagination)
│   │   ├── cache.py              # WiredTiger cache telemetry (10s auto-refresh)
│   │   ├── working_set.py        # Working set memory footprint calculations
│   │   ├── random_read.py        # Random read workload runner
│   │   ├── new_reports.py        # External annual reports detection
│   │   └── real_reports.py       # Awesome Annual Security Reports collection query
│   └── scripts/
│       ├── seed_working_set.py   # Seeds 100,000 documents (~2 KB each)
│       └── import_real_reports.py # Imports real GitHub annual security reports
│
├── frontend/
│   ├── index.html                # SOC Dashboard with dedicated Lab 7.1 & Lab 7.2 tabs
│   ├── css/
│   │   └── styles.css            # Dark cybersecurity theme & telemetry cards
│   └── js/
│       ├── api.js                # Port auto-discovery (8080/5500) & API abstraction
│       └── app.js                # Controller, Chart.js, $bsonSize metrics, and bench runner
│
└── README.md
```

---

## 🚀 How to Run

1. **Start the FastAPI Backend**:
   ```powershell
   cd "c:\Users\Jainish pachori\mongodb_lab_7\backend"
   pip install -r requirements.txt
   python main.py
   ```

2. **Open the Dashboard in Browser**:
   Navigate to **`http://127.0.0.1:8080`** (or via Live Server at `http://127.0.0.1:5500/frontend/index.html`).

3. **Explore the Tabs**:
   - **Lab 7.1 Schema Analysis**: View `$bsonSize` calculations, Embedding vs Referencing rationale, and run the Redesign Query Benchmark.
   - **Lab 7.2 Working Set**: Inspect the 100,000 documents working set memory footprint.
   - **WiredTiger Cache**: Monitor live cache utilization graph refreshed every 10s.
   - **Random Read Bench**: Run the random access experiment and monitor cache hits vs evictions.
   - **Threat Reports**: Search and filter across 100,000 live records.
   - **Annual Security Reports**: Compare external reports and sync with MongoDB Atlas.
