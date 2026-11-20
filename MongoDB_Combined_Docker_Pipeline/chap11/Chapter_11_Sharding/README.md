# Chapter 11: MongoDB Sharding (Labs 11.1 & 11.2)

This directory implements **Chapter 11** of the MongoDB practical curriculum as a standalone, modular, independently runnable experiment.

---

## Architecture Overview

```
                      +-----------------------------+
                      |       Client / Runner       |
                      |   (Host or Docker Runner)   |
                      +--------------+--------------+
                                     |
                                     v
                      +-----------------------------+
                      |        mongos Router        |
                      |    (Port 27027 / 27017)     |
                      +-------+--------------+------+
                              |              |
           +------------------+              +------------------+
           |                                                    |
           v                                                    v
+-----------------------+                            +-----------------------+
|    Shard 1 Replica    |                            |    Shard 2 Replica    |
|   (chapter11-shard1)  |                            |   (chapter11-shard2)  |
|      (Port 27022)     |                            |      (Port 27023)     |
+-----------------------+                            +-----------------------+
           ^                                                    ^
           |         +--------------------------------+         |
           +---------+      Config Server (CSRS)      +---------+
                     |       (chapter11-cfg1)         |
                     |         (Port 27021)           |
                     +--------------------------------+
```

- **Config Server (`cfg1`):** `mongo:7.0`, replica set `rs-config`, host port `27021`.
- **Shard 1 (`shard1`):** `mongo:7.0`, replica set `rs-shard1`, host port `27022`.
- **Shard 2 (`shard2`):** `mongo:7.0`, replica set `rs-shard2`, host port `27023`.
- **Query Router (`mongos`):** `mongo:7.0`, host port `27027`.
- **Network:** Isolated bridge network `chapter11-sharding-net`.
- **Zero Conflict:** Runs completely independently of Chapters 7–10 without port or volume overlap.

---

## File Structure

```
Chapter_11_Sharding/
├── docker-compose.yml           # Complete sharded cluster stack
├── init_sharding.py             # Cluster & shard key initialization script
├── load_data.py                 # Ingestion of 10,000 docs per collection
├── analyze_distribution.py      # Storage, chunk & explain query analysis
├── run_lab11.py                 # Master automated Python pipeline
├── run_lab11.bat                # 1-click Windows execution batch script
├── cleanup.bat                  # Safe cleanup script (preserves other chapters)
├── Dockerfile                   # Docker packaging for submission / lab runner
├── REPORT.md                    # Lab report with decision matrix & actual results
└── README.md                    # Execution guide & Docker Hub instructions
```

---

## How to Run Chapter 11

### Option A: 1-Click Execution (Windows CMD / PowerShell)
Double-click `run_lab11.bat` or run:
```cmd
cd Chapter_11_Sharding
run_lab11.bat
```

### Option B: Step-by-Step Manual Execution

1. **Start the Sharded Cluster Containers:**
   ```cmd
   cd Chapter_11_Sharding
   docker compose up -d cfg1 shard1 shard2 mongos
   ```

2. **Initialize Cluster & Shard Collections:**
   ```cmd
   python init_sharding.py
   ```

3. **Ingest 10,000 Documents Per Collection:**
   ```cmd
   python load_data.py
   ```

4. **Analyze Distribution & Query Targeting:**
   ```cmd
   python analyze_distribution.py
   ```

### Option C: Fully Containerized Execution (No Python on Host)
```cmd
cd Chapter_11_Sharding
docker compose up -d cfg1 shard1 shard2 mongos
docker compose run --rm app
```

---

## Verified Actual Results

- **`hotspot_data` (`{ ts: 1 }`):**
  - Shard 1: **10,000 docs (100.0%)** | 2,799,500 bytes
  - Shard 2: **0 docs (0.0%)** | 0 bytes
  - *Observation:* Monotonically increasing timestamps created an absolute write hotspot.
- **`even_data` (`{ user_id: "hashed" }`):**
  - Shard 1: **4,943 docs (49.4%)** | 1,318,396 bytes
  - Shard 2: **5,057 docs (50.6%)** | 1,349,038 bytes
  - *Observation:* MD5 hashed keys distributed documents evenly across both shards.
- **Query Targeting:**
  - Range Query on `{ ts: 1 }` -> **Single-Shard Targeted** (1 shard contacted, stage `FETCH`).
  - Range Query on `{ user_id: "hashed" }` -> **Scatter-Gather** (2 shards contacted, stage `SHARDING_FILTER`).
  - Point Query on `{ user_id: "hashed" }` -> **Single-Shard Targeted** (1 shard contacted).

---

## Safe Cleanup Instructions

To stop and remove Chapter 11 containers while **completely preserving Chapters 7–10**:

Run:
```cmd
cd Chapter_11_Sharding
cleanup.bat
```
Or manually:
```cmd
docker compose down
```
> **Safety Note:** `docker compose down` inside `Chapter_11_Sharding` only removes Chapter 11 containers (`chapter11-cfg1`, `chapter11-shard1`, `chapter11-shard2`, `chapter11-mongos`) and does **not** touch `combined-mongo1`, `combined-mongo2`, or any other experiment volumes.

---

## Docker Hub Submission Preparation

To prepare Chapter 11 as a submission image on Docker Hub:

1. **Build the Chapter 11 Image:**
   ```cmd
   docker build -t <your-dockerhub-username>/mongodb-sharding-lab11:v1.0 .
   ```

2. **Tag as Latest:**
   ```cmd
   docker tag <your-dockerhub-username>/mongodb-sharding-lab11:v1.0 <your-dockerhub-username>/mongodb-sharding-lab11:latest
   ```

3. **Verify Locally:**
   ```cmd
   docker run --rm <your-dockerhub-username>/mongodb-sharding-lab11:latest python3 run_lab11.py --help
   ```

4. **Push to Docker Hub (Only with Explicit Approval):**
   ```cmd
   docker login
   docker push <your-dockerhub-username>/mongodb-sharding-lab11:latest
   ```
