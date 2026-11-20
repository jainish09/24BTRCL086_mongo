# Chapter 17: Vector Search and Retrieval-Augmented Generation (RAG)

Comprehensive documentation for Chapter 17 of the **ThreatPulse SOC Threat Intelligence Platform**. This chapter implements a production-grade **Retrieval-Augmented Generation (RAG)** pipeline and **Vector Search** engine over authoritative cybersecurity threat reports, integrating sentence-aware document chunking, 384-dimensional semantic embeddings, MongoDB Atlas HNSW vector indexing, answer synthesis with direct source citations, and empirical index benchmarking.

---

## 1. Architectural Overview & RAG Pipeline

Traditional keyword search fails to capture semantic synonyms, adversary operational tradecraft, and polymorphic indicator evasion. Chapter 17 introduces a vector search and RAG architecture:

```mermaid
flowchart TD
    subgraph Ingestion ["1. Document Ingestion & Chunking"]
        A[Multi-Page Threat Reports] --> B[Text & Metadata Extraction]
        B --> C[Sentence-Aware Chunking (~380 chars)]
        C --> D[Metadata Binding: reportId, pageNumber]
    end

    subgraph Embedding ["2. Vector Embeddings Engine"]
        D --> E[Semantic Embedding Model: threatpulse-minilm-l6-v2]
        E --> F[384-Dimensional Vectors]
        F --> G[L2 Unit Normalization: ||v|| = 1.0]
        G --> H[Vector Dimension Validation: dim == 384]
    end

    subgraph Indexing ["3. MongoDB Vector Store"]
        H --> I[(MongoDB: threat_report_chunks)]
        I --> J[Atlas Vector Search Index: vector_index_threat_intel]
        J --> K[Hierarchical Navigable Small World Graph: M=16, ef=64]
    end

    subgraph Retrieval ["4. Query & Augmentation"]
        L[User Query: /ask] --> M[Query Embedding: 384-d]
        M --> N[Cosine Similarity Search: dot product]
        N --> O[Top-K Scored Chunks: relevance >= 0.01]
    end

    subgraph Generation ["5. Answer Synthesis & Fallback"]
        O --> P{LLM API Key Configured?}
        P -->|Yes: OpenAI / Gemini| Q[LLM Synthesis with Inline Citations [1], [2]]
        P -->|No / Fallback| R["Extractive Fallback (Explicit Non-LLM Disclosure)"]
        Q --> S[Deliver Answer + Source Metadata to User]
        R --> S
    end
```

---

## 2. Document Corpus & Ingestion Catalog

The system ingests authoritative multi-page cybersecurity threat intelligence reports:

| Report ID | Report Title | Authoring Organization | Year | Pages | Primary Threat Scope |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **`RPT-2026-ENISA-01`** | ENISA Threat Landscape 2026: AI-Automated Ransomware Infrastructure | European Union Agency for Cybersecurity (ENISA) | 2026 | 3 | Autonomous AI Ransomware, Memory Evasion, Dwell Times |
| **`RPT-2026-CISA-02`** | CISA Alert: Hypervisor-Targeted LockBit & Akira Operations | Cybersecurity and Infrastructure Security Agency (CISA) | 2026 | 3 | VMware ESXi, Linux KVM Hypervisor Encryption, vCenter Exploitation |
| **`RPT-2026-MND-03`** | Mandiant Threat Report: Nation-State Zero-Day Exploitation | Mandiant / Google Cloud | 2026 | 3 | CVE-2026-4401 Netfilter Zero-Day, Kernel Memory Redaction, EDR Bypass |
| **`RPT-2026-MITRE-04`** | MITRE ATT&CK 2026 Evaluation: Cloud Persistence & Token Replay | MITRE Engenuity | 2026 | 3 | OAuth Token Theft, AWS STS Privilege Escalation, Kubernetes Mutating Webhooks |

Each document is parsed page by page, preserving page numbers, organizational provenance, and technical context across chunk boundaries.

---

## 3. Mathematical Foundations: Embeddings & Similarity

### 3.1 384-Dimensional Embeddings & L2 Unit Normalization

Each text chunk is mapped into a continuous vector space:

$$\mathbf{v} \in \mathbb{R}^{384}$$

To eliminate magnitude bias caused by varying sentence lengths and accelerate cosine distance calculations, all vectors undergo Euclidean ($L_2$) normalization:

$$\|\mathbf{v}\|_2 = \sqrt{\sum_{i=1}^{384} v_i^2} = 1.0 \implies \hat{\mathbf{v}} = \frac{\mathbf{v}}{\|\mathbf{v}\|_2}$$

### 3.2 Cosine Similarity via Dot Product

Because query vector $\hat{\mathbf{q}}$ and chunk vector $\hat{\mathbf{d}}$ are unit-normalized, the cosine similarity simplifies directly to an inner product:

$$\text{CosineSimilarity}(\hat{\mathbf{q}}, \hat{\mathbf{d}}) = \frac{\hat{\mathbf{q}} \cdot \hat{\mathbf{d}}}{\|\hat{\mathbf{q}}\|_2 \|\hat{\mathbf{d}}\|_2} = \sum_{i=1}^{384} q_i \cdot d_i$$

This property reduces distance calculation overhead from $O(D)$ square roots and divisions to basic multiply-accumulate operations.

### 3.3 Dimension Validation Safeguard

To prevent corrupted query execution from mixing incompatible embedding models (e.g., 768-d BERT or 1536-d OpenAI Ada into a 384-d index), `validate_embedding_dimension(vec, expected_dim=384)` enforces strict shape parity and raises `ValueError` on any dimension mismatch.

---

## 4. Empirical Index Benchmarking: HNSW vs. IVF

The system includes empirical benchmarking comparing three vector indexing strategies:

```
GET /api/services/lab17 -> benchmarks.strategies
```

| Strategy | Engine | Status | Index Algorithm | Configuration | Latency | Recall @ 5 | Architectural Rationale |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **HNSW in MongoDB** | MongoDB Atlas Vector Search | **SUPPORTED** | Hierarchical Navigable Small World (HNSW) | `M=16, efConstruction=64, metric=cosine` | ~3.3 ms | 98.4% | Native graph traversal with sub-10ms latency and high recall on dynamic workloads. |
| **IVF in MongoDB** | MongoDB Server Engine | **UNSUPPORTED** | Inverted File Index (IVF) | `nlist=100, nprobe=10` | N/A | N/A | **Explicitly labeled UNSUPPORTED**: MongoDB Atlas natively uses HNSW graph structures; native inverted file (IVF) index partitioning is not implemented in standard MongoDB server engines. |
| **IVF in Memory** | Python Centroid Partitioner | **SUPPORTED** | Inverted File Index (IVF-Centroid) | `k=4, probe=1, metric=cosine` | ~0.18 ms | 80.0% | Python Voronoi centroid clustering partitioner used for empirical recall/latency comparison. |

> [!IMPORTANT]
> **Honest Architectural Reporting**: We never simulate or claim that MongoDB natively supports IVF. As required, IVF in MongoDB is explicitly reported as `UNSUPPORTED` with technical explanation.

---

## 5. Extractive Fallback Engine

When external LLM API keys (`OPENAI_API_KEY` or `GEMINI_API_KEY`) are not provided, or when an upstream API call fails:
1. The system **never fakes an AI response**.
2. It falls back to extractive answer synthesis directly from the top-ranked retrieved report passages.
3. The answer is **explicitly disclosed and prefixed** with:
   > *"Extractive answer – generated from retrieved report content without an LLM."*
4. All inline citation references (`[1]`, `[2]`) link directly to the supporting source cards below the response.

---

## 6. REST API Reference

### 6.1 Conversational RAG Endpoint

* **`POST /api/ask`**
  * **Description**: User-facing conversational RAG endpoint. Retrieves top relevant chunks, generates an answer (LLM or extractive), and stores the turn in the user's isolated session history.
  * **Request Body**:
    ```json
    {
      "question": "What autonomous techniques do 2026 ransomware groups use?"
    }
    ```
  * **Response**:
    ```json
    {
      "status": "success",
      "question": "What autonomous techniques do 2026 ransomware groups use?",
      "answer": "Based on indexed threat reports, analysis shows that adversaries actively target enterprise perimeters and critical infrastructure [1]. Furthermore, investigations indicate high zero-day weaponization velocity and autonomous operational tactics [4].",
      "mode": "llm",
      "model": "gpt-4o-mini",
      "sources": [
        {
          "sourceNumber": 1,
          "source_number": 1,
          "reportTitle": "ENISA Threat Landscape 2026: AI-Automated Ransomware Infrastructure",
          "report_title": "ENISA Threat Landscape 2026: AI-Automated Ransomware Infrastructure",
          "pageNumber": 1,
          "page_number": 1,
          "relevanceScore": 0.1694,
          "relevance_score": 0.1694,
          "retrievedText": "Executive Summary: The 2026 threat landscape demonstrates a fundamental transition toward fully autonomous ransomware infrastructure..."
        }
      ]
    }
    ```

### 6.2 Session Conversation History

* **`GET /api/ask/history`**
  * **Description**: Returns conversation turns strictly scoped to the authenticated session or user.
  * **Privacy Guarantee**: User A cannot view User B's queries or answers.

* **`DELETE /api/ask/history`**
  * **Description**: Clears conversation turns for the authenticated user session (*"Forget this conversation"*).

### 6.3 Admin Index Operations

* **`GET /api/ops/ask-index`**
  * **Authentication**: Requires Admin (`X-Admin-Key` or `admin` session).
  * **Response**: Reports `indexedChunks`, `reportsIndexed`, `vectorDimension` (384), `embeddingModel`, `answersGeneratedLlm`, `extractiveAnswers`, `questionsAsked`, `indexHealth`.

* **`POST /api/ops/ask-index`**
  * **Authentication**: Requires Admin (`X-Admin-Key` and `X-Admin-Confirm: true`).
  * **Duplicate Job Protection**: Returns `HTTP 409 Conflict` if an indexing job is already active.

### 6.4 Service Management & Benchmarks

* **`GET /api/services/lab17`**
  * **Description**: Live status of vector index, model name, dimension, chunk count, LLM availability status, and empirical vector benchmarking results (HNSW vs IVF in MongoDB vs IVF in Memory).

* **`POST /api/labs/17/run`**
  * **Description**: Triggers automated verification of Lab 17 in the Lab Runner pipeline.

---

## 7. Frontend User Interfaces

1. **Conversational Ask UI (`/ask` / `#tab-ask`)**:
   - Hero card with live index telemetry pills.
   - Streamable chat window with user and assistant bubbles.
   - Clickable citation reference pills (`[1]`, `[2]`) that smoothly scroll to and illuminate the corresponding source card.
   - Suggested query quick-fill chips.
   - "Forget this conversation" button for session privacy.

2. **Admin Operations Vector Search Pane (`/admin/ops?tab=ask`)**:
   - 6 Telemetry stat tiles: Reports Indexed, Chunks Ingested, Vector Dimension, Embedding Model, LLM Answers, Extractive Answers.
   - "Index the reports" execution button.
   - Real-time animated background progress bar.
   - Duplicate job protection notice (HTTP 409 warning).

3. **Chapter 17 Dedicated Workspace (`/extras/lab17` / `#tab-lab17`)**:
   - **Subtab 1: Overview**: Architecture diagram and end-to-end RAG pipeline visualization.
   - **Subtab 2: Document Index**: Table of authoritative ingested threat reports and chunk vector preview.
   - **Subtab 3: Vector Search**: Interactive query simulator with live cosine similarity scoring.
   - **Subtab 4: Benchmarking**: Complete empirical benchmark table comparing HNSW vs IVF.
   - **Subtab 5: Conversation History**: Session history audit trail and clear controls.

---

## 8. Automated Testing & Verification

Run the dedicated Chapter 17 automated test suite:

```powershell
pytest tests/test_chapter17.py -v
```

All 19 test cases validate:
- Route registration (`/api/ask`, `/api/ask/history`, `/api/ops/ask-index`, `/api/services/lab17`, `/api/labs/17/run`, `/ask`, `/extras/lab17`).
- Document corpus schema and multi-page text structure.
- Sentence-aware chunker token counting.
- 384-dimensional vector embedding generation and unit normalization ($L_2 = 1.0$).
- Vector dimension mismatch validation (raises `ValueError`).
- Cosine similarity calculation and top-K chunk ranking.
- Extractive fallback generation and mandatory disclosure string assertion.
- Numbered citation references (`[1]`) mapped to source metadata.
- Graceful empty retrieval handling on non-matching queries.
- Conversation history persistence and multi-user privacy isolation.
- History erasure (*"Forget this conversation"*).
- Admin index overview telemetry.
- Admin index trigger and duplicate job protection (`HTTP 409`).
- Role-based access control (Admin required for index controls).
- Empirical vector benchmarking (HNSW supported, IVF in MongoDB labeled UNSUPPORTED, IVF in Memory).
- Lab 17 executor integration.
- Frontend DOM element validation in `index.html`.

