# ThreatPulse SOC Platform & Threat Advisor (Tri-DB & RAG)
> **Comprehensive Enterprise Cyber Threat Intelligence, Tri-DB Orchestration, Hybrid RAG & Sentinel Endpoint Security Platform.**

[![Docker Image](https://img.shields.io/badge/DockerHub-jainishhhh%2Fmongodb__final%3Alatest-blue?logo=docker)](https://hub.docker.com/r/jainishhhh/mongodb_final)
[![Python Version](https://img.shields.io/badge/python-3.11-blue.svg)](https://www.python.org/)
[![Database](https://img.shields.io/badge/MongoDB-Atlas%20%26%207.0-green.svg)](https://www.mongodb.com/)
[![Kubernetes](https://img.shields.io/badge/Kubernetes-Docker%20Desktop-326CE5.svg)](https://kubernetes.io/)

---

## 🌟 Overview & Architectural Scope

**ThreatPulse SOC** is an enterprise-grade Cyber Threat Intelligence (CTI) operations platform engineered across **Labs 7 through 18**, featuring real-time WiredTiger cache monitoring, multi-database consensus, vector semantic search, and an AI-powered **Threat Advisor** with deterministic endpoint vulnerability scanning.

---

## 🏗️ Chapter & Lab Implementations (Labs 7 - 18)

| Module / Lab | Core Technologies | Description |
| :--- | :--- | :--- |
| **Lab 7.1** | MongoDB Aggregation, `$bsonSize` | Schema analysis, embedded vs referenced BSON payload sizing |
| **Lab 7.2** | WiredTiger Cache, Working Set | Cache hit ratios, dirty byte tracking, memory thrashing mitigation |
| **Lab 8** | MongoDB Replica Set (`rs0`) | 3-node primary-secondary replica set with automated failover |
| **Lab 9** | Write Concern (`w:1`, `w:majority`, `j:true`) | Latency benchmarking and simulated network partition recovery |
| **Lab 10** | ACID Multi-Document Transactions | Two-phase bank transfers and atomic inventory reservation |
| **Lab 11** | Horizontal Sharding & Routers | Range/Hash shard keys, mongos routing, chunk balancing |
| **Lab 12** | Database Security (TLS & RBAC) | Encrypted transport, role-based access control, field redaction |
| **Lab 13** | Cloud & Containers | Multi-container Docker Compose, Kubernetes StatefulSet, Prometheus |
| **Lab 14** | Reliability & Disaster Recovery | Continuous rolling telemetry, automated alerting, RPO/RTO verification |
| **Lab 15** | SaaS Multi-Tenant Architecture | Isolated document partitioning, tenant isolation, cross-tenant leak prevention |
| **Lab 16** | Tri-DB Heterogeneous Integration | MongoDB (Transactions) + Cassandra (Time-Series) + Neo4j (Graph) |
| **Lab 17** | Vector Search & Hybrid RAG | 384-d normalized embeddings, semantic retrieval, Grok LLM integration |
| **Lab 18** | Comparative Database Capstone | 2-of-3 Tri-DB consensus voting for automated False-Positive detection |
| **Threat Advisor** | LLM Streaming & Sentinel Scanner | Grounded CTI chat, CISA KEV lifecycle, and deterministic PC scanner |

---

## 🚀 Quick Start Guide

### 1. Run Locally (Windows)
```cmd
start_dashboard.bat
```
The dashboard will open automatically at **http://localhost:8080**.

### 2. Run via Docker
Pull and run the pre-built image from Docker Hub:
```bash
docker pull jainishhhh/mongodb_final:latest
docker run -d -p 8080:8080 --name threatpulse-soc jainishhhh/mongodb_final:latest
```
Access at **http://localhost:8080**.

### 3. Deploy to Kubernetes
```powershell
kubectl apply -f k8s/
kubectl rollout status deployment/threatpulse-soc-app -n threatpulse
```
Access via LoadBalancer at **http://localhost:8080** or NodePort at **http://localhost:30080**.

---

## 🛡️ Sentinel PC Scanner Agent
Threat Advisor features a zero-dependency Python scanner that safely audits host OS build, installed applications, and Defender/Firewall security posture:
```powershell
powershell -ExecutionPolicy Bypass -Command "irm http://localhost:8080/install.ps1 | iex"
```

---

## 👥 Authors & Repository
- **Repository**: `24BTRCL086_mongo`
- **Owner**: `jainish09`
- **DockerHub**: `jainishhhh/mongodb_final`
