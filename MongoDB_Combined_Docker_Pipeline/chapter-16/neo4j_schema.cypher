// ============================================================================
// Chapter 16: Neo4j Graph Database Schema & Fraud Investigation Queries
// Model: Accounts, Shared Devices, and Transaction Graph
// ============================================================================

// 1. Constraints & Unique Indexes
CREATE CONSTRAINT unique_account_id IF NOT EXISTS FOR (a:Account) REQUIRE a.id IS UNIQUE;
CREATE CONSTRAINT unique_device_fingerprint IF NOT EXISTS FOR (d:Device) REQUIRE d.fingerprint IS UNIQUE;
CREATE CONSTRAINT unique_threat_indicator IF NOT EXISTS FOR (t:Threat) REQUIRE t.value IS UNIQUE;

// 2. Sample Relationship Topology
// (:Account)-[:LOGGED_IN_FROM { lastSeen: datetime() }]->(:Device)
// (:Account)-[:SENT_TRANSFER { amount: 4500.00, timestamp: datetime() }]->(:Account)
// (:Device)-[:ASSOCIATED_WITH]->(:Threat)

// 3. Multi-Hop Investigation Query: Find accounts sharing a compromised device
MATCH (target:Account { id: "ACC-FRAUD-001" })-[:LOGGED_IN_FROM]->(d:Device)<-[:LOGGED_IN_FROM]-(linked:Account)
WHERE target <> linked
RETURN target.id AS source_account, d.fingerprint AS shared_device, linked.id AS connected_account;

// 4. Multi-Hop Money Flow Traversal (Up to 3 Hops)
MATCH path = (origin:Account { id: "ACC-FRAUD-001" })-[:SENT_TRANSFER*1..3]->(destination:Account)
RETURN path;
