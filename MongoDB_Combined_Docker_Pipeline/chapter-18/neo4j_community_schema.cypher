// ============================================================================
// Chapter 18: Neo4j Threat Community & Shared Infrastructure Graph Schema
// Detects bridging hubs (Cloudflare Anycast, Google DNS) that trigger false alarms
// ============================================================================

// 1. Constraints & Unique Indexes
CREATE CONSTRAINT unique_threat_val IF NOT EXISTS FOR (t:Threat) REQUIRE t.value IS UNIQUE;
CREATE CONSTRAINT unique_family_name IF NOT EXISTS FOR (f:Family) REQUIRE f.name IS UNIQUE;
CREATE CONSTRAINT unique_source_id IF NOT EXISTS FOR (s:Source) REQUIRE s.id IS UNIQUE;

// 2. Node Schema
// (:Threat { value: "1.1.1.1", type: "IP", severity: "LOW", isFalsePositive: true })
// (:Family { name: "Public-DNS-Infrastructure", category: "PUBLIC_DNS_RESOLVER" })
// (:Source { id: "FEED-SHADOWNET-SENSOR", reliabilityScore: 0.72 })

// 3. Relationships
// (:Threat)-[:ATTRIBUTED_TO { confidence: 0.95 }]->(:Family)
// (:Threat)-[:REPORTED_BY { timestamp: "2026-11-15T12:00:00Z" }]->(:Source)
// (:Threat)-[:SHARED_INDICATOR { weight: 4 }]->(:Threat)
// (:Source)-[:SUSPICIOUS { disputeRate: 0.42 }]->(:Source)

// 4. Community Detection Query for Shared Infrastructure Hubs
MATCH (f:Family)<-[:ATTRIBUTED_TO]-(t:Threat)-[:SHARED_INDICATOR]-(t2:Threat)-[:ATTRIBUTED_TO]->(f2:Family)
WHERE f <> f2
RETURN f.name AS family_a, f2.name AS family_b, count(DISTINCT t) AS shared_indicators
ORDER BY shared_indicators DESC;
