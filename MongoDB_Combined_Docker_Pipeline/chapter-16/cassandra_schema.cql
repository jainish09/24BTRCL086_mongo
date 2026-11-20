-- ============================================================================
-- Chapter 16: Apache Cassandra Distributed Audit Log Schema
-- Keyspace: threatpulse_audit
-- Replication: SimpleStrategy, replication_factor = 1 (Dev) / NetworkTopology (Prod)
-- ============================================================================

CREATE KEYSPACE IF NOT EXISTS threatpulse_audit
WITH replication = {'class': 'SimpleStrategy', 'replication_factor': 1};

USE threatpulse_audit;

-- Query-oriented table partitioned by day and actor
CREATE TABLE IF NOT EXISTS audit_events (
    day text,
    actor text,
    timestamp timestamp,
    event_id uuid,
    action text,
    target_resource text,
    ip_address text,
    status text,
    details text,
    PRIMARY KEY ((day), actor, timestamp, event_id)
) WITH CLUSTERING ORDER BY (actor ASC, timestamp DESC, event_id ASC);

-- Index for searching across actors on a specific day
CREATE INDEX IF NOT EXISTS idx_audit_action ON audit_events (action);

-- Sample query: Retrieve all actions by a specific analyst today
-- SELECT * FROM audit_events WHERE day = '2026-11-15' AND actor = 'analyst_alice';
