-- ============================================================================
-- Chapter 18: Apache Cassandra Wide-Column CTI Query-Oriented Tables
-- Keyspace: threat_intel
-- ============================================================================

CREATE KEYSPACE IF NOT EXISTS threat_intel
WITH replication = {'class': 'SimpleStrategy', 'replication_factor': 1};

USE threat_intel;

-- 1. Query historical threats by source feed ordered chronologically
CREATE TABLE IF NOT EXISTS threats_by_source (
    source text,
    timestamp timestamp,
    threat_id text,
    value text,
    threat_type text,
    severity text,
    confidence float,
    PRIMARY KEY ((source), timestamp, threat_id)
) WITH CLUSTERING ORDER BY (timestamp DESC);

-- 2. Query threat spread and sightings by indicator value
CREATE TABLE IF NOT EXISTS threats_by_value (
    value text,
    source text,
    timestamp timestamp,
    threat_id text,
    threat_type text,
    severity text,
    PRIMARY KEY ((value), source, timestamp)
) WITH CLUSTERING ORDER BY (source ASC, timestamp DESC);

-- 3. Pre-aggregated daily source volume analytics
CREATE TABLE IF NOT EXISTS volume_by_day (
    day text,
    source text,
    count counter,
    critical counter,
    high counter,
    PRIMARY KEY ((day), source)
);
