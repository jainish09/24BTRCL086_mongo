#!/usr/bin/env python3
"""
Chapter 11: Distribution & Query Plan Analysis Script (Lab 11.2)
Author: Senior MongoDB Engineer
Description:
  1. Inspects chunk distribution from config.collections & config.chunks.
  2. Queries both physical shard nodes directly for ground-truth document counts and storage size.
  3. Executes $collStats aggregation across the cluster.
  4. Runs range queries on both collections using explain("executionStats").
  5. Demonstrates single-shard targeting vs scatter-gather broadcast.
  6. Exports structured findings to distribution_summary.json.
"""

import os
import sys
import json
import argparse
from datetime import datetime, timezone, timedelta
from pymongo import MongoClient

def get_endpoints(container_mode=False):
    if container_mode:
        return {
            "mongos": "mongodb://mongos:27017/",
            "shard1": "mongodb://shard1:27017/?directConnection=true",
            "shard2": "mongodb://shard2:27017/?directConnection=true"
        }
    else:
        return {
            "mongos": "mongodb://127.0.0.1:27027/",
            "shard1": "mongodb://127.0.0.1:27022/?directConnection=true",
            "shard2": "mongodb://127.0.0.1:27023/?directConnection=true"
        }

def inspect_chunks_v7(mongos_client, namespace):
    """
    Retrieves chunk count and distribution across shards for MongoDB 7.0.
    In MongoDB 7.0, config.collections maps namespace to uuid,
    and config.chunks stores chunks keyed by collection uuid.
    """
    config_db = mongos_client["config"]
    coll_meta = config_db["collections"].find_one({"_id": namespace})
    shard_counts = {}
    chunk_list = []

    if coll_meta and "uuid" in coll_meta:
        c_uuid = coll_meta["uuid"]
        chunks = list(config_db["chunks"].find({"uuid": c_uuid}))
        chunk_list = chunks
        for c in chunks:
            s_id = c.get("shard", "unknown")
            shard_counts[s_id] = shard_counts.get(s_id, 0) + 1
    else:
        # Fallback for earlier MongoDB conventions
        chunks = list(config_db["chunks"].find({"ns": namespace}))
        chunk_list = chunks
        for c in chunks:
            s_id = c.get("shard", "unknown")
            shard_counts[s_id] = shard_counts.get(s_id, 0) + 1

    return len(chunk_list), shard_counts

def get_direct_shard_metrics(shard_client, db_name, coll_name):
    """Queries physical mongod shard node directly for exact ground-truth metrics."""
    try:
        db = shard_client[db_name]
        if coll_name not in db.list_collection_names():
            return {"count": 0, "size": 0, "storageSize": 0, "indexes": 0}
        
        count = db[coll_name].count_documents({})
        stats = db.command("collStats", coll_name)
        return {
            "count": count,
            "size": stats.get("size", 0),
            "storageSize": stats.get("storageSize", 0),
            "totalIndexSize": stats.get("totalIndexSize", 0),
            "avgObjSize": stats.get("avgObjSize", 0)
        }
    except Exception as e:
        return {"error": str(e), "count": 0}

def get_collstats_agg(mongos_client, db_name, coll_name):
    """Runs $collStats aggregation via mongos with storageStats."""
    db = mongos_client[db_name]
    try:
        pipeline = [{"$collStats": {"storageStats": {}}}]
        results = list(db[coll_name].aggregate(pipeline))
        per_shard = {}
        for r in results:
            shard_name = r.get("shard", "unknown")
            storage_stats = r.get("storageStats", {})
            per_shard[shard_name] = {
                "count": storage_stats.get("count", 0),
                "size": storage_stats.get("size", 0),
                "storageSize": storage_stats.get("storageSize", 0)
            }
        return per_shard
    except Exception as e:
        return {"aggregation_error": str(e)}

def explain_range_query(mongos_client, db_name, coll_name, filter_spec, query_label):
    db = mongos_client[db_name]
    cmd = {
        "explain": {
            "find": coll_name,
            "filter": filter_spec
        },
        "verbosity": "executionStats"
    }
    explain_res = db.command(cmd)

    exec_stats = explain_res.get("executionStats", {})
    shards_visited = []
    total_docs_examined = 0
    total_n_returned = 0
    execution_time_ms = exec_stats.get("executionTimeMillis", 0)

    shards_dict = exec_stats.get("executionStages", {}).get("shards", [])
    if not shards_dict and "shards" in explain_res:
        for s_name, s_data in explain_res.get("shards", {}).items():
            s_exec = s_data.get("executionStats", {})
            shards_visited.append({
                "shardName": s_name,
                "nReturned": s_exec.get("nReturned", 0),
                "docsExamined": s_exec.get("totalDocsExamined", 0),
                "keysExamined": s_exec.get("totalKeysExamined", 0),
                "stage": s_exec.get("executionStages", {}).get("stage", "UNKNOWN"),
                "timeMillis": s_exec.get("executionTimeMillis", 0)
            })
            total_n_returned += s_exec.get("nReturned", 0)
            total_docs_examined += s_exec.get("totalDocsExamined", 0)
    elif shards_dict:
        for s in shards_dict:
            shards_visited.append({
                "shardName": s.get("shardName", "unknown"),
                "nReturned": s.get("executionStages", {}).get("nReturned", 0),
                "docsExamined": s.get("executionStages", {}).get("totalDocsExamined", 0),
                "keysExamined": s.get("executionStages", {}).get("totalKeysExamined", 0),
                "stage": s.get("executionStages", {}).get("stage", "UNKNOWN"),
                "timeMillis": s.get("executionStages", {}).get("executionTimeMillis", 0)
            })
            total_n_returned += s.get("executionStages", {}).get("nReturned", 0)
            total_docs_examined += s.get("executionStages", {}).get("totalDocsExamined", 0)
    else:
        shards_visited.append({
            "shardName": "consolidated",
            "nReturned": exec_stats.get("nReturned", 0),
            "docsExamined": exec_stats.get("totalDocsExamined", 0),
            "keysExamined": exec_stats.get("totalKeysExamined", 0),
            "stage": exec_stats.get("executionStages", {}).get("stage", "UNKNOWN")
        })
        total_n_returned = exec_stats.get("nReturned", 0)
        total_docs_examined = exec_stats.get("totalDocsExamined", 0)

    active_shards_contacted = len(shards_visited)
    targeting_type = "Single-Shard Targeted" if active_shards_contacted == 1 else "Scatter-Gather (All Shards)"

    return {
        "query_label": query_label,
        "filter": str(filter_spec),
        "targeting_type": targeting_type,
        "shards_contacted_count": active_shards_contacted,
        "total_n_returned": total_n_returned,
        "total_docs_examined": total_docs_examined,
        "execution_time_ms": execution_time_ms,
        "shards_detail": shards_visited
    }

def main():
    parser = argparse.ArgumentParser(description="Analyze sharded distribution and query plans")
    parser.add_argument("--container", action="store_true", help="Run with internal Docker hostnames")
    args = parser.parse_args()

    is_container = args.container or os.environ.get("RUNNING_IN_CONTAINER") == "1"
    ep = get_endpoints(container_mode=is_container)

    print("=" * 75)
    print("CHAPTER 11: DISTRIBUTION & QUERY PLAN ANALYSIS (LAB 11.2)")
    print("=" * 75)

    mongos_client = MongoClient(ep["mongos"])
    shard1_client = MongoClient(ep["shard1"])
    shard2_client = MongoClient(ep["shard2"])

    db_name = "exp11_db"
    summary_report = {
        "analysis_timestamp": datetime.now(timezone.utc).isoformat(),
        "database": db_name,
        "collections": {}
    }

    # 1. Analyze hotspot_data
    print("\n[PART 1] Evaluating 'hotspot_data' (Shard Key: { ts: 1 })")
    print("-" * 75)
    ns_hotspot = f"{db_name}.hotspot_data"
    total_chunks_h, chunks_by_shard_h = inspect_chunks_v7(mongos_client, ns_hotspot)
    s1_metrics_h = get_direct_shard_metrics(shard1_client, db_name, "hotspot_data")
    s2_metrics_h = get_direct_shard_metrics(shard2_client, db_name, "hotspot_data")
    collstats_h = get_collstats_agg(mongos_client, db_name, "hotspot_data")

    total_h = s1_metrics_h["count"] + s2_metrics_h["count"]
    s1_pct_h = (s1_metrics_h["count"] / total_h * 100) if total_h > 0 else 0
    s2_pct_h = (s2_metrics_h["count"] / total_h * 100) if total_h > 0 else 0

    print(f"Total Documents: {total_h:,}")
    print(f"  * Shard 1 (rs-shard1): {s1_metrics_h['count']:,} docs ({s1_pct_h:.1f}%) | "
          f"Data: {s1_metrics_h['size']:,} B | Storage: {s1_metrics_h['storageSize']:,} B")
    print(f"  * Shard 2 (rs-shard2): {s2_metrics_h['count']:,} docs ({s2_pct_h:.1f}%) | "
          f"Data: {s2_metrics_h['size']:,} B | Storage: {s2_metrics_h['storageSize']:,} B")
    print(f"Total Chunks: {total_chunks_h} | Chunk Mapping: {chunks_by_shard_h}")

    # 2. Analyze even_data
    print("\n[PART 2] Evaluating 'even_data' (Shard Key: { user_id: 'hashed' })")
    print("-" * 75)
    ns_even = f"{db_name}.even_data"
    total_chunks_e, chunks_by_shard_e = inspect_chunks_v7(mongos_client, ns_even)
    s1_metrics_e = get_direct_shard_metrics(shard1_client, db_name, "even_data")
    s2_metrics_e = get_direct_shard_metrics(shard2_client, db_name, "even_data")
    collstats_e = get_collstats_agg(mongos_client, db_name, "even_data")

    total_e = s1_metrics_e["count"] + s2_metrics_e["count"]
    s1_pct_e = (s1_metrics_e["count"] / total_e * 100) if total_e > 0 else 0
    s2_pct_e = (s2_metrics_e["count"] / total_e * 100) if total_e > 0 else 0

    print(f"Total Documents: {total_e:,}")
    print(f"  * Shard 1 (rs-shard1): {s1_metrics_e['count']:,} docs ({s1_pct_e:.1f}%) | "
          f"Data: {s1_metrics_e['size']:,} B | Storage: {s1_metrics_e['storageSize']:,} B")
    print(f"  * Shard 2 (rs-shard2): {s2_metrics_e['count']:,} docs ({s2_pct_e:.1f}%) | "
          f"Data: {s2_metrics_e['size']:,} B | Storage: {s2_metrics_e['storageSize']:,} B")
    print(f"Total Chunks: {total_chunks_e} | Chunk Mapping: {chunks_by_shard_e}")

    summary_report["collections"]["hotspot_data"] = {
        "shard_key": "{ ts: 1 }",
        "total_documents": total_h,
        "shard1_count": s1_metrics_h["count"],
        "shard2_count": s2_metrics_h["count"],
        "shard1_percentage": round(s1_pct_h, 2),
        "shard2_percentage": round(s2_pct_h, 2),
        "shard1_storage_bytes": s1_metrics_h["storageSize"],
        "shard2_storage_bytes": s2_metrics_h["storageSize"],
        "total_chunks": total_chunks_h,
        "chunks_per_shard": chunks_by_shard_h,
        "collStats_agg": collstats_h
    }

    summary_report["collections"]["even_data"] = {
        "shard_key": "{ user_id: 'hashed' }",
        "total_documents": total_e,
        "shard1_count": s1_metrics_e["count"],
        "shard2_count": s2_metrics_e["count"],
        "shard1_percentage": round(s1_pct_e, 2),
        "shard2_percentage": round(s2_pct_e, 2),
        "shard1_storage_bytes": s1_metrics_e["storageSize"],
        "shard2_storage_bytes": s2_metrics_e["storageSize"],
        "total_chunks": total_chunks_e,
        "chunks_per_shard": chunks_by_shard_e,
        "collStats_agg": collstats_e
    }

    # 3. Query Execution Plans
    print("\n[PART 3] Query Execution Plans (explain executionStats)")
    print("-" * 75)

    # Range Query on hotspot_data
    t_min = datetime(2026, 10, 30, 0, 0, 10, tzinfo=timezone.utc)
    t_max = datetime(2026, 10, 30, 0, 0, 30, tzinfo=timezone.utc)
    hotspot_filter = {"ts": {"$gte": t_min, "$lte": t_max}}
    explain_hotspot = explain_range_query(
        mongos_client, db_name, "hotspot_data", hotspot_filter,
        "Range Query on Ranged Key: { ts: { $gte, $lte } }"
    )

    print(f"\n1. {explain_hotspot['query_label']}")
    print(f"   - Targeting Result: {explain_hotspot['targeting_type']}")
    print(f"   - Shards Contacted: {explain_hotspot['shards_contacted_count']}")
    print(f"   - Documents Returned: {explain_hotspot['total_n_returned']}")
    for s in explain_hotspot["shards_detail"]:
        print(f"     > {s['shardName']}: stage={s['stage']}, returned={s['nReturned']}")

    # Range Query on even_data
    even_range_filter = {"user_id": {"$gte": "usr_20000000", "$lte": "usr_40000000"}}
    explain_even_range = explain_range_query(
        mongos_client, db_name, "even_data", even_range_filter,
        "Range Query on Hashed Key: { user_id: { $gte, $lte } }"
    )

    print(f"\n2. {explain_even_range['query_label']}")
    print(f"   - Targeting Result: {explain_even_range['targeting_type']}")
    print(f"   - Shards Contacted: {explain_even_range['shards_contacted_count']}")
    print(f"   - Documents Returned: {explain_even_range['total_n_returned']}")
    for s in explain_even_range["shards_detail"]:
        print(f"     > {s['shardName']}: stage={s['stage']}, returned={s['nReturned']}")

    # Point Query on even_data
    sample_doc = mongos_client[db_name]["even_data"].find_one()
    sample_user_id = sample_doc["user_id"] if sample_doc else "usr_10000000_1000"
    even_point_filter = {"user_id": sample_user_id}
    explain_even_point = explain_range_query(
        mongos_client, db_name, "even_data", even_point_filter,
        f"Point Query on Hashed Key: {{ user_id: '{sample_user_id}' }}"
    )

    print(f"\n3. {explain_even_point['query_label']}")
    print(f"   - Targeting Result: {explain_even_point['targeting_type']}")
    print(f"   - Shards Contacted: {explain_even_point['shards_contacted_count']}")
    print(f"   - Documents Returned: {explain_even_point['total_n_returned']}")
    for s in explain_even_point["shards_detail"]:
        print(f"     > {s['shardName']}: stage={s['stage']}, returned={s['nReturned']}")

    summary_report["queries"] = {
        "hotspot_range_query": explain_hotspot,
        "even_range_query": explain_even_range,
        "even_point_query": explain_even_point
    }

    # Save to file
    out_dir = os.path.dirname(os.path.abspath(__file__))
    out_file = os.path.join(out_dir, "distribution_summary.json")
    with open(out_file, "w") as f:
        json.dump(summary_report, f, indent=2, default=str)
    print(f"\n[OK] Analysis metrics exported to '{out_file}'.")

    return 0

if __name__ == "__main__":
    sys.exit(main())
