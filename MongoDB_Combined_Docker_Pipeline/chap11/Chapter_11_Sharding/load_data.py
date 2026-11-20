#!/usr/bin/env python3
"""
Chapter 11: Data Ingestion Script (Lab 11.2)
Author: Senior MongoDB Engineer
Description:
  Inserts exactly 10,000 documents into each collection through mongos:
  1. 'hotspot_data' -> Shard key: { ts: 1 }
     Strictly monotonically increasing BSON datetime timestamps.
  2. 'even_data'    -> Shard key: { user_id: "hashed" }
     Varied, high-cardinality pseudo-random user IDs.
"""

import os
import sys
import time
import random
import argparse
from datetime import datetime, timezone, timedelta
from pymongo import MongoClient
from pymongo.errors import BulkWriteError, PyMongoError

def get_mongos_uri(container_mode=False):
    if container_mode:
        return "mongodb://mongos:27017/"
    else:
        return "mongodb://127.0.0.1:27027/"

def generate_hotspot_batch(start_idx, count, base_time):
    batch = []
    for i in range(start_idx, start_idx + count):
        doc = {
            "_id": i,
            "ts": base_time + timedelta(milliseconds=i * 10),
            "sensor_id": f"sensor_{(i % 25):03d}",
            "metric_type": "temperature_celsius",
            "value": round(20.0 + (i % 150) * 0.1, 2),
            "status": "NORMAL" if (i % 20 != 0) else "ALERT",
            "batch_tag": f"batch_{start_idx // count}",
            "metadata": {
                "source": "iot_ingest_pipeline",
                "seq": i,
                "padding": "x" * 64
            }
        }
        batch.append(doc)
    return batch

def generate_even_batch(start_idx, count, rng, base_time):
    batch = []
    actions = ["view_item", "add_to_cart", "checkout", "search", "update_profile"]
    for i in range(start_idx, start_idx + count):
        user_uuid = f"usr_{rng.randint(10000000, 99999999)}_{rng.randint(1000, 9999)}"
        doc = {
            "_id": i,
            "user_id": user_uuid,
            "session_id": f"sess_{rng.randint(100000, 999999)}",
            "action": actions[rng.randint(0, len(actions) - 1)],
            "cart_value": round(rng.uniform(10.0, 500.0), 2),
            "timestamp": base_time + timedelta(seconds=rng.randint(0, 86400)),
            "metadata": {
                "client_ip": f"192.168.{rng.randint(1, 254)}.{rng.randint(1, 254)}",
                "seq": i,
                "padding": "x" * 64
            }
        }
        batch.append(doc)
    return batch

def load_collection(coll, coll_name, generator_func, total_docs=10000, batch_size=1000):
    print(f"\n--- Ingesting {total_docs:,} documents into '{coll_name}' via mongos ---")
    start_time = time.time()
    inserted_count = 0

    coll.delete_many({})

    for start_idx in range(0, total_docs, batch_size):
        batch = generator_func(start_idx, min(batch_size, total_docs - start_idx))
        b_start = time.time()
        try:
            coll.insert_many(batch, ordered=False)
            inserted_count += len(batch)
            b_elapsed = time.time() - b_start
            print(f"  [Progress] {inserted_count:5d}/{total_docs} inserted "
                  f"(Batch {len(batch)} in {b_elapsed:.3f}s, Rate: {len(batch)/b_elapsed:,.0f} docs/s)")
        except BulkWriteError as bwe:
            print(f"  [ERROR] BulkWriteError at {start_idx}: {bwe.details}")
            raise bwe
        except PyMongoError as pe:
            print(f"  [ERROR] PyMongoError: {pe}")
            raise pe

    total_time = time.time() - start_time
    actual_count = coll.count_documents({})
    print(f"[COMPLETED] '{coll_name}': {actual_count:,} documents in {total_time:.2f}s "
          f"(Avg Rate: {actual_count/total_time:,.0f} docs/s)")
    return actual_count, total_time

def main():
    parser = argparse.ArgumentParser(description="Insert documents into sharded collections")
    parser.add_argument("--container", action="store_true", help="Run with internal Docker hostnames")
    parser.add_argument("--docs", type=int, default=10000, help="Document count (default: 10000)")
    parser.add_argument("--batch-size", type=int, default=1000, help="Batch size (default: 1000)")
    args = parser.parse_args()

    is_container = args.container or os.environ.get("RUNNING_IN_CONTAINER") == "1"
    mongos_uri = get_mongos_uri(container_mode=is_container)

    print("=" * 75)
    print("CHAPTER 11: DATA INGESTION PIPELINE (LAB 11.2)")
    print(f"Target mongos: {mongos_uri}")
    print(f"Target Document Count: {args.docs:,} docs/collection")
    print("=" * 75)

    client = MongoClient(mongos_uri)
    db = client["exp11_db"]

    base_time = datetime(2026, 10, 30, 0, 0, 0, tzinfo=timezone.utc)
    rng = random.Random(42)

    # 1. Load hotspot_data
    hotspot_coll = db["hotspot_data"]
    h_count, h_time = load_collection(
        hotspot_coll,
        "hotspot_data (sharded by { ts: 1 })",
        lambda s, c: generate_hotspot_batch(s, c, base_time),
        total_docs=args.docs,
        batch_size=args.batch_size
    )

    # 2. Load even_data
    even_coll = db["even_data"]
    e_count, e_time = load_collection(
        even_coll,
        "even_data (sharded by { user_id: 'hashed' })",
        lambda s, c: generate_even_batch(s, c, rng, base_time),
        total_docs=args.docs,
        batch_size=args.batch_size
    )

    print("\n" + "=" * 75)
    print("INGESTION SUMMARY:")
    print("=" * 75)
    print(f"  * 'hotspot_data': {h_count:,} docs inserted ({h_time:.2f}s)")
    print(f"  * 'even_data':    {e_count:,} docs inserted ({e_time:.2f}s)")
    print("All operations successfully routed through mongos.")
    return 0

if __name__ == "__main__":
    sys.exit(main())
