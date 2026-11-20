#!/usr/bin/env python3
"""
Chapter 11: Sharded Cluster Initialization Script (Lab 11.2)
Author: Senior MongoDB Engineer
Description:
  1. Initiates Config Server replica set (rs-config)
  2. Initiates Shard 1 replica set (rs-shard1)
  3. Initiates Shard 2 replica set (rs-shard2)
  4. Waits for mongos to establish communication with CSRS
  5. Adds shard1 and shard2 to the mongos cluster
  6. Enables sharding on database 'exp11_db'
  7. Shards collection 'hotspot_data' by { ts: 1 } (Ranged Key)
  8. Shards collection 'even_data' by { user_id: "hashed" } (Hashed Key)
"""

import os
import sys
import time
import argparse
from pymongo import MongoClient
from pymongo.errors import OperationFailure, ServerSelectionTimeoutError

def get_endpoints(container_mode=False):
    if container_mode:
        return {
            "cfg1": "mongodb://cfg1:27017/?directConnection=true",
            "shard1": "mongodb://shard1:27017/?directConnection=true",
            "shard2": "mongodb://shard2:27017/?directConnection=true",
            "mongos": "mongodb://mongos:27017/",
            "shard1_rs_uri": "rs-shard1/shard1:27017",
            "shard2_rs_uri": "rs-shard2/shard2:27017",
            "cfg1_rs_host": "cfg1:27017",
            "shard1_rs_host": "shard1:27017",
            "shard2_rs_host": "shard2:27017"
        }
    else:
        return {
            "cfg1": "mongodb://127.0.0.1:27021/?directConnection=true",
            "shard1": "mongodb://127.0.0.1:27022/?directConnection=true",
            "shard2": "mongodb://127.0.0.1:27023/?directConnection=true",
            "mongos": "mongodb://127.0.0.1:27027/",
            "shard1_rs_uri": "rs-shard1/shard1:27017",
            "shard2_rs_uri": "rs-shard2/shard2:27017",
            "cfg1_rs_host": "cfg1:27017",
            "shard1_rs_host": "shard1:27017",
            "shard2_rs_host": "shard2:27017"
        }

def wait_for_node(uri, name, timeout=60):
    start = time.time()
    while time.time() - start < timeout:
        try:
            client = MongoClient(uri, serverSelectionTimeoutMS=2000)
            res = client.admin.command("ping")
            if res.get("ok") == 1:
                print(f"[OK] {name} is reachable and responding.")
                return client
        except Exception:
            pass
        time.sleep(1)
    raise TimeoutError(f"Failed to reach {name} at {uri} within {timeout}s.")

def init_replica_set(client, rs_name, host_in_rs, is_config=False):
    try:
        status = client.admin.command("replSetGetStatus")
        print(f"[INFO] Replica set '{rs_name}' is already initialized.")
        return
    except OperationFailure as e:
        if "no replSet" not in str(e) and "NotYetInitialized" not in str(e):
            print(f"[WARN] Status for '{rs_name}': {e}")

    print(f"[INIT] Initializing replica set '{rs_name}'...")
    cfg = {
        "_id": rs_name,
        "members": [{"_id": 0, "host": host_in_rs}]
    }
    if is_config:
        cfg["configsvr"] = True

    try:
        client.admin.command("replSetInitiate", cfg)
        print(f"[OK] replSetInitiate submitted for '{rs_name}'.")
    except OperationFailure as e:
        if "already initialized" in str(e):
            print(f"[INFO] Replica set '{rs_name}' already initialized.")
        else:
            raise e

    print(f"[WAIT] Waiting for primary election on '{rs_name}'...")
    deadline = time.time() + 45
    while time.time() < deadline:
        try:
            is_master = client.admin.command("isMaster") or client.admin.command("hello")
            if is_master.get("ismaster", False) or is_master.get("isWritablePrimary", False):
                print(f"[OK] '{rs_name}' primary elected: {is_master.get('primary') or host_in_rs}")
                return
        except Exception:
            pass
        time.sleep(1)
    print(f"[WARN] Primary election check timed out for '{rs_name}', proceeding.")

def main():
    parser = argparse.ArgumentParser(description="Initialize Chapter 11 Sharded Cluster")
    parser.add_argument("--container", action="store_true", help="Run with internal Docker network names")
    args = parser.parse_args()

    is_container = args.container or os.environ.get("RUNNING_IN_CONTAINER") == "1"
    ep = get_endpoints(container_mode=is_container)

    print("=" * 75)
    print("CHAPTER 11: SHARDED CLUSTER INITIALIZATION (LAB 11.2)")
    print("=" * 75)

    # 1. Initiate Config Server CSRS
    print("\n[Step 1/5] Initializing Config Server CSRS (rs-config)...")
    cfg_client = wait_for_node(ep["cfg1"], "Config Server (cfg1)")
    init_replica_set(cfg_client, "rs-config", ep["cfg1_rs_host"], is_config=True)

    # 2. Initiate Shard 1
    print("\n[Step 2/5] Initializing Data Shard 1 (rs-shard1)...")
    shard1_client = wait_for_node(ep["shard1"], "Shard 1 (shard1)")
    init_replica_set(shard1_client, "rs-shard1", ep["shard1_rs_host"])

    # 3. Initiate Shard 2
    print("\n[Step 3/5] Initializing Data Shard 2 (rs-shard2)...")
    shard2_client = wait_for_node(ep["shard2"], "Shard 2 (shard2)")
    init_replica_set(shard2_client, "rs-shard2", ep["shard2_rs_host"])

    # 4. Connect to mongos & register shards
    print("\n[Step 4/5] Connecting to Query Router (mongos) & Registering Shards...")
    mongos_client = wait_for_node(ep["mongos"], "mongos Router", timeout=60)
    admin_db = mongos_client.admin

    current_shards = admin_db.command("listShards").get("shards", [])
    existing_shard_ids = [s["_id"] for s in current_shards]
    print(f"[INFO] Current registered shards: {existing_shard_ids}")

    for s_name, s_uri in [("rs-shard1", ep["shard1_rs_uri"]), ("rs-shard2", ep["shard2_rs_uri"])]:
        if s_name not in existing_shard_ids:
            print(f"[ADD] Adding shard: {s_uri}")
            try:
                res = admin_db.command("addShard", s_uri)
                print(f"[OK] Shard added: {res.get('shardAdded', s_name)}")
            except OperationFailure as e:
                print(f"[INFO] addShard response: {e}")
        else:
            print(f"[INFO] Shard '{s_name}' already registered.")

    # 5. Enable sharding on database & shard target collections
    print("\n[Step 5/5] Configuring Database and Collection Shard Keys...")
    db_name = "exp11_db"
    try:
        admin_db.command("enableSharding", db_name)
        print(f"[OK] Sharding enabled on database '{db_name}'.")
    except OperationFailure as e:
        if "already enabled" in str(e):
            print(f"[INFO] Sharding already enabled on '{db_name}'.")
        else:
            print(f"[WARN] enableSharding: {e}")

    db = mongos_client[db_name]

    # Shard hotspot_data by { ts: 1 }
    print("\nConfiguring 'hotspot_data' with shard key { ts: 1 }...")
    db.hotspot_data.create_index([("ts", 1)])
    try:
        admin_db.command("shardCollection", f"{db_name}.hotspot_data", key={"ts": 1})
        print("[OK] Collection 'hotspot_data' sharded by { ts: 1 }.")
    except OperationFailure as e:
        if "already sharded" in str(e):
            print("[INFO] Collection 'hotspot_data' is already sharded.")
        else:
            print(f"[WARN] shardCollection hotspot_data: {e}")

    # Shard even_data by { user_id: "hashed" }
    print("\nConfiguring 'even_data' with shard key { user_id: 'hashed' }...")
    db.even_data.create_index([("user_id", "hashed")])
    try:
        admin_db.command("shardCollection", f"{db_name}.even_data", key={"user_id": "hashed"})
        print("[OK] Collection 'even_data' sharded by { user_id: 'hashed' }.")
    except OperationFailure as e:
        if "already sharded" in str(e):
            print("[INFO] Collection 'even_data' is already sharded.")
        else:
            print(f"[WARN] shardCollection even_data: {e}")

    print("\n" + "=" * 75)
    print("CLUSTER TOPOLOGY CONFIRMED:")
    print("=" * 75)
    shards = admin_db.command("listShards").get("shards", [])
    for s in shards:
        print(f"  * Shard ID: {s['_id']} | Host: {s['host']}")
    print("\nInitialization successfully finished.")
    return 0

if __name__ == "__main__":
    sys.exit(main())
