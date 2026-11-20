#!/usr/bin/env python3
"""
Chapter 11: Master Lab Runner (Lab 11.1 & 11.2)
Author: Senior MongoDB Engineer
Description:
  Automates Chapter 11 execution:
    1. Runs init_sharding.py to set up CSRS, shards, mongos, and sharded collections.
    2. Runs load_data.py to ingest 10,000 documents per collection.
    3. Runs analyze_distribution.py to evaluate storage, chunk skew, and query plans.
"""

import os
import sys
import subprocess
import time

def run_step(step_title, script_path, extra_args):
    print("\n" + "=" * 75)
    print(f"STEP: {step_title}")
    print("=" * 75)
    cmd = [sys.executable, script_path] + extra_args
    start = time.time()
    res = subprocess.run(cmd)
    elapsed = time.time() - start
    if res.returncode != 0:
        print(f"\n[FAILED] {step_title} terminated with exit code {res.returncode}")
        sys.exit(res.returncode)
    print(f"[PASSED] {step_title} finished in {elapsed:.2f}s.")

def main():
    script_dir = os.path.dirname(os.path.abspath(__file__))
    is_container = os.environ.get("RUNNING_IN_CONTAINER") == "1" or "--container" in sys.argv
    extra_flags = ["--container"] if is_container else []

    print("*" * 75)
    print("STARTING CHAPTER 11: MONGODB SHARDING LAB EXECUTION")
    print("*" * 75)

    # 1. Initialize Sharded Cluster
    run_step(
        "1. Initialize Sharded Cluster & Shard Keys",
        os.path.join(script_dir, "init_sharding.py"),
        extra_flags
    )

    # 2. Ingest 10,000 documents per collection
    run_step(
        "2. Ingest 10,000 Documents Per Collection",
        os.path.join(script_dir, "load_data.py"),
        extra_flags
    )

    # 3. Analyze Distribution and Explain Plans
    run_step(
        "3. Analyze Distribution and Range Query Execution Plans",
        os.path.join(script_dir, "analyze_distribution.py"),
        extra_flags
    )

    print("\n" + "*" * 75)
    print("CHAPTER 11 LAB EXECUTION FULLY COMPLETED!")
    print("*" * 75)

if __name__ == "__main__":
    main()
