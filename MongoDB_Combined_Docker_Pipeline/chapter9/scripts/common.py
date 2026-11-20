"""Shared helpers for the Chapter 9 labs (replica set setup, logging, latency measurement)."""

import os
import statistics
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

from bson import json_util
from pymongo import MongoClient, ReadPreference
from pymongo.errors import OperationFailure, PyMongoError
from pymongo.write_concern import WriteConcern

RS_NAME = "rs0"
MEMBERS = ["mongo1:27017", "mongo2:27017", "mongo3:27017"]
RS_URI = f"mongodb://{','.join(MEMBERS)}/?replicaSet={RS_NAME}"
OUTPUT_DIR = Path(os.environ.get("OUTPUT_DIR", "/lab/output"))
ALREADY_INITIALIZED = 23


# --------------------------------------------------------------------------- output
class Recorder:
    """Collects every MongoDB command and its reply, then saves them as one JSON file."""

    def __init__(self, title, name):
        self.title, self.name, self.steps = title, name, []

    def record(self, step, command, result):
        self.steps.append({"step": step, "executedAt": datetime.now(timezone.utc),
                           "command": command, "result": result})

    def save(self, **extra):
        OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
        path = OUTPUT_DIR / f"{self.name}.json"
        document = {"activity": self.title, "script": f"{self.name}.py", **extra, "steps": self.steps}
        path.write_text(json_util.dumps(document, indent=2, json_options=json_util.RELAXED_JSON_OPTIONS))
        print(f"\nMongoDB commands and replies saved to output/{path.name}")


class Tee:
    """Copies everything printed to the terminal into output/<name>_output.txt."""

    def __init__(self, name):
        OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
        self.file = open(OUTPUT_DIR / f"{name}_output.txt", "w")

    def __enter__(self):
        self.stdout, sys.stdout = sys.stdout, self
        return self

    def write(self, text):
        self.stdout.write(text)
        self.file.write(text)

    def flush(self):
        self.stdout.flush()
        self.file.flush()

    def __exit__(self, *exc):
        sys.stdout = self.stdout
        self.file.close()


# --------------------------------------------------------------------------- replica set
def direct(host, timeout_ms=2000):
    """A connection to exactly one member (like mongosh --host mongo2)."""
    return MongoClient(f"mongodb://{host}/?directConnection=true",
                       serverSelectionTimeoutMS=timeout_ms, connectTimeoutMS=timeout_ms,
                       socketTimeoutMS=timeout_ms * 3)


def replica_status():
    """rs.status() from whichever member answers first."""
    last_error = None
    for host in MEMBERS:
        try:
            return direct(host).admin.command("replSetGetStatus",
                                              read_preference=ReadPreference.PRIMARY_PREFERRED)
        except PyMongoError as error:
            last_error = error
    raise last_error


def primary_of(status):
    return next((m["name"] for m in status["members"] if m["stateStr"] == "PRIMARY"), None)


def ensure_replica_set(recorder=None, timeout=120):
    """Initialise rs0 if needed and wait until it has 1 PRIMARY + 2 SECONDARY."""
    deadline = time.time() + timeout
    for host in MEMBERS:  # the containers may still be starting
        while True:
            try:
                direct(host).admin.command("ping")
                break
            except PyMongoError:
                if time.time() > deadline:
                    raise
                time.sleep(1)

    config = {"_id": RS_NAME, "members": [{"_id": i, "host": h} for i, h in enumerate(MEMBERS)]}
    try:
        result = direct(MEMBERS[0]).admin.command("replSetInitiate", config)
        print("  replSetInitiate -> ok: 1.0 (new replica set)")
    except OperationFailure as error:
        if error.code != ALREADY_INITIALIZED:
            raise
        result = error.details
        print("  replica set rs0 is already initialised")
    if recorder:
        recorder.record("Initialise the replica set", {"replSetInitiate": config}, result)

    while time.time() < deadline:
        try:
            states = [m["stateStr"] for m in replica_status()["members"]]
            if states.count("PRIMARY") == 1 and states.count("SECONDARY") == len(MEMBERS) - 1:
                return
        except PyMongoError:
            pass
        time.sleep(1)
    raise TimeoutError("replica set did not reach 1 PRIMARY + 2 SECONDARY")


def print_members(status):
    print(f"  {'member':<14} {'state':<10} health")
    for m in status["members"]:
        print(f"  {m['name']:<14} {m['stateStr']:<10} {int(m['health'])}")


# --------------------------------------------------------------------------- latency
WARMUP = 50


def measure_inserts(db, label, write_concern, n_docs):
    """Insert n_docs small documents one at a time and time every write.

    Returns a dict with total seconds, average / median / p95 / max latency in ms
    and writes per second.
    """
    collection = db.get_collection("latency_test", write_concern=write_concern)
    collection.drop()
    for i in range(WARMUP):  # open connections, create the collection; not timed
        collection.insert_one({"warmup": i})
    collection.delete_many({})

    latencies = []
    started = time.perf_counter()
    for i in range(n_docs):
        t0 = time.perf_counter()
        collection.insert_one({"seq": i, "concern": label, "payload": "x" * 100,
                               "ts": datetime.now(timezone.utc)})
        latencies.append((time.perf_counter() - t0) * 1000)
    total = time.perf_counter() - started

    latencies.sort()
    return {
        "concern": label,
        "writeConcern": write_concern.document,
        "documents": n_docs,
        "total_s": round(total, 3),
        "avg_ms": round(total / n_docs * 1000, 3),
        "median_ms": round(statistics.median(latencies), 3),
        "p95_ms": round(latencies[int(0.95 * n_docs) - 1], 3),
        "max_ms": round(latencies[-1], 3),
        "writes_per_s": round(n_docs / total, 1),
        "count_after": collection.count_documents({}),
    }


def wc(w, j=None):
    """WriteConcern with a 30 s timeout so a broken member can never hang the test."""
    return WriteConcern(w=w, j=j, wtimeout=30000) if j is not None else WriteConcern(w=w, wtimeout=30000)
