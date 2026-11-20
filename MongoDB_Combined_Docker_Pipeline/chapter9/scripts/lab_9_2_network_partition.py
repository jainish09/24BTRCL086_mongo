"""Lab 9.2 - Simulate a network partition.

Uses Docker's own network commands (the same as `docker network disconnect`) to
cut members off from the replica set, while the Lab 8.2 failover observer runs in
the background and logs every change in member state.

  Phase A  disconnect ONE secondary for 30 s -> insert with w: 1 and w: majority
  Phase B  also disconnect the OTHER secondary -> the primary is alone:
           insert with w: 1 and w: majority, watch the primary step down,
           try another write, then read
  Phase C  reconnect both secondaries -> watch the election and the catch-up

The lab container needs the Docker socket (mounted in docker-compose.yml).
Run:  docker compose run --rm lab 9.2
"""

import os
import threading
import time
from datetime import datetime, timezone

import docker
from pymongo import MongoClient, ReadPreference
from pymongo.errors import PyMongoError
from pymongo.write_concern import WriteConcern

from common import (MEMBERS, RS_URI, Recorder, Tee, direct, ensure_replica_set, primary_of,
                    print_members, replica_status)
from observer import ObserverThread

TITLE = "Lab 9.2 - Simulate a Network Partition"
NAME = "lab_9_2_network_partition"
NETWORK = os.environ.get("LAB_NETWORK", "mongo-net-09")
PARTITION_SECONDS = int(os.environ.get("PARTITION_SECONDS", "30"))
WTIMEOUT_MS = 5000

rec = Recorder(TITLE, NAME)
dk = docker.from_env()
network = dk.networks.get(NETWORK)
saved_aliases = {}
disconnected = []
timeline = []
start = time.time()
print_lock = threading.Lock()


def log(source, message, event=False):
    elapsed = time.time() - start
    with print_lock:
        print(f"  {elapsed:6.1f}s  {datetime.now():%H:%M:%S}  [{source:<8}] {message}", flush=True)
    if event:
        timeline.append({"t_s": round(elapsed, 1), "clock": datetime.now().strftime("%H:%M:%S"), "event": message})


def container_of(member):
    return dk.containers.get("combined-" + member.split(":")[0])


def disconnect(member):
    """Same as: docker network disconnect <network> <container>"""
    container = container_of(member)
    container.reload()
    aliases = container.attrs["NetworkSettings"]["Networks"][NETWORK].get("Aliases") or []
    saved_aliases[member] = sorted({member.split(":")[0], *aliases})
    network.disconnect(container)
    disconnected.append(member)
    rec.record(f"docker network disconnect {NETWORK} {container.name}",
               {"docker": f"network disconnect {NETWORK} {container.name}"}, {"ok": True})
    log("DOCKER", f"docker network disconnect {NETWORK} {container.name}   <-- {member} partitioned", event=True)


def reconnect(member):
    """Same as: docker network connect <network> <container> (keeping its DNS aliases)"""
    container = container_of(member)
    network.connect(container, aliases=saved_aliases.get(member, [member.split(":")[0]]))
    disconnected.remove(member)
    rec.record(f"docker network connect {NETWORK} {container.name}",
               {"docker": f"network connect {NETWORK} {container.name}"}, {"ok": True})
    log("DOCKER", f"docker network connect {NETWORK} {container.name}   <-- {member} back on the network", event=True)


def make_sure_everyone_is_connected():
    """Repair a previous run that was interrupted half-way."""
    for member in MEMBERS:
        container = container_of(member)
        container.reload()
        if NETWORK not in container.attrs["NetworkSettings"]["Networks"]:
            network.connect(container, aliases=[member.split(":")[0]])
            print(f"  reconnected {container.name} left over from an earlier run")


inserts = []
writer = MongoClient(RS_URI, serverSelectionTimeoutMS=5000)
collection = writer["lab09"]["partition_test"]


def insert(phase, label, concern):
    doc = {"phase": phase, "label": label, "insertedAt": datetime.now(timezone.utc)}
    t0 = time.perf_counter()
    try:
        collection.with_options(write_concern=concern).insert_one(doc)
        outcome, detail = "SUCCESS", "acknowledged"
    except PyMongoError as error:
        outcome, detail = "FAILED", f"{type(error).__name__}: {str(error).split(',')[0][:90]}"
    ms = (time.perf_counter() - t0) * 1000
    entry = {"phase": phase, "label": label, "writeConcern": concern.document,
             "outcome": outcome, "ms": round(ms, 1), "detail": detail}
    inserts.append(entry)
    rec.record(f"{phase}: insert with {label}",
               {"insert": "partition_test", "$db": "lab09", "writeConcern": concern.document}, entry)
    log("INSERT", f"{label:<32} {outcome:<8} {ms:8.1f} ms   {detail}", event=True)
    return outcome


def wait_for(condition, timeout, what):
    t0 = time.time()
    while time.time() - t0 < timeout:
        if observer.latest and condition(observer.latest):
            return time.time() - t0
        time.sleep(0.5)
    raise TimeoutError(f"timed out waiting for: {what}")


def hold_until(t0, seconds):
    remaining = seconds - (time.time() - t0)
    if remaining > 0:
        log("MAIN", f"holding the partition for another {remaining:.0f} s ...")
        time.sleep(remaining)


def counts_per_member():
    """How many of each test document every member holds (read directly from each member)."""
    table = {}
    for member in MEMBERS:
        coll = direct(member)["lab09"].get_collection(
            "partition_test", read_preference=ReadPreference.PRIMARY_PREFERRED)
        table[member] = {r["_id"]: r["n"] for r in coll.aggregate(
            [{"$group": {"_id": "$label", "n": {"$sum": 1}}}])}
    return table


def main():
    global observer
    print(TITLE.upper())

    print("\nSetup: healthy 3-node replica set")
    make_sure_everyone_is_connected()
    ensure_replica_set(rec)
    status = replica_status()
    rec.record("rs.status() before the partition", {"replSetGetStatus": 1}, status)
    print_members(status)
    primary = primary_of(status)
    secondaries = [m["name"] for m in status["members"] if m["stateStr"] == "SECONDARY"]
    first, second = secondaries
    collection.with_options(write_concern=WriteConcern(w="majority")).drop()
    print(f"  primary = {primary}   secondaries = {first}, {second}   docker network = {NETWORK}")

    print("\nTimeline  (elapsed time, clock, source, event)")
    observer = ObserverThread(log)
    observer.start()
    time.sleep(2)
    log("MAIN", "all members healthy, starting the experiment", event=True)

    try:
        # ------------------------------------------------------------------ Phase A
        print("\n  --- Phase A: partition ONE secondary ---")
        t_a = time.time()
        disconnect(first)
        took = wait_for(lambda s: first in s["primary_sees_down"], 30, "primary to notice")
        log("MAIN", f"primary marked {first} as down after {took:.1f} s (heartbeat timeout); "
                    f"{primary} + {second} are still 2 of 3 = a majority", event=True)
        insert("A", "w: 1", WriteConcern(w=1))
        insert("A", "w: majority", WriteConcern(w="majority", wtimeout=WTIMEOUT_MS))
        log("MAIN", f"primary is still {observer.latest['primary']}")
        hold_until(t_a, PARTITION_SECONDS)

        # ------------------------------------------------------------------ Phase B
        print("\n  --- Phase B: partition the OTHER secondary as well (primary is alone) ---")
        t_b = time.time()
        disconnect(second)
        insert("B", "w: 1 (before step-down)", WriteConcern(w=1))
        insert("B", "w: majority (before step-down)", WriteConcern(w="majority", wtimeout=WTIMEOUT_MS))
        wait_for(lambda s: s["primary"] is None, 40, "primary to step down")
        log("MAIN", f"{primary} STEPPED DOWN to SECONDARY {time.time() - t_b:.1f} s after it lost "
                    "its majority - no member can accept writes", event=True)
        insert("B", "w: 1 (after step-down)", WriteConcern(w=1))
        try:
            n = direct(primary)["lab09"].get_collection(
                "partition_test", read_preference=ReadPreference.PRIMARY_PREFERRED).count_documents({})
            log("READ", f"read from {primary} SUCCESS - {n} documents: the set is read-only", event=True)
        except PyMongoError as error:
            log("READ", f"read from {primary} FAILED - {error}", event=True)
        hold_until(t_b, PARTITION_SECONDS)
    finally:
        # ------------------------------------------------------------------ Phase C
        print("\n  --- Phase C: heal the partition ---")
        t_c = time.time()
        for member in list(disconnected):
            reconnect(member)

    wait_for(lambda s: s["primary"] is not None, 90, "a new primary")
    new_primary = observer.latest["primary"]
    log("MAIN", f"election finished: {new_primary} is PRIMARY {time.time() - t_c:.1f} s after the reconnect "
                f"(old primary was {primary})", event=True)

    # catch-up: wait until every member has the primary's latest optime
    catch_up = []
    t_cu = time.time()
    while time.time() - t_cu < 120:
        try:
            st = direct(new_primary).admin.command("replSetGetStatus")
        except PyMongoError:
            time.sleep(1)
            continue
        p = next((m for m in st["members"] if m["stateStr"] == "PRIMARY"), None)
        if p is None:  # primary changed again; ask whoever is primary now
            time.sleep(1)
            new_primary = observer.latest["primary"] or new_primary
            continue
        lag = {m["name"]: (p["optimeDate"] - m["optimeDate"]).total_seconds()
               for m in st["members"] if "optimeDate" in m}
        states = {m["name"]: m["stateStr"] for m in st["members"]}
        catch_up.append({"at": datetime.now(timezone.utc), "states": states, "lag_s": lag})
        log("CATCH-UP", "  ".join(f"{n.split(':')[0]}={states[n]} lag={lag.get(n, '?')}s" for n in states))
        if all(s in ("PRIMARY", "SECONDARY") for s in states.values()) and \
                len(lag) == len(MEMBERS) and max(lag.values()) <= 0:
            break
        time.sleep(2)
    log("MAIN", f"all members caught up {time.time() - t_c:.1f} s after the reconnect", event=True)
    rec.record("Catch-up after reconnect (replSetGetStatus polls)", {"replSetGetStatus": 1}, catch_up)
    time.sleep(2)
    observer.stop()

    # ------------------------------------------------------------------ results
    print("\nWhich test documents does each member hold now?")
    counts = counts_per_member()
    rec.record("Documents per member after recovery", {"aggregate": "partition_test", "$group": "label"}, counts)
    print(f"  {'insert':<32} {'result during partition':<24} " + " ".join(f"{m.split(':')[0]:>7}" for m in MEMBERS))
    for entry in inserts:
        held = [counts[m].get(entry["label"], 0) for m in MEMBERS]
        print(f"  {entry['label']:<32} {entry['outcome'] + ' ' + str(entry['ms']) + ' ms':<24} "
              + " ".join(f"{h:>7}" for h in held))
    kept = [i["label"] for i in inserts if all(counts[m].get(i["label"], 0) for m in MEMBERS)]
    lost = [i["label"] for i in inserts
            if i["outcome"] == "SUCCESS" and not any(counts[m].get(i["label"], 0) for m in MEMBERS)]
    timed_out_but_kept = [i["label"] for i in inserts if i["outcome"] == "FAILED" and i["label"] in kept]
    print(f"\n  on every member after recovery: {', '.join(kept) or 'none'}")
    if lost:
        print(f"  acknowledged but ROLLED BACK (the new primary never had them): {', '.join(lost)}")
    failed_not_stored = [i["label"] for i in inserts
                         if i["outcome"] == "FAILED" and not any(counts[m].get(i["label"], 0) for m in MEMBERS)]
    if failed_not_stored:
        print(f"  failed and not stored anywhere: {', '.join(failed_not_stored)}")
    if timed_out_but_kept:
        print(f"  reported as failed but still stored: {', '.join(timed_out_but_kept)} "
              "(a wtimeout does not undo the write)")

    print("\nTimeline of key events")
    for e in timeline:
        print(f"  {e['t_s']:6.1f}s  {e['clock']}  {e['event']}")

    final = replica_status()
    rec.record("rs.status() after recovery", {"replSetGetStatus": 1}, final)
    print("\nFinal rs.status()")
    print_members(final)
    rec.save(network=NETWORK, partitionSeconds=PARTITION_SECONDS, inserts=inserts, timeline=timeline,
             observerChanges=observer.changes, documentsPerMember=counts)


if __name__ == "__main__":
    with Tee(NAME):
        main()
