"""Activity 9.1 (Try it yourself) - Does journaling add significant latency?

Repeats the Lab 9.1 experiment for every write concern with j: false and j: true
(6 runs of 1,000 inserts) and compares the two.

Run:  docker compose run --rm lab 9.1-try
"""

import os

from pymongo import MongoClient

from common import (RS_URI, Recorder, Tee, direct, ensure_replica_set, measure_inserts,
                    primary_of, print_members, replica_status, wc)

TITLE = "Activity 9.1 (Try it yourself) - Journaling j: true vs j: false"
NAME = "try_9_1_journal_latency"
N_DOCS = int(os.environ.get("N_DOCS", "1000"))


def main():
    rec = Recorder(TITLE, NAME)
    print(TITLE.upper())

    print("\nReplica set check")
    ensure_replica_set(rec)
    status = replica_status()
    print_members(status)
    data_members = sum(1 for m in status["members"] if m["stateStr"] in ("PRIMARY", "SECONDARY"))

    config = direct(primary_of(status)).admin.command("replSetGetConfig")["config"]
    majority_journal = config.get("writeConcernMajorityJournalDefault")
    rec.record("Replica set configuration", {"replSetGetConfig": 1}, config)
    print(f"  writeConcernMajorityJournalDefault = {majority_journal}")

    levels = [("w: 1", 1), ("w: majority", "majority"), (f"w: all (w: {data_members})", data_members)]
    db = MongoClient(RS_URI)["lab09"]

    print(f"\nInsert {N_DOCS} documents for each of the 6 combinations")
    results = {}
    for label, w in levels:
        for j in (False, True):
            name = f"{label}, j: {str(j).lower()}"
            print(f"  {name:<30} ...", end=" ", flush=True)
            r = measure_inserts(db, name, wc(w, j), N_DOCS)
            results[(label, j)] = r
            rec.record(f"Insert {N_DOCS} documents with {name}",
                       {"insert": "latency_test", "$db": "lab09", "documents": f"{N_DOCS} x insert_one",
                        "writeConcern": wc(w, j).document}, r)
            print(f"total {r['total_s']:.3f} s   avg {r['avg_ms']:.3f} ms")

    print("\nComparison table (average latency per write)\n")
    header = (f"  {'Write concern':<18} {'j: false (ms)':>13} {'j: true (ms)':>12} "
              f"{'Added (ms)':>10} {'Added %':>8} {'p95 j:f':>8} {'p95 j:t':>8}")
    print(header)
    print("  " + "-" * (len(header) - 2))
    overhead = []
    for label, _ in levels:
        off, on = results[(label, False)], results[(label, True)]
        added = on["avg_ms"] - off["avg_ms"]
        pct = added / off["avg_ms"] * 100
        overhead.append({"writeConcern": label, "jFalse_avg_ms": off["avg_ms"], "jTrue_avg_ms": on["avg_ms"],
                         "added_ms": round(added, 3), "added_pct": round(pct, 1)})
        print(f"  {label:<18} {off['avg_ms']:>13.3f} {on['avg_ms']:>12.3f} {added:>+10.3f} {pct:>+7.1f}% "
              f"{off['p95_ms']:>8.3f} {on['p95_ms']:>8.3f}")

    w1 = overhead[0]
    print("\nDoes journaling add significant latency?")
    print(f"  w: 1        j: true adds {w1['added_ms']:+.3f} ms per write ({w1['added_pct']:+.1f}%). "
          "Here the primary must flush its journal to disk before it replies.")
    print(f"  w: majority j: true adds {overhead[1]['added_ms']:+.3f} ms ({overhead[1]['added_pct']:+.1f}%). "
          f"With writeConcernMajorityJournalDefault = {majority_journal}, majority writes are "
          "already journaled, so j makes little difference.")
    print(f"  w: all      j: true adds {overhead[2]['added_ms']:+.3f} ms ({overhead[2]['added_pct']:+.1f}%). "
          "The network wait for the slowest secondary dominates.")

    rec.save(documentsPerRun=N_DOCS, summary=list(results.values()), journalOverhead=overhead)


if __name__ == "__main__":
    with Tee(NAME):
        main()
