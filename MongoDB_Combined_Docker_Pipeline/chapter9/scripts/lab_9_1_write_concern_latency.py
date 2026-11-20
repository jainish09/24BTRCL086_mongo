"""Lab 9.1 - Measure write concern latency.

Inserts 1,000 documents with each write concern (w: 1, w: majority, w: all),
measures the total time, works out the average latency per write and prints a
comparison table.

Note: MongoDB has no literal w: "all". "All members" is written as the number of
data-bearing members, which is w: 3 for this replica set.

Run:  docker compose run --rm lab 9.1
"""

import os

from pymongo import MongoClient

from common import (RS_URI, Recorder, Tee, ensure_replica_set, measure_inserts, primary_of,
                    print_members, replica_status, wc)

TITLE = "Lab 9.1 - Measure Write Concern Latency"
NAME = "lab_9_1_write_concern_latency"
N_DOCS = int(os.environ.get("N_DOCS", "1000"))


def main():
    rec = Recorder(TITLE, NAME)
    print(TITLE.upper())

    print("\nReplica set check")
    ensure_replica_set(rec)
    status = replica_status()
    rec.record("rs.status() before the test", {"replSetGetStatus": 1}, status)
    print_members(status)
    data_members = sum(1 for m in status["members"] if m["stateStr"] in ("PRIMARY", "SECONDARY"))

    concerns = [
        ("w: 1", wc(1)),
        ("w: majority", wc("majority")),
        (f"w: all (w: {data_members})", wc(data_members)),
    ]

    db = MongoClient(RS_URI)["lab09"]
    print(f"\nStep 1: insert {N_DOCS} documents one at a time with each write concern "
          f"(primary: {primary_of(status)})")
    results = []
    for label, concern in concerns:
        print(f"  {label:<18} ...", end=" ", flush=True)
        r = measure_inserts(db, label, concern, N_DOCS)
        results.append(r)
        rec.record(f"Insert {N_DOCS} documents with {label}",
                   {"insert": "latency_test", "$db": "lab09", "documents": f"{N_DOCS} x insert_one",
                    "writeConcern": concern.document}, r)
        print(f"total {r['total_s']:.3f} s   ({r['count_after']} documents stored)")

    base = results[0]["avg_ms"]
    print("\nStep 2 + 3: average latency per write and comparison table\n")
    header = f"  {'Write concern':<18} {'Total (s)':>9} {'Avg (ms)':>9} {'Median':>8} {'p95':>8} {'Max':>8} {'Writes/s':>9} {'vs w:1':>7}"
    print(header)
    print("  " + "-" * (len(header) - 2))
    for r in results:
        print(f"  {r['concern']:<18} {r['total_s']:>9.3f} {r['avg_ms']:>9.3f} {r['median_ms']:>8.3f} "
              f"{r['p95_ms']:>8.3f} {r['max_ms']:>8.3f} {r['writes_per_s']:>9.1f} {r['avg_ms'] / base:>6.2f}x")

    w1, wmaj, wall = results
    print("\nWhat the numbers show")
    print(f"  w: 1        returns as soon as the primary has applied the write: {w1['avg_ms']:.3f} ms per write.")
    print(f"  w: majority also waits for 1 secondary to confirm (2 of 3 members): "
          f"+{wmaj['avg_ms'] - w1['avg_ms']:.3f} ms, {wmaj['avg_ms'] / base:.2f}x w: 1.")
    print(f"  w: all      waits for every secondary, so it is as slow as the slowest member: "
          f"+{wall['avg_ms'] - w1['avg_ms']:.3f} ms, {wall['avg_ms'] / base:.2f}x w: 1.")

    rec.record("rs.status() after the test", {"replSetGetStatus": 1}, replica_status())
    rec.save(documentsPerConcern=N_DOCS, summary=results)


if __name__ == "__main__":
    with Tee(NAME):
        main()
