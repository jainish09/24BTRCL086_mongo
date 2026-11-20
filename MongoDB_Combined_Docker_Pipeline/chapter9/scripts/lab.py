"""Entry point of the Chapter 9 lab image.

    docker compose run --rm lab <command>

Commands:
    setup      initialise the 3-node replica set rs0 and show rs.status()
    9.1        Lab 9.1  - write concern latency (w: 1 / majority / all)
    9.1-try    Activity 9.1 (Try it yourself) - j: true vs j: false
    9.2        Lab 9.2  - network partition (needs the Docker socket)
    observer   the Lab 8.2 failover observer, polling every second (Ctrl+C to stop)
    all        setup, 9.1, 9.1-try and 9.2 one after another
    results    print the results saved in the image from the author's own run
    compose    print the docker-compose.yml needed to run this image
"""

import os
import runpy
import sys
from pathlib import Path

HERE = Path(__file__).parent
SCRIPTS = {
    "9.1": "lab_9_1_write_concern_latency.py",
    "9.1-try": "try_9_1_journal_latency.py",
    "9.2": "lab_9_2_network_partition.py",
    "observer": "observer.py",
}


def run(script):
    runpy.run_path(str(HERE / script), run_name="__main__")


def setup():
    from common import ensure_replica_set, print_members, replica_status
    print("Chapter 9 lab - replica set setup")
    ensure_replica_set()
    print_members(replica_status())


def main():
    command = sys.argv[1] if len(sys.argv) > 1 else "help"
    if command in SCRIPTS:
        run(SCRIPTS[command])
    elif command == "setup":
        setup()
    elif command == "all":
        setup()
        for name in ("9.1", "9.1-try", "9.2"):
            print("\n" + "=" * 100 + "\n")
            run(SCRIPTS[name])
    elif command == "results":
        for path in sorted((HERE / "results").glob("*_output.txt")):
            print("=" * 100 + f"\n{path.name}\n" + "=" * 100)
            print(path.read_text())
    elif command == "compose":
        text = (HERE / "docker-compose.yml").read_text().replace("    build: .\n", "")
        print(text.replace("${LAB_IMAGE:-mongodb-lab09:local}", os.environ.get("LAB_IMAGE", "mongodb-lab09:local")))
    else:
        print(__doc__)


if __name__ == "__main__":
    sys.path.insert(0, str(HERE))
    main()
