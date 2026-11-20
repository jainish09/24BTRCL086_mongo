"""Failover observer (from Lab 8.2), used in Lab 9.2.

Polls every member once a second and prints what each one reports about itself,
plus which members the primary currently sees as unhealthy.

Standalone use (Terminal 1 in Lab 9.2):
    docker compose run --rm lab observer
Stop it with Ctrl+C.
"""

import threading
import time
from datetime import datetime, timezone

from pymongo.errors import PyMongoError

from common import MEMBERS, direct


class Observer:
    def __init__(self, timeout_ms=700):
        self.clients = {h: direct(h, timeout_ms) for h in MEMBERS}

    def snapshot(self):
        """{'states': {member: state}, 'primary_sees_down': [...], 'primary': member or None}"""
        states = {}
        for host, client in self.clients.items():
            try:
                hello = client.admin.command("hello")
                if hello.get("isWritablePrimary"):
                    states[host] = "PRIMARY"
                elif hello.get("secondary"):
                    states[host] = "SECONDARY"
                elif hello.get("arbiterOnly"):
                    states[host] = "ARBITER"
                else:
                    states[host] = "OTHER"
            except PyMongoError:
                states[host] = "UNREACHABLE"
        primary = next((h for h, s in states.items() if s == "PRIMARY"), None)
        down = []
        if primary:
            try:
                status = self.clients[primary].admin.command("replSetGetStatus")
                down = [m["name"] for m in status["members"] if m["health"] != 1]
            except PyMongoError:
                pass
        return {"states": states, "primary": primary, "primary_sees_down": down}

    @staticmethod
    def line(snap):
        text = "  ".join(f"{h.split(':')[0]}={s}" for h, s in snap["states"].items())
        if snap["primary"]:
            down = ", ".join(h.split(":")[0] for h in snap["primary_sees_down"]) or "none"
            text += f"   | primary sees down: {down}"
        else:
            text += "   | NO PRIMARY (read-only)"
        return text


class ObserverThread(threading.Thread):
    """Runs the observer in the background and logs a line whenever something changes."""

    def __init__(self, log):
        super().__init__(daemon=True)
        self.observer, self.log = Observer(), log
        self.stop_event = threading.Event()
        self.latest, self.changes = None, []

    def run(self):
        last = None
        while not self.stop_event.is_set():
            snap = self.observer.snapshot()
            self.latest = snap
            key = (tuple(snap["states"].items()), tuple(snap["primary_sees_down"]))
            if key != last:
                self.log("OBSERVER", Observer.line(snap))
                self.changes.append({"at": datetime.now(timezone.utc), **snap})
                last = key
            time.sleep(1)

    def stop(self):
        self.stop_event.set()


def main():
    observer = Observer()
    print("Failover observer - polling every second (Ctrl+C to stop)")
    try:
        while True:
            print(f"{datetime.now():%H:%M:%S}  {Observer.line(observer.snapshot())}", flush=True)
            time.sleep(1)
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
