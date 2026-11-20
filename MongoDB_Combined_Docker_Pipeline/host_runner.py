"""
Narrowly Scoped Host Runner for MongoDB Combined Docker Pipeline.
Runs only fixed, explicitly whitelisted commands for Labs 7 through 18.
Listens on port 8001 for communication from the dashboard container.
"""

import sys
import json
import logging
from pathlib import Path
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse, parse_qs

# Ensure lab7/backend is in Python path to import lab_executor
ROOT_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT_DIR / "lab7" / "backend"))

from lab_executor import executor

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("HostLabRunner")

PORT = 8001
HOST = "0.0.0.0"  # Bind to all interfaces so Docker container can reach it


class HostRunnerHandler(BaseHTTPRequestHandler):
    def _send_json(self, status_code: int, data: dict):
        self.send_response(status_code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
        self.end_headers()
        self.wfile.write(json.dumps(data).encode("utf-8"))

    def do_OPTIONS(self):
        self.send_response(204)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
        self.end_headers()

    def do_GET(self):
        parsed = urlparse(self.path)
        path = parsed.path
        query = parse_qs(parsed.query)

        if path == "/ping":
            self._send_json(200, {
                "status": "online",
                "service": "HostLabRunner",
                "dockerAvailable": executor.check_docker()
            })
        elif path == "/status":
            self._send_json(200, executor.get_status())
        elif path == "/logs":
            since = int(query.get("since", [0])[0])
            self._send_json(200, {"logs": executor.get_logs(since)})
        elif path.startswith("/results/"):
            lab_id = path.split("/")[-1]
            status = executor.get_status()
            lab_data = status.get("labs", {}).get(lab_id)
            if lab_data:
                self._send_json(200, lab_data)
            else:
                self._send_json(404, {"error": "Lab not found"})
        else:
            self._send_json(404, {"error": "Not found"})

    def do_POST(self):
        parsed = urlparse(self.path)
        path = parsed.path

        if path == "/run/7":
            res = executor.start_background_run("7")
            status_code = 409 if res.get("busy") else 200
            self._send_json(status_code, res)
        elif path == "/run/8":
            res = executor.start_background_run("8")
            status_code = 409 if res.get("busy") else 200
            self._send_json(status_code, res)
        elif path == "/run/9":
            res = executor.start_background_run("9")
            status_code = 409 if res.get("busy") else 200
            self._send_json(status_code, res)
        elif path == "/run/10":
            res = executor.start_background_run("10")
            status_code = 409 if res.get("busy") else 200
            self._send_json(status_code, res)
        elif path == "/run/11":
            res = executor.start_background_run("11")
            status_code = 409 if res.get("busy") else 200
            self._send_json(status_code, res)
        elif path == "/run/12":
            res = executor.start_background_run("12")
            status_code = 409 if res.get("busy") else 200
            self._send_json(status_code, res)
        elif path == "/run/13":
            res = executor.start_background_run("13")
            status_code = 409 if res.get("busy") else 200
            self._send_json(status_code, res)
        elif path == "/run/14":
            res = executor.start_background_run("14")
            status_code = 409 if res.get("busy") else 200
            self._send_json(status_code, res)
        elif path == "/run/15":
            res = executor.start_background_run("15")
            status_code = 409 if res.get("busy") else 200
            self._send_json(status_code, res)
        elif path == "/run/16":
            res = executor.start_background_run("16")
            status_code = 409 if res.get("busy") else 200
            self._send_json(status_code, res)
        elif path == "/run/17":
            res = executor.start_background_run("17")
            status_code = 409 if res.get("busy") else 200
            self._send_json(status_code, res)
        elif path == "/run/18":
            res = executor.start_background_run("18")
            status_code = 409 if res.get("busy") else 200
            self._send_json(status_code, res)
        elif path in ("/run/all", "/run/run-all"):
            res = executor.start_background_run("all")
            status_code = 409 if res.get("busy") else 200
            self._send_json(status_code, res)
        else:
            self._send_json(404, {"error": "Invalid action"})

    def log_message(self, format, *args):
        # Override to keep logs clean
        logger.info(f"{self.client_address[0]} - {format % args}")


def main():
    docker_ok = executor.check_docker()
    print("=" * 65)
    print("MongoDB Combined Pipeline - Host Lab Runner (Chapters 7 - 18)")
    print("=" * 65)
    print(f"Host: {HOST}:{PORT}")
    print(f"Docker Compose Available: {docker_ok}")
    print("Approved Lab Endpoints:")
    print("  - POST /run/7   (Lab 7 Health & Telemetry)")
    print("  - POST /run/8   (Lab 8 Replication & Failover)")
    print("  - POST /run/9   (Lab 9 Latency & Network Partition)")
    print("  - POST /run/10  (Lab 10 ACID Transactions & Inventory)")
    print("  - POST /run/11  (Lab 11 Horizontal Sharding Cluster)")
    print("  - POST /run/12  (Lab 12 Enterprise Security TLS & RBAC)")
    print("  - POST /run/13  (Lab 13 Containers & Cloud: Docker, K8s, Atlas)")
    print("  - POST /run/14  (Lab 14 Monitoring & Backup Recovery)")
    print("  - POST /run/15  (Lab 15 Multi-Tenant Case Management)")
    print("  - POST /run/16  (Lab 16 Cassandra & Neo4j Integration)")
    print("  - POST /run/17  (Lab 17 Vector Search & RAG)")
    print("  - POST /run/18  (Lab 18 Comparative Capstone & PDF)")
    print("  - POST /run/all (Run All Labs 7 -> 18 Sequentially)")
    print("  - GET  /status  (Status & Telemetry)")
    print("  - GET  /logs    (Live Logs)")
    print("=" * 65)
    print("Listening for requests from ThreatPulse dashboard...\n")

    server = HTTPServer((HOST, PORT), HostRunnerHandler)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nStopping Host Lab Runner.")
        server.server_close()


if __name__ == "__main__":
    main()
