"""
Threat Advisor Agent Service.
Handles scanner enrollment, token hashing, polling dispatch, and vulnerability correlation.
"""

import secrets
import hashlib
import logging
from datetime import datetime, timezone, timedelta
from typing import Dict, Any, Optional, List

from database import get_database
from threat_advisor.cpe_matcher import evaluate_cve_against_host
from threat_advisor.snapshot_data import SNAPSHOT_THREATS

logger = logging.getLogger("threat_intel.threat_advisor.agent")


def hash_token(raw_token: str) -> str:
    """Computes SHA-256 hash of agent token so plain token is never stored on server."""
    return hashlib.sha256(raw_token.encode("utf-8")).hexdigest()


class AgentService:
    def __init__(self):
        self.db = get_database()
        # In-memory backup state for when MongoDB is in mock/disconnected state
        self._mock_hosts: Dict[str, Dict[str, Any]] = {}
        self._mock_tokens: Dict[str, datetime] = {}
        self._manual_scan_triggers: set = set()

    def get_collection(self, name: str):
        db = get_database()
        if db is not None:
            return db[name]
        return None

    def create_install_token(self) -> str:
        """Generates a 30-minute temporary install token."""
        token = secrets.token_hex(16)
        now = datetime.now(timezone.utc)
        scan_tokens_col = self.get_collection("scan_tokens")

        if scan_tokens_col is not None:
            scan_tokens_col.insert_one({
                "token": token,
                "createdAt": now,
                "expiresAt": now + timedelta(minutes=30)
            })
        else:
            self._mock_tokens[token] = now + timedelta(minutes=30)

        return token

    def verify_install_token(self, token: str) -> bool:
        """Validates temporary install token."""
        now = datetime.now(timezone.utc)
        scan_tokens_col = self.get_collection("scan_tokens")

        if scan_tokens_col is not None:
            rec = scan_tokens_col.find_one({"token": token})
            if rec:
                # One-time use token; delete upon use
                scan_tokens_col.delete_one({"_id": rec["_id"]})
                return True
            return False
        else:
            if token in self._mock_tokens:
                del self._mock_tokens[token]
                return True
            return False

    def register_agent(self, install_token: str, device_hash: str, hostname: str, os_info: Dict[str, Any]) -> Optional[str]:
        """Exchanges install token for permanent agent token (stored only as SHA-256 hash)."""
        if not self.verify_install_token(install_token):
            return None

        perm_token = secrets.token_hex(32)
        token_h = hash_token(perm_token)
        now_iso = datetime.now(timezone.utc).isoformat()

        agent_devices_col = self.get_collection("agent_devices")
        hosts_col = self.get_collection("hosts")

        device_doc = {
            "deviceHash": device_hash,
            "tokenHash": token_h,
            "hostname": hostname,
            "osInfo": os_info,
            "enrolledAt": now_iso,
            "lastSeen": now_iso
        }

        if agent_devices_col is not None:
            agent_devices_col.update_one({"deviceHash": device_hash}, {"$set": device_doc}, upsert=True)
            if hosts_col is not None:
                hosts_col.update_one(
                    {"deviceHash": device_hash},
                    {
                        "$set": {
                            "deviceHash": device_hash,
                            "hostname": hostname,
                            "osVersion": os_info.get("osVersion", "Windows"),
                            "osBuild": os_info.get("osBuild", ""),
                            "arch": os_info.get("arch", "x64"),
                            "lastSeen": now_iso,
                            "status": "ENROLLED"
                        }
                    },
                    upsert=True
                )
        else:
            self._mock_hosts[device_hash] = device_doc

        return perm_token

    def authenticate_agent(self, device_hash: str, permanent_token: str) -> bool:
        """Verifies agent's permanent token against the stored SHA-256 hash."""
        token_h = hash_token(permanent_token)
        agent_devices_col = self.get_collection("agent_devices")

        if agent_devices_col is not None:
            rec = agent_devices_col.find_one({"deviceHash": device_hash, "tokenHash": token_h})
            return rec is not None
        else:
            mock_dev = self._mock_hosts.get(device_hash)
            return mock_dev is not None and mock_dev.get("tokenHash") == token_h

    def request_manual_scan(self, device_hash: Optional[str] = None):
        """Called when user clicks 'Scan now' in the UI."""
        if device_hash:
            self._manual_scan_triggers.add(device_hash)
        else:
            self._manual_scan_triggers.add("ALL")

    def execute_local_host_scan(self) -> Dict[str, Any]:
        """
        Executes a real-time host audit when user clicks 'Scan Now' on localhost.
        Directly scans Windows Registry, AppX packages, ports, and OS patch levels,
        and saves findings immediately into MongoDB without waiting for polling.
        """
        try:
            import sys
            scanner_dir = os.path.abspath(
                os.path.join(os.path.dirname(__file__), "..", "..", "..", "scanner")
            )
            for s_candidate in [scanner_dir, "/app/scanner", os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "scanner"))]:
                if os.path.exists(s_candidate) and s_candidate not in sys.path:
                    sys.path.insert(0, s_candidate)
            import sentinel_agent

            hosts_col = self.get_collection("hosts")
            device_hash = None
            hostname = None
            if hosts_col is not None:
                last_host = hosts_col.find_one({}, sort=[("lastSeen", -1)])
                if last_host:
                    device_hash = last_host.get("deviceHash")
                    hostname = last_host.get("hostname")

            if not device_hash:
                device_hash = sentinel_agent.get_machine_hash()

            report = sentinel_agent.collect_full_scan_report("http://localhost:8080", "LOCAL_TRIGGERED")
            report["deviceHash"] = device_hash
            if hostname:
                report["hostname"] = hostname

            summary = self.ingest_agent_report(report)
            return {"status": "scanned", "summary": summary}
        except Exception as e:
            self.request_manual_scan()
            return {"status": "queued", "message": f"Scan queued (background poll): {e}"}

    def should_agent_scan(self, device_hash: str) -> Dict[str, Any]:
        """Server-side decision: should scanner run a new scan right now?"""
        # 1. Manual trigger
        if "ALL" in self._manual_scan_triggers or device_hash in self._manual_scan_triggers:
            self._manual_scan_triggers.discard(device_hash)
            self._manual_scan_triggers.discard("ALL")
            return {"shouldScan": True, "reason": "User clicked Scan Now in Threat Advisor"}

        # 2. Check last scan time
        hosts_col = self.get_collection("hosts")
        if hosts_col is not None:
            host = hosts_col.find_one({"deviceHash": device_hash})
            if not host or not host.get("lastScanTime"):
                return {"shouldScan": True, "reason": "First scan on enrolled device"}

            try:
                last_scan = datetime.fromisoformat(host["lastScanTime"].replace("Z", "+00:00"))
                if (datetime.now(timezone.utc) - last_scan).total_seconds() > 900:  # 15 minutes
                    return {"shouldScan": True, "reason": "Last scan older than 15 minutes"}
            except Exception:
                return {"shouldScan": True, "reason": "Scan timestamp refresh required"}

        return {"shouldScan": False, "reason": "Idle; scan up to date"}

    def ingest_agent_report(self, report: Dict[str, Any]) -> Dict[str, Any]:
        """Processes scanner results and performs deterministic CPE version checks."""
        device_hash = report.get("deviceHash")
        now_iso = datetime.now(timezone.utc).isoformat()

        hosts_col = self.get_collection("hosts")
        findings_col = self.get_collection("findings")
        device_checks_col = self.get_collection("device_checks")
        threats_col = self.get_collection("threats")

        # 1. Update host record
        host_doc = {
            "deviceHash": device_hash,
            "lastScanTime": now_iso,
            "lastSeen": now_iso,
            "osBuild": report.get("osBuild"),
            "hotfixesCount": len(report.get("hotfixes", [])),
            "installedProgramsCount": len(report.get("installedPrograms", [])),
            "storeAppsCount": len(report.get("storeApps", [])),
            "securitySettings": report.get("securitySettings", {}),
            "listeningPorts": report.get("listeningPorts", []),
            "installedPrograms": report.get("installedPrograms", []),
            "storeApps": report.get("storeApps", []),
            "steamGames": report.get("steamGames", []),
            "status": "ACTIVE_SCANNED"
        }

        if hosts_col is not None:
            hosts_col.update_one({"deviceHash": device_hash}, {"$set": host_doc}, upsert=True)
        else:
            self._mock_hosts[device_hash] = host_doc

        # 2. Retrieve threats to check
        if threats_col is not None:
            threats = list(threats_col.find({}))
        else:
            threats = SNAPSHOT_THREATS

        affected_count = 0
        patched_count = 0
        not_affected_count = 0
        checks_list = []

        for t in threats:
            check_result = evaluate_cve_against_host(t, report)
            check_result["deviceHash"] = device_hash
            check_result["evaluatedAt"] = now_iso
            checks_list.append(check_result)

            verdict = check_result["verdict"]
            if verdict == "AFFECTED":
                affected_count += 1
            elif verdict == "PATCHED":
                patched_count += 1
            else:
                not_affected_count += 1

            if device_checks_col is not None:
                device_checks_col.update_one(
                    {"deviceHash": device_hash, "cveId": check_result["cveId"]},
                    {"$set": check_result},
                    upsert=True
                )

        summary = {
            "deviceHash": device_hash,
            "totalChecks": len(checks_list),
            "affectedCount": affected_count,
            "patchedCount": patched_count,
            "notAffectedCount": not_affected_count,
            "lastScanTime": now_iso,
            "checks": checks_list
        }

        return summary

    def get_latest_host_summary(self, device_hash: Optional[str] = None) -> Optional[Dict[str, Any]]:
        """Retrieves host scan summary and verdict counts for the 'My System' panel."""
        hosts_col = self.get_collection("hosts")
        device_checks_col = self.get_collection("device_checks")

        host = None
        if hosts_col is not None:
            if device_hash:
                host = hosts_col.find_one({"deviceHash": device_hash}, {"_id": 0})
            else:
                host = hosts_col.find_one(sort=[("lastScanTime", -1)], projection={"_id": 0})

        if not host:
            # Fallback mock for demo if no live scanner has run yet
            return {
                "enrolled": False,
                "deviceHash": "No scanner enrolled yet",
                "hostname": "Local Machine",
                "osBuild": "Pending scan",
                "affectedCount": 0,
                "patchedCount": 0,
                "notAffectedCount": 0,
                "findings": [],
                "installCommand": "powershell -ExecutionPolicy Bypass -Command \"irm http://localhost:8080/install.ps1 | iex\""
            }

        d_hash = host.get("deviceHash")
        checks = []
        if device_checks_col is not None and d_hash:
            checks = list(device_checks_col.find({"deviceHash": d_hash}, {"_id": 0}))

        aff = sum(1 for c in checks if c.get("verdict") == "AFFECTED")
        pat = sum(1 for c in checks if c.get("verdict") == "PATCHED")
        not_aff = sum(1 for c in checks if c.get("verdict") == "NOT AFFECTED")

        return {
            "enrolled": True,
            "deviceHash": d_hash,
            "hostname": host.get("hostname", "Windows Host"),
            "osBuild": host.get("osBuild", "N/A"),
            "lastScanTime": host.get("lastScanTime"),
            "programsCount": host.get("installedProgramsCount", 0),
            "installedPrograms": host.get("installedPrograms", []),
            "storeApps": host.get("storeApps", []),
            "steamGames": host.get("steamGames", []),
            "securitySettings": host.get("securitySettings", {}),
            "affectedCount": aff,
            "patchedCount": pat,
            "notAffectedCount": not_aff,
            "findings": checks,
            "installCommand": "powershell -ExecutionPolicy Bypass -Command \"irm http://localhost:8080/install.ps1 | iex\""
        }


agent_service = AgentService()
