"""
ThreatPulse SOC Platform - Lab Runner API Routes.
Provides endpoints for monitoring and running Labs 7, 8, and 9.
Supports both direct host execution and container-to-host runner delegation.
"""

import os
import sys
import json
import logging
import urllib.request
import urllib.error
from typing import Optional, Dict, Any, List
from fastapi import APIRouter, HTTPException, Query, Response

from lab_executor import executor

logger = logging.getLogger("threat_intel.routes.labs")

router = APIRouter(prefix="/labs", tags=["Lab Runner"])

# Cache for discovered host runner URL
_active_host_runner_url: Optional[str] = None


def get_candidate_host_runner_urls() -> List[str]:
    """Returns possible URLs where the host runner might be listening."""
    urls = []
    env_url = os.environ.get("HOST_RUNNER_URL")
    if env_url:
        urls.append(env_url.rstrip("/"))
    # Common Docker Desktop host routes
    urls.extend([
        "http://172.29.224.1:8001",
        "http://10.171.94.247:8001",
        "http://host.docker.internal:8001",
        "http://127.0.0.1:8001",
        "http://localhost:8001"
    ])
    return urls


def ping_host_runner(url: str, timeout: float = 1.0) -> bool:
    """Checks if a host runner is responsive at the given URL."""
    try:
        req = urllib.request.Request(f"{url}/ping", headers={"User-Agent": "ThreatPulse-Backend"})
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            if resp.status == 200:
                data = json.loads(resp.read().decode())
                return data.get("service") == "HostLabRunner"
    except Exception:
        pass
    return False


def get_active_host_runner() -> Optional[str]:
    """Finds and caches the active host runner URL."""
    global _active_host_runner_url
    if _active_host_runner_url and ping_host_runner(_active_host_runner_url, timeout=0.5):
        return _active_host_runner_url

    for candidate in get_candidate_host_runner_urls():
        if ping_host_runner(candidate, timeout=0.8):
            _active_host_runner_url = candidate
            return candidate

    _active_host_runner_url = None
    return None


def forward_to_host_runner(method: str, path: str, body: Optional[dict] = None) -> Dict[str, Any]:
    """Forwards a request to the host runner service."""
    runner_url = get_active_host_runner()
    if not runner_url:
        raise HTTPException(
            status_code=503,
            detail={
                "message": "Host Lab Runner is not running. Start 'start-host-runner.bat' on your Windows machine to run Docker-based labs.",
                "hostRunnerRequired": True
            }
        )

    url = f"{runner_url}{path}"
    data = json.dumps(body).encode() if body else None
    headers = {"Content-Type": "application/json", "User-Agent": "ThreatPulse-Backend"}
    req = urllib.request.Request(url, data=data, headers=headers, method=method)

    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            return json.loads(resp.read().decode())
    except urllib.error.HTTPError as e:
        err_body = e.read().decode()
        try:
            parsed = json.loads(err_body)
        except Exception:
            parsed = {"error": err_body}
        raise HTTPException(status_code=e.code, detail=parsed)
    except Exception as e:
        raise HTTPException(status_code=502, detail=f"Failed communicating with host runner: {e}")


@router.get("/status")
def get_lab_status():
    """
    Returns the comprehensive status of Lab 7, 8, 9, system health, and execution state.
    """
    docker_direct = executor.check_docker()
    runner_url = get_active_host_runner()
    host_runner_ok = runner_url is not None

    # If host runner is active and local docker is not, fetch state from host runner
    if not docker_direct and host_runner_ok:
        try:
            host_status = forward_to_host_runner("GET", "/status")
            host_status["system"]["hostRunnerAvailable"] = True
            host_status["system"]["hostRunnerUrl"] = runner_url
            return host_status
        except Exception:
            pass

    # Otherwise use local executor status
    status = executor.get_status()
    status["system"]["hostRunnerAvailable"] = host_runner_ok
    status["system"]["hostRunnerUrl"] = runner_url
    return status


@router.get("/logs")
def get_execution_logs(since: int = Query(0, description="Log index to start from")):
    """
    Retrieves execution logs for live streaming in the frontend.
    """
    docker_direct = executor.check_docker()
    runner_url = get_active_host_runner()

    if not docker_direct and runner_url:
        try:
            return forward_to_host_runner("GET", f"/logs?since={since}")
        except Exception:
            pass

    return {"logs": executor.get_logs(since_idx=since)}


@router.get("/results/{lab_id}")
def get_lab_results(lab_id: str):
    """
    Retrieves detailed structured JSON results for a specific lab (7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, or 18).
    """
    if lab_id not in ("7", "8", "9", "10", "11", "12", "13", "14", "15", "16", "17", "18"):
        raise HTTPException(status_code=400, detail="Invalid lab ID. Must be 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, or 18.")

    docker_direct = executor.check_docker()
    runner_url = get_active_host_runner()

    if not docker_direct and runner_url:
        try:
            return forward_to_host_runner("GET", f"/results/{lab_id}")
        except Exception:
            pass

    status = executor.get_status()
    lab = status.get("labs", {}).get(lab_id)
    if not lab or not lab.get("results"):
        raise HTTPException(status_code=404, detail=f"No results available for Lab {lab_id}.")
    return lab


@router.post("/7/run")
def run_lab7():
    """
    Runs the Lab 7 verification workflow (FastAPI health, MongoDB connection, $bsonSize, WiredTiger).
    Delegates to host runner if running in container, or executes locally.
    """
    docker_direct = executor.check_docker()
    if docker_direct:
        res = executor.start_background_run("7")
        if res.get("busy"):
            raise HTTPException(status_code=409, detail=res)
        return res
    else:
        runner_url = get_active_host_runner()
        if runner_url:
            return forward_to_host_runner("POST", "/run/7")
        res = executor.start_background_run("7")
        if res.get("busy"):
            raise HTTPException(status_code=409, detail=res)
        return res


@router.post("/8/run")
def run_lab8():
    """
    Runs Lab 8 (Activity 8.1 replica set & Activity 8.2 failover monitor).
    """
    docker_direct = executor.check_docker()

    if docker_direct:
        res = executor.start_background_run("8")
        if res.get("busy"):
            raise HTTPException(status_code=409, detail=res)
        return res
    else:
        # Delegate to host runner
        return forward_to_host_runner("POST", "/run/8")


@router.post("/9/run")
def run_lab9():
    """
    Runs Lab 9 (setup, 9.1 write concern, 9.1-try journal latency, 9.2 network partition).
    """
    docker_direct = executor.check_docker()

    if docker_direct:
        res = executor.start_background_run("9")
        if res.get("busy"):
            raise HTTPException(status_code=409, detail=res)
        return res
    else:
        # Delegate to host runner
        return forward_to_host_runner("POST", "/run/9")


@router.post("/10/run")
def run_lab10():
    """
    Runs Lab 10 (Multi-Document ACID Transactions & Inventory).
    """
    docker_direct = executor.check_docker()

    if docker_direct:
        res = executor.start_background_run("10")
        if res.get("busy"):
            raise HTTPException(status_code=409, detail=res)
        return res
    else:
        runner_url = get_active_host_runner()
        if runner_url:
            return forward_to_host_runner("POST", "/run/10")
        res = executor.start_background_run("10")
        if res.get("busy"):
            raise HTTPException(status_code=409, detail=res)
        return res


@router.post("/11/run")
def run_lab11():
    """
    Runs Lab 11 (Horizontal Sharding & Query Routing).
    """
    docker_direct = executor.check_docker()

    if docker_direct:
        res = executor.start_background_run("11")
        if res.get("busy"):
            raise HTTPException(status_code=409, detail=res)
        return res
    else:
        runner_url = get_active_host_runner()
        if runner_url:
            return forward_to_host_runner("POST", "/run/11")
        res = executor.start_background_run("11")
        if res.get("busy"):
            raise HTTPException(status_code=409, detail=res)
        return res


@router.post("/12/run")
def run_lab12():
    """
    Runs Lab 12 (Database Security TLS & Scoped RBAC).
    """
    docker_direct = executor.check_docker()

    if docker_direct:
        res = executor.start_background_run("12")
        if res.get("busy"):
            raise HTTPException(status_code=409, detail=res)
        return res
    else:
        runner_url = get_active_host_runner()
        if runner_url:
            return forward_to_host_runner("POST", "/run/12")
        res = executor.start_background_run("12")
        if res.get("busy"):
            raise HTTPException(status_code=409, detail=res)
        return res


@router.post("/13/run")
def run_lab13():
    """
    Runs Lab 13 (Containers & Cloud: Docker, Replica Set, Failover, Prometheus, K8s, Atlas).
    """
    docker_direct = executor.check_docker()

    if docker_direct:
        res = executor.start_background_run("13")
        if res.get("busy"):
            raise HTTPException(status_code=409, detail=res)
        return res
    else:
        runner_url = get_active_host_runner()
        if runner_url:
            return forward_to_host_runner("POST", "/run/13")
        res = executor.start_background_run("13")
        if res.get("busy"):
            raise HTTPException(status_code=409, detail=res)
        return res


@router.post("/14/run")
def run_lab14():
    """
    Runs Lab 14 (Monitoring, Alerts & Backup Recovery).
    """
    docker_direct = executor.check_docker()

    if docker_direct:
        res = executor.start_background_run("14")
        if res.get("busy"):
            raise HTTPException(status_code=409, detail=res)
        return res
    else:
        runner_url = get_active_host_runner()
        if runner_url:
            return forward_to_host_runner("POST", "/run/14")
        res = executor.start_background_run("14")
        if res.get("busy"):
            raise HTTPException(status_code=409, detail=res)
        return res


@router.post("/15/run")
def run_lab15():
    """
    Runs Lab 15 (Multi-Tenant Case Management & Organisation Isolation).
    """
    docker_direct = executor.check_docker()

    if docker_direct:
        res = executor.start_background_run("15")
        if res.get("busy"):
            raise HTTPException(status_code=409, detail=res)
        return res
    else:
        runner_url = get_active_host_runner()
        if runner_url:
            return forward_to_host_runner("POST", "/run/15")
        res = executor.start_background_run("15")
        if res.get("busy"):
            raise HTTPException(status_code=409, detail=res)
        return res


@router.post("/16/run")
def run_lab16():
    """
    Runs Lab 16 (Cassandra & Neo4j Multi-Database Integration).
    """
    docker_direct = executor.check_docker()

    if docker_direct:
        res = executor.start_background_run("16")
        if res.get("busy"):
            raise HTTPException(status_code=409, detail=res)
        return res
    else:
        runner_url = get_active_host_runner()
        if runner_url:
            return forward_to_host_runner("POST", "/run/16")
        res = executor.start_background_run("16")
        if res.get("busy"):
            raise HTTPException(status_code=409, detail=res)
        return res


@router.post("/17/run")
def run_lab17():
    """
    Runs Lab 17 (Vector Search & RAG Threat Intelligence).
    """
    docker_direct = executor.check_docker()

    if docker_direct:
        res = executor.start_background_run("17")
        if res.get("busy"):
            raise HTTPException(status_code=409, detail=res)
        return res
    else:
        runner_url = get_active_host_runner()
        if runner_url:
            return forward_to_host_runner("POST", "/run/17")
        res = executor.start_background_run("17")
        if res.get("busy"):
            raise HTTPException(status_code=409, detail=res)
        return res


@router.post("/18/run")
def run_lab18():
    """
    Runs Lab 18 (Comparative Database Capstone - False-Positive Detection).
    """
    docker_direct = executor.check_docker()

    if docker_direct:
        res = executor.start_background_run("18")
        if res.get("busy"):
            raise HTTPException(status_code=409, detail=res)
        return res
    else:
        runner_url = get_active_host_runner()
        if runner_url:
            return forward_to_host_runner("POST", "/run/18")
        res = executor.start_background_run("18")
        if res.get("busy"):
            raise HTTPException(status_code=409, detail=res)
        return res



@router.post("/run-all")
def run_all_labs():
    """
    Runs Labs 7 through 13 sequentially.
    """
    docker_direct = executor.check_docker()

    if docker_direct:
        res = executor.start_background_run("all")
        if res.get("busy"):
            raise HTTPException(status_code=409, detail=res)
        return res
    else:
        # Delegate to host runner
        return forward_to_host_runner("POST", "/run/all")
