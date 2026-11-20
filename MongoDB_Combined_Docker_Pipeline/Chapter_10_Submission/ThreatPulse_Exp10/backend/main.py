"""
ThreatPulse SOC Platform - Experiment 10 Backend
Multi-Document Transactions & Subscription SOC Platform
"""

import os
import logging
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
import datetime

from database import get_client, get_database
from seed_data import seed_database
from routes.auth_routes import router as auth_router
from routes.billing import router as billing_router
from routes.features import router as features_router
from routes.transfers import router as transfers_router
from routes.txn_lab import router as txn_lab_router
from routes.admin import router as admin_router
from routes.benchmark import router as benchmark_router
from routes.reports import router as reports_router

logger = logging.getLogger("threatpulse.main")
logging.basicConfig(level=logging.INFO)

app = FastAPI(
    title="ThreatPulse Exp 10 - Multi-Document Transactions SOC Platform",
    description="Cyber Threat Intelligence SaaS Platform powered by MongoDB Multi-Document Transactions on Replica Set rs0",
    version="10.0.0"
)

# CORS Middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Include API Routers
app.include_router(auth_router)
app.include_router(billing_router)
app.include_router(features_router)
app.include_router(transfers_router)
app.include_router(txn_lab_router)
app.include_router(admin_router)
app.include_router(benchmark_router)
app.include_router(reports_router)


@app.on_event("startup")
def on_startup():
    logger.info("Initializing ThreatPulse Exp 10 Application...")
    try:
        # Auto-seed if needed
        seed_database(force=False)
        logger.info("ThreatPulse Exp 10 database ready.")
    except Exception as e:
        logger.error(f"Startup seeding warning: {e}")


@app.get("/api/health")
def health_check():
    """
    Comprehensive Health Check for Experiment 10:
    Verifies database connectivity, replica set topology, primary status, and collection integrity.
    """
    client = get_client()
    db = get_database()
    
    # Check replica set status
    try:
        hello_doc = client.admin.command("hello")
        is_primary = hello_doc.get("isWritablePrimary", False) or hello_doc.get("ismaster", False)
        replica_set_name = hello_doc.get("setName", "standalone")
        hosts = hello_doc.get("hosts", [])
        primary_host = hello_doc.get("primary", "unknown")
    except Exception as e:
        raise HTTPException(status_code=503, detail=f"Database unreachable: {str(e)}")

    collection_names = db.list_collection_names()

    return {
        "status": "HEALTHY",
        "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "database": {
            "name": db.name,
            "connected": True,
            "replica_set": replica_set_name,
            "is_writable_primary": is_primary,
            "primary_node": primary_host,
            "active_hosts": hosts,
            "collections_count": len(collection_names),
            "multi_document_transactions_supported": bool(replica_set_name and replica_set_name != "standalone")
        },
        "soc_platform": {
            "version": "10.0.0",
            "experiment": "Experiment 10: Multi-Document Transactions",
            "features_active": [
                "10.1 Bank Transfer (Atomicity)",
                "10.1-try Transient Error Backoff Retry",
                "10.2 Anti-overselling Inventory Reservation",
                "10.2-bench Multi-worker Throughput Benchmarking",
                "Printable Invoices & Cryptographic Receipts",
                "Mathematical Conservation Auditing"
            ]
        }
    }


# Frontend Static Files Mount
frontend_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "frontend"))
if os.path.isdir(frontend_dir):
    app.mount("/static", StaticFiles(directory=frontend_dir), name="static")

    @app.get("/")
    def serve_frontend_index():
        index_file = os.path.join(frontend_dir, "index.html")
        if os.path.isfile(index_file):
            return FileResponse(index_file)
        return {"message": "ThreatPulse Exp 10 Backend API Online. Frontend index.html not yet built."}


if __name__ == "__main__":
    import uvicorn
    from config import HOST, PORT
    uvicorn.run("main:app", host=HOST, port=PORT, reload=True)
