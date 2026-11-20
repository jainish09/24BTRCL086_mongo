import os

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse

from routes.reports import router as reports_router
from routes.cache import router as cache_router
from routes.working_set import router as working_set_router
from routes.random_read import router as random_read_router
from routes.new_reports import router as new_reports_router
from routes.real_reports import router as real_reports_router
from routes.lab71 import router as lab71_router
from routes.taxonomy import router as taxonomy_router
from routes.labs import router as labs_router
from routes.lab13 import router as lab13_router
from routes.ops import router as ops_router
from routes.auth import router as auth_router
from routes.lab14 import router as lab14_router
from routes.moderation import router as moderation_router
from routes.cases import router as cases_router
from routes.lab16 import router as lab16_router
from routes.lab17 import router as lab17_router
from routes.lab18 import router as lab18_router
from routes.threat_advisor import router as threat_advisor_router

from database import get_database


app = FastAPI(
    title="MongoDB Lab 7.1 & 7.2 - Threat Intelligence & WiredTiger SOC Dashboard",
    description=(
        "SOC-grade dashboard and REST API for analyzing "
        "Lab 7.1 Schema ($bsonSize, Embedding vs Referencing) and "
        "Lab 7.2 Working Set & WiredTiger Cache Telemetry."
    ),
    version="2.0.0"
)


# Enable unrestricted CORS for frontend clients (LiveServer, localhost, 127.0.0.1)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)


# Register existing API routers
app.include_router(reports_router, prefix="/api")
app.include_router(cache_router, prefix="/api")
app.include_router(working_set_router, prefix="/api")
app.include_router(random_read_router, prefix="/api")
app.include_router(new_reports_router, prefix="/api")
app.include_router(real_reports_router, prefix="/api")

# Register Lab 7.1 & Taxonomy API routers
app.include_router(lab71_router, prefix="/api")
app.include_router(taxonomy_router, prefix="/api")
app.include_router(labs_router, prefix="/api")

# Register Chapter 13 & Admin Operations routers
app.include_router(lab13_router, prefix="/api")
app.include_router(ops_router, prefix="/api")
app.include_router(auth_router, prefix="/api")

# Register Chapter 14 & Moderation routers
app.include_router(lab14_router)
app.include_router(moderation_router, prefix="/api")

# Register Chapter 15: Multi-Tenant Case Management router
app.include_router(cases_router, prefix="/api")

# Register Chapter 16: Cassandra & Neo4j Multi-Database Integration router
app.include_router(lab16_router, prefix="/api")

# Register Chapter 17: Vector Search & RAG Threat Intelligence router
app.include_router(lab17_router, prefix="/api")

# Register Chapter 18: Comparative Capstone (Tri-DB False Positives) router
app.include_router(lab18_router, prefix="/api")

# Register Threat Advisor (LLM Chat & PC Scanner on MongoDB) router
app.include_router(threat_advisor_router)



@app.get("/api/health")
def health_check():
    db = get_database()

    return {
        "status": "online",
        "service": "Threat Intelligence SOC API",
        "mongoConnected": db is not None,
        "wiredTigerCacheMonitoring": "Active"
    }


# Serve frontend static files if present
frontend_dir = os.path.abspath(
    os.path.join(
        os.path.dirname(__file__),
        "..",
        "frontend"
    )
)

if os.path.exists(frontend_dir):
    css_dir = os.path.join(frontend_dir, "css")
    js_dir = os.path.join(frontend_dir, "js")
    img_dir = os.path.join(frontend_dir, "img")
    if os.path.exists(css_dir):
        app.mount("/css", StaticFiles(directory=css_dir), name="css")
    if os.path.exists(js_dir):
        app.mount("/js", StaticFiles(directory=js_dir), name="js")
    if os.path.exists(img_dir):
        app.mount("/img", StaticFiles(directory=img_dir), name="img")
    app.mount("/static", StaticFiles(directory=frontend_dir), name="static")

    NO_CACHE_HEADERS = {
        "Cache-Control": "no-cache, no-store, must-revalidate, max-age=0",
        "Pragma": "no-cache",
        "Expires": "0"
    }

    @app.get("/")
    def serve_index():
        return FileResponse(
            os.path.join(frontend_dir, "index.html"),
            headers=NO_CACHE_HEADERS
        )

    @app.get("/extras/lab8")
    def serve_lab8():
        return FileResponse(
            os.path.join(frontend_dir, "index.html"),
            headers=NO_CACHE_HEADERS
        )

    @app.get("/extras/lab9")
    def serve_lab9():
        return FileResponse(
            os.path.join(frontend_dir, "index.html"),
            headers=NO_CACHE_HEADERS
        )

    @app.get("/extras/lab10")
    def serve_lab10():
        return FileResponse(
            os.path.join(frontend_dir, "index.html"),
            headers=NO_CACHE_HEADERS
        )

    @app.get("/extras/lab11")
    def serve_lab11():
        return FileResponse(
            os.path.join(frontend_dir, "index.html"),
            headers=NO_CACHE_HEADERS
        )

    @app.get("/extras/lab12")
    def serve_lab12():
        return FileResponse(
            os.path.join(frontend_dir, "index.html"),
            headers=NO_CACHE_HEADERS
        )

    @app.get("/extras/lab13")
    def serve_lab13():
        return FileResponse(
            os.path.join(frontend_dir, "index.html"),
            headers=NO_CACHE_HEADERS
        )

    @app.get("/admin/ops")
    def serve_admin_ops():
        return FileResponse(
            os.path.join(frontend_dir, "index.html"),
            headers=NO_CACHE_HEADERS
        )

    @app.get("/extras/lab14")
    def serve_lab14():
        return FileResponse(
            os.path.join(frontend_dir, "index.html"),
            headers=NO_CACHE_HEADERS
        )

    @app.get("/moderation")
    def serve_moderation():
        return FileResponse(
            os.path.join(frontend_dir, "index.html"),
            headers=NO_CACHE_HEADERS
        )

    @app.get("/cases")
    def serve_cases():
        return FileResponse(
            os.path.join(frontend_dir, "index.html"),
            headers=NO_CACHE_HEADERS
        )

    @app.get("/extras/lab15")
    def serve_lab15():
        return FileResponse(
            os.path.join(frontend_dir, "index.html"),
            headers=NO_CACHE_HEADERS
        )

    @app.get("/extras/lab16")
    def serve_lab16():
        return FileResponse(
            os.path.join(frontend_dir, "index.html"),
            headers=NO_CACHE_HEADERS
        )

    @app.get("/ask")
    def serve_ask():
        return FileResponse(
            os.path.join(frontend_dir, "index.html"),
            headers=NO_CACHE_HEADERS
        )

    @app.get("/extras/lab17")
    def serve_lab17():
        return FileResponse(
            os.path.join(frontend_dir, "index.html"),
            headers=NO_CACHE_HEADERS
        )

    @app.get("/extras/lab18")
    def serve_lab18():
        return FileResponse(
            os.path.join(frontend_dir, "index.html"),
            headers=NO_CACHE_HEADERS
        )



if __name__ == "__main__":
    import uvicorn
    from config import HOST, PORT

    uvicorn.run(
        "main:app",
        host=HOST,
        port=PORT,
        reload=True
    )