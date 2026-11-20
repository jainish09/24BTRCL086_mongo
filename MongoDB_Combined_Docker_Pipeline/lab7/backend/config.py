import os
from dotenv import load_dotenv

load_dotenv()

MONGODB_URI = os.getenv("MONGODB_URI", "mongodb://localhost:27017")
DB_NAME = os.getenv("DB_NAME", "threat_intel_db")
COLLECTION_NAME = os.getenv("COLLECTION_NAME", "threat_reports")
PORT = int(os.getenv("PORT", 8080))
HOST = os.getenv("HOST", "127.0.0.1")

# Admin and monitoring configurations
ADMIN_API_KEY = os.getenv("ADMIN_API_KEY", "threatpulse-soc-admin-secret-2026")
PROMETHEUS_URL = os.getenv("PROMETHEUS_URL", "http://127.0.0.1:9090")
GRAFANA_URL = os.getenv("GRAFANA_URL", "http://127.0.0.1:3013")
KUBERNETES_NAMESPACE = os.getenv("KUBERNETES_NAMESPACE", "default")

# Chapter 14: Monitoring & Backup configurations
BACKUP_STORAGE_DIR = os.getenv("BACKUP_STORAGE_DIR", os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "backups")))
BACKUP_RPO_TARGET_SEC = int(os.getenv("BACKUP_RPO_TARGET_SEC", 3600))  # 60m SLA
BACKUP_RTO_TARGET_SEC = int(os.getenv("BACKUP_RTO_TARGET_SEC", 300))   # 5m SLA
CACHE_HIT_RATIO_WARNING_THRESHOLD = float(os.getenv("CACHE_HIT_RATIO_WARNING_THRESHOLD", 80.0))  # 80%
REPLICATION_LAG_WARNING_THRESHOLD = float(os.getenv("REPLICATION_LAG_WARNING_THRESHOLD", 10.0))  # 10s


