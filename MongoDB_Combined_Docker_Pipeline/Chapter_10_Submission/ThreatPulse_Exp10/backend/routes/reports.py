"""
ThreatPulse SOC Platform - Threat Intelligence Feed & Report Routes
Provides threat feeds with tier-based limit enforcement:
- Free Plan: Max 15 items, redacted raw BSON telemetry
- Analyst / Pro: Unrestricted feeds, full MITRE mappings & raw observables
"""

from fastapi import APIRouter, HTTPException, Depends, Request
from typing import Optional, List
from bson import ObjectId
import datetime

from database import col_reports, col_subscriptions
from auth import get_current_user
from config import PLANS

router = APIRouter(prefix="/api/reports", tags=["reports"])


@router.get("/feed")
def get_threat_feed(request: Request, limit: int = 20, severity: Optional[str] = None):
    """
    Returns threat intelligence feed with tier-based limit gating.
    Public visitors get 5 items. Free users get up to 15. Plus/Pro get up to requested limit.
    """
    user = None
    try:
        user = get_current_user(request)
    except Exception:
        user = None

    if user:
        user_id = user["_id"]
        sub = col_subscriptions().find_one({"user_id": user_id})
        plan_key = sub.get("plan", "free") if sub else "free"
    else:
        plan_key = "public"

    plan_meta = PLANS.get(plan_key, PLANS["free"])
    tier_max = plan_meta["limits"]["max_feed_preview"] if plan_key in PLANS else 5
    effective_limit = min(limit, tier_max)

    query = {}
    if severity:
        query["severity"] = severity.upper()

    reports = list(col_reports().find(query, {"_id": 0}).sort("published_at", -1).limit(effective_limit))

    # Format dates and apply BSON redaction if on Free/Public plan
    allow_raw_bson = plan_meta.get("limits", {}).get("raw_bson_access", False) if plan_key in PLANS else False

    sanitized = []
    for r in reports:
        item = dict(r)
        if "published_at" in item and isinstance(item["published_at"], datetime.datetime):
            item["published_at"] = item["published_at"].isoformat()

        if not allow_raw_bson:
            # Redact raw technical IOC telemetry for free/public users
            if "iocs" in item and len(item["iocs"]) > 1:
                item["iocs"] = [item["iocs"][0]]  # only show 1 preview IOC
                item["iocs_redacted_count"] = len(r.get("iocs", [])) - 1
                item["upgrade_required_for_full_iocs"] = True
        sanitized.append(item)

    return {
        "status": "success",
        "current_tier": plan_key,
        "tier_limit": tier_max,
        "count": len(sanitized),
        "reports": sanitized
    }


@router.get("/stats")
def get_feed_stats():
    """
    Summary metrics for SOC dashboard HUD.
    """
    reports_col = col_reports()
    total = reports_col.count_documents({})
    critical = reports_col.count_documents({"severity": "CRITICAL"})
    high = reports_col.count_documents({"severity": "HIGH"})
    
    # Calculate unique IOC count
    pipeline = [
        {"$unwind": "$iocs"},
        {"$group": {"_id": "$iocs.value"}},
        {"$count": "total_iocs"}
    ]
    ioc_res = list(reports_col.aggregate(pipeline))
    ioc_count = ioc_res[0]["total_iocs"] if ioc_res else 0

    return {
        "status": "success",
        "total_threat_reports": total,
        "critical_incidents": critical,
        "high_incidents": high,
        "active_iocs_tracked": ioc_count,
        "system_status": "MONITORING_ACTIVE"
    }


@router.get("/{report_id}")
def get_report_detail(report_id: str, request: Request):
    """
    Retrieves full threat report.
    """
    rep = col_reports().find_one({"report_id": report_id}, {"_id": 0})
    if not rep:
        raise HTTPException(status_code=404, detail="Threat report not found")

    if "published_at" in rep and isinstance(rep["published_at"], datetime.datetime):
        rep["published_at"] = rep["published_at"].isoformat()

    return {"status": "success", "report": rep}
