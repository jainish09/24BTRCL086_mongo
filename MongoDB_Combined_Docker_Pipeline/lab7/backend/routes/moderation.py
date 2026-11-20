"""
ThreatPulse SOC Platform - Moderator Alerts & Triage Router.
Provides GET /api/moderation/alerts and POST /api/moderation/alerts/ack
for operational alert triage by moderators and administrators.
"""

from datetime import datetime, timezone
from typing import Optional, Dict, Any, List
from fastapi import APIRouter, HTTPException, Depends, Request

from auth import require_moderator_or_admin
from config import CACHE_HIT_RATIO_WARNING_THRESHOLD, REPLICATION_LAG_WARNING_THRESHOLD
from routes.lab14 import _live_alerts, _alerts_lock

router = APIRouter(prefix="/moderation", tags=["Moderator Alerts & Operations"])


@router.get("/alerts")
def get_moderation_alerts(request: Request, user: Dict[str, Any] = Depends(require_moderator_or_admin)):
    """
    Returns list of open and recent WARNING/CRITICAL alerts for moderator review.
    Requires moderator or administrator authorization.
    """
    with _alerts_lock:
        alerts = list(_live_alerts)
        open_count = sum(1 for a in alerts if not a.get("acknowledged"))

    return {
        "status": "success",
        "openCount": open_count,
        "totalCount": len(alerts),
        "alerts": alerts,
        "warningThresholds": {
            "cacheHitRatio": CACHE_HIT_RATIO_WARNING_THRESHOLD,
            "replicationLagSeconds": REPLICATION_LAG_WARNING_THRESHOLD
        },
        "operator": {
            "name": user.get("name", "Security Moderator"),
            "role": user.get("role")
        }
    }


@router.post("/alerts/ack")
def acknowledge_alert(payload: Dict[str, Any], request: Request, user: Dict[str, Any] = Depends(require_moderator_or_admin)):
    """
    Acknowledges an alert by ID (or list of IDs), recording user identity and timestamp.
    Requires moderator or administrator authorization.
    """
    alert_id = payload.get("alertId")
    alert_ids = payload.get("alertIds", [alert_id] if alert_id else [])

    if not alert_ids or not any(alert_ids):
        raise HTTPException(status_code=400, detail={"error": "Must provide 'alertId' or 'alertIds' to acknowledge."})

    acknowledged_items = []
    now_iso = datetime.now(timezone.utc).isoformat()
    operator_name = user.get("name") or user.get("email") or "Operator"

    with _alerts_lock:
        for a in _live_alerts:
            if a["id"] in alert_ids or "all" in alert_ids:
                a["acknowledged"] = True
                a["acknowledgedAt"] = now_iso
                a["acknowledgedBy"] = operator_name
                acknowledged_items.append(a)

        open_count = sum(1 for a in _live_alerts if not a.get("acknowledged"))

    if not acknowledged_items:
        raise HTTPException(status_code=404, detail={"error": f"Alert(s) '{alert_ids}' not found."})

    return {
        "status": "success",
        "message": f"Successfully acknowledged {len(acknowledged_items)} alert(s).",
        "acknowledgedCount": len(acknowledged_items),
        "openCount": open_count,
        "acknowledgedAlerts": acknowledged_items
    }

