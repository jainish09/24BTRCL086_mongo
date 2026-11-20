"""
Threat Advisor MongoDB Aggregation Pipeline Lifecycle Calculator.
Computes Active, Evolving, Anticipated, Resolved statuses using $dateDiff and $switch.
"""

from typing import Dict, Any, List
from datetime import datetime, timezone
import logging

logger = logging.getLogger("threat_intel.threat_advisor.lifecycle")


def build_lifecycle_aggregation_pipeline() -> List[Dict[str, Any]]:
    """
    Constructs the MongoDB aggregation pipeline to compute the lifecycle status
    directly inside MongoDB using $dateDiff against $$NOW and $switch.
    """
    return [
        {
            "$set": {
                "parsedDateAdded": {
                    "$cond": [
                        {"$and": [{"$ne": ["$kev.dateAdded", None]}, {"$ne": ["$kev.dateAdded", ""]}]},
                        {"$dateFromString": {"dateString": "$kev.dateAdded", "onError": None}},
                        None
                    ]
                },
                "parsedDueDate": {
                    "$cond": [
                        {"$and": [{"$ne": ["$kev.dueDate", None]}, {"$ne": ["$kev.dueDate", ""]}]},
                        {"$dateFromString": {"dateString": "$kev.dueDate", "onError": None}},
                        None
                    ]
                },
                "parsedPubDate": {
                    "$cond": [
                        {"$and": [{"$ne": ["$publishedDate", None]}, {"$ne": ["$publishedDate", ""]}]},
                        {"$dateFromString": {"dateString": "$publishedDate", "onError": None}},
                        None
                    ]
                }
            }
        },
        {
            "$set": {
                "daysSinceAdded": {
                    "$cond": [
                        {"$ne": ["$parsedDateAdded", None]},
                        {"$dateDiff": {"startDate": "$parsedDateAdded", "endDate": "$$NOW", "unit": "day"}},
                        9999
                    ]
                },
                "daysUntilDue": {
                    "$cond": [
                        {"$ne": ["$parsedDueDate", None]},
                        {"$dateDiff": {"startDate": "$$NOW", "endDate": "$parsedDueDate", "unit": "day"}},
                        -9999
                    ]
                },
                "daysSincePub": {
                    "$cond": [
                        {"$ne": ["$parsedPubDate", None]},
                        {"$dateDiff": {"startDate": "$parsedPubDate", "endDate": "$$NOW", "unit": "day"}},
                        9999
                    ]
                }
            }
        },
        {
            "$set": {
                "status": {
                    "$switch": {
                        "branches": [
                            # 1. Active: in KEV and added in last 90 days, or its fix due date is still ahead
                            {
                                "case": {
                                    "$and": [
                                        {"$eq": ["$kev.isKev", True]},
                                        {
                                            "$or": [
                                                {"$lte": ["$daysSinceAdded", 90]},
                                                {"$gte": ["$daysUntilDue", 0]}
                                            ]
                                        }
                                    ]
                                },
                                "then": "Active"
                            },
                            # 2. Evolving: in KEV within 3 years and (ransomware or EPSS >= 0.50); or not in KEV, >120 days old, EPSS >= 0.50
                            {
                                "case": {
                                    "$or": [
                                        {
                                            "$and": [
                                                {"$eq": ["$kev.isKev", True]},
                                                {"$lte": ["$daysSinceAdded", 1095]},
                                                {
                                                    "$or": [
                                                        {"$eq": ["$kev.knownRansomwareCampaignUse", True]},
                                                        {"$gte": ["$epss", 0.50]}
                                                    ]
                                                }
                                            ]
                                        },
                                        {
                                            "$and": [
                                                {"$ne": ["$kev.isKev", True]},
                                                {"$gte": ["$daysSincePub", 120]},
                                                {"$gte": ["$epss", 0.50]}
                                            ]
                                        }
                                    ]
                                },
                                "then": "Evolving"
                            },
                            # 3. Anticipated: not exploited, published in last 120 days, CVSS >= 7 or EPSS >= 0.05
                            {
                                "case": {
                                    "$and": [
                                        {"$ne": ["$kev.isKev", True]},
                                        {"$lte": ["$daysSincePub", 120]},
                                        {
                                            "$or": [
                                                {"$gte": ["$cvss", 7.0]},
                                                {"$gte": ["$epss", 0.05]}
                                            ]
                                        }
                                    ]
                                },
                                "then": "Anticipated"
                            }
                        ],
                        # 4. Resolved: exploited in past with low exploitation now, or old and never exploited
                        "default": "Resolved"
                    }
                }
            }
        },
        {
            "$unset": ["parsedDateAdded", "parsedDueDate", "parsedPubDate", "daysSinceAdded", "daysUntilDue", "daysSincePub"]
        }
    ]


def compute_python_fallback_status(cve: Dict[str, Any]) -> str:
    """
    Python fallback implementation of the exact same lifecycle rules
    for offline or local validation.
    """
    now = datetime.now(timezone.utc)
    kev = cve.get("kev", {})
    is_kev = kev.get("isKev", False)
    date_added_str = kev.get("dateAdded")
    due_date_str = kev.get("dueDate")
    pub_date_str = cve.get("publishedDate")
    ransomware = kev.get("knownRansomwareCampaignUse", False)
    epss = float(cve.get("epss", 0.0))
    cvss = float(cve.get("cvss", 0.0))

    days_since_added = 9999
    if date_added_str:
        try:
            d = datetime.fromisoformat(date_added_str.replace("Z", "+00:00"))
            days_since_added = (now - d).days
        except Exception:
            pass

    days_until_due = -9999
    if due_date_str:
        try:
            d = datetime.fromisoformat(due_date_str.replace("Z", "+00:00"))
            days_until_due = (d - now).days
        except Exception:
            pass

    days_since_pub = 9999
    if pub_date_str:
        try:
            d = datetime.fromisoformat(pub_date_str.replace("Z", "+00:00"))
            days_since_pub = (now - d).days
        except Exception:
            pass

    # 1. Active: in KEV and added in last 90 days, or its fix due date is still ahead
    if is_kev and (days_since_added <= 90 or days_until_due >= 0):
        return "Active"

    # 2. Evolving: in KEV within 3 years and (ransomware or EPSS >= 0.50); or not in KEV, older than 120 days, EPSS >= 0.50
    if (is_kev and days_since_added <= 1095 and (ransomware or epss >= 0.50)) or \
       (not is_kev and days_since_pub >= 120 and epss >= 0.50):
        return "Evolving"

    # 3. Anticipated: not exploited, published in last 120 days, CVSS >= 7 or EPSS >= 0.05
    if (not is_kev) and (days_since_pub <= 120) and (cvss >= 7.0 or epss >= 0.05):
        return "Anticipated"

    # 4. Resolved
    return "Resolved"
