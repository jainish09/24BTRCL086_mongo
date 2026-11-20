from fastapi import APIRouter, Query, HTTPException
from typing import Optional
from database import get_collection
from bson import ObjectId
import re

router = APIRouter(prefix="/reports", tags=["Threat Reports"])

@router.get("/count")
def get_reports_count():
    coll = get_collection()
    if coll is not None:
        try:
            count = coll.count_documents({})
            latest_doc = coll.find_one(sort=[("year", -1)])
            latest_year = latest_doc.get("year", 2026) if latest_doc else 2026
            return {
                "totalReports": count,
                "latestYear": latest_year,
                "connected": True
            }
        except Exception as e:
            return {"totalReports": 0, "latestYear": 2026, "connected": False, "error": str(e)}
    return {
        "totalReports": 0,
        "latestYear": 2026,
        "connected": False,
        "note": "Awaiting MongoDB Atlas Connection"
    }

@router.get("")
def get_reports(
    search: Optional[str] = Query(None, description="Search term in title, organization, description"),
    year: Optional[int] = Query(None, description="Filter by year"),
    threatType: Optional[str] = Query(None, description="Filter by Threat Type"),
    category: Optional[str] = Query(None, description="Filter by Category"),
    severity: Optional[str] = Query(None, description="Filter by Severity (e.g., Critical, High, Medium, Low)"),
    page: int = Query(1, ge=1),
    limit: int = Query(10, ge=1, le=100),
    sort_by: str = Query("createdAt", description="Field to sort by"),
    order: str = Query("desc", description="asc or desc")
):
    coll = get_collection()
    if coll is None:
        return {
            "data": [],
            "page": page,
            "limit": limit,
            "total": 0,
            "totalPages": 0,
            "connected": False,
            "message": "MongoDB is not connected. Configure MONGODB_URI in backend/.env"
        }

    query = {}
    if search:
        regex = re.compile(search, re.IGNORECASE)
        query["$or"] = [
            {"title": regex},
            {"organization": regex},
            {"description": regex},
            {"reportId": regex},
            {"source": regex}
        ]
    if year:
        query["year"] = year
    
    cat_filter = category or threatType
    if cat_filter and cat_filter.lower() != "all":
        query["threatType"] = {"$regex": f"^{re.escape(cat_filter)}$", "$options": "i"}
        
    if severity and severity.lower() != "all":
        query["severity"] = severity

    sort_direction = -1 if order.lower() == "desc" else 1
    total = coll.count_documents(query)
    skip = (page - 1) * limit
    
    cursor = coll.find(query).sort(sort_by, sort_direction).skip(skip).limit(limit)
    
    reports = []
    for doc in cursor:
        doc["_id"] = str(doc["_id"])
        reports.append(doc)

    return {
        "data": reports,
        "page": page,
        "limit": limit,
        "total": total,
        "totalPages": (total + limit - 1) // limit if total > 0 else 0,
        "connected": True
    }

@router.get("/{id}")
def get_report_by_id(id: str):
    coll = get_collection()
    if coll is None:
        raise HTTPException(status_code=503, detail="Database disconnected")

    doc = coll.find_one({"reportId": id})
    if not doc and ObjectId.is_valid(id):
        doc = coll.find_one({"_id": ObjectId(id)})

    if not doc:
        raise HTTPException(status_code=404, detail="Threat report not found")

    doc["_id"] = str(doc["_id"])
    return doc
