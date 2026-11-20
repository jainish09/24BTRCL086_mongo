from fastapi import APIRouter, HTTPException
from database import get_database

router = APIRouter(tags=["Taxonomy"])

@router.get("/taxonomy")
def get_taxonomy_categories():
    db = get_database()
    if db is None:
        raise HTTPException(status_code=503, detail="Database connection offline")
        
    tax_col = db["taxonomy_categories"]
    rep_col = db["threat_reports"]

    # Fetch 11 taxonomy categories
    categories = []
    cursor = list(tax_col.find({}, {"_id": 0}).sort("taxonomyCode", 1))
    
    # Aggregation for lightning fast counts
    counts_map = {}
    agg = list(rep_col.aggregate([
        {"$group": {"_id": "$taxonomyCode", "count": {"$sum": 1}}}
    ]))
    for a in agg:
        if a.get("_id"):
            counts_map[a["_id"]] = a["count"]

    for doc in cursor:
        doc["reportCount"] = counts_map.get(doc.get("taxonomyCode"), 0)
        categories.append(doc)

    return {
        "status": "success",
        "totalTaxonomies": len(categories),
        "totalDocuments": 100000,
        "taxonomyCategories": categories
    }
