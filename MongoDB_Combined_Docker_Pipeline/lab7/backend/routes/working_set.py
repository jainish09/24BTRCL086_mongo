from fastapi import APIRouter
from database import get_database, get_collection, get_wiredtiger_stats

router = APIRouter(prefix="/working-set", tags=["Working Set Analysis"])

@router.get("")
def get_working_set_analysis():
    db = get_database()
    coll = get_collection()
    
    # Lab defaults
    doc_count = 100000
    avg_doc_size_bytes = 2048  # ~2 KB
    total_data_size_bytes = doc_count * avg_doc_size_bytes  # ~200 MB
    
    actual_count = 0
    actual_size_bytes = 0
    is_live = False

    if db is not None and coll is not None:
        try:
            stats = db.command("collStats", coll.name)
            actual_count = stats.get("count", 0)
            actual_size_bytes = stats.get("size", 0)
            avg_size = stats.get("avgObjSize", 2048)
            if actual_count > 0:
                doc_count = actual_count
                avg_doc_size_bytes = avg_size
                total_data_size_bytes = actual_size_bytes
                is_live = True
        except Exception:
            pass

    wt_stats = get_wiredtiger_stats()
    cache_max_bytes = wt_stats["maxCacheBytes"] if wt_stats else (1024 * 1024 * 1024)
    cache_current_bytes = wt_stats["currentCacheBytes"] if wt_stats else 0
    
    # Percentage of working set that fits in max cache & currently in cache
    pct_of_ws_in_cache = round(min(100.0, (cache_current_bytes / total_data_size_bytes * 100.0)), 2) if total_data_size_bytes > 0 else 0.0
    working_set_to_cache_ratio = round((total_data_size_bytes / cache_max_bytes * 100.0), 2) if cache_max_bytes > 0 else 0.0

    return {
        "testDocumentsCount": doc_count,
        "approxDocSizeBytes": avg_doc_size_bytes,
        "approxDocSizeKB": round(avg_doc_size_bytes / 1024, 2),
        "totalWorkingSizeBytes": total_data_size_bytes,
        "totalWorkingSizeMB": round(total_data_size_bytes / (1024 * 1024), 2),
        "cacheMaxMB": round(cache_max_bytes / (1024 * 1024), 2),
        "cacheCurrentMB": round(cache_current_bytes / (1024 * 1024), 2),
        "percentageInCache": pct_of_ws_in_cache,
        "workingSetToCacheRatio": working_set_to_cache_ratio,
        "explanation": "The working set represents the data actively accessed by the workload. If the working set is larger than available cache, MongoDB may need to evict data and read it from disk.",
        "labBenchmark": {
            "targetDocuments": 100000,
            "targetDocSizeKB": 2.0,
            "estimatedWorkingSetMB": 195.31
        },
        "isLiveCollection": is_live
    }
