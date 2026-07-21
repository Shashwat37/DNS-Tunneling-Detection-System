"""
Results router — runs detection on a completed upload and returns analysis data.
"""
import io
import math
from collections import Counter

import pandas as pd
from bson import ObjectId
from fastapi import APIRouter, Depends, HTTPException, Response
from fastapi.responses import StreamingResponse

from app.db import get_db
from app.dependencies import get_current_user
from app.detection import analyze

router = APIRouter(prefix="/results", tags=["results"])


async def _get_upload_doc(upload_id: str, user_id: str, db):
    try:
        doc = await db.uploads.find_one({"_id": ObjectId(upload_id)})
    except Exception:
        raise HTTPException(status_code=404, detail="Upload not found")
    if not doc or doc.get("user_id") != user_id:
        raise HTTPException(status_code=404, detail="Upload not found")
    return doc


async def _get_or_run_analysis(upload_id: str, upload_doc: dict, db) -> list[dict]:
    """
    Return cached per-row results from MongoDB, or run detection and cache them.
    """
    cached = await db.results.find_one({"upload_id": upload_id})
    if cached:
        return cached["rows"]

    # Re-fetch raw CSV bytes stored at upload time? We stored metadata only.
    # Instead: re-run from the raw_csv field if present, else return error.
    raw_csv = upload_doc.get("raw_csv")
    filename = upload_doc.get("filename", "upload.csv")
    if not raw_csv:
        raise HTTPException(
            status_code=400,
            detail="Raw file not stored — re-upload to trigger analysis.",
        )

    from app.normalizer import detect_and_normalize  # local import avoids circular
    df, _ = detect_and_normalize(raw_csv, filename)

    result_df = analyze(df)

    rows = []
    for _, row in result_df.iterrows():
        rows.append(
            {
                "domain": str(row.get("domain", "")),
                "timestamp": str(row.get("timestamp", "")),
                "query_type": str(row.get("query_type", "")),
                "query_length": int(row.get("query_length", 0)),
                "subdomain_count": int(row.get("subdomain_count", 0)),
                "response_size": int(row.get("response_size", 0)),
                "score": int(row.get("score", 0)),
                "label": str(row.get("label", "Normal")),
                "if_anomaly": bool(row.get("if_anomaly", False)),
                "feat_subdomain_entropy": round(float(row.get("feat_subdomain_entropy", 0)), 4),
            }
        )

    await db.results.insert_one({"upload_id": upload_id, "rows": rows})
    await db.uploads.update_one(
        {"_id": ObjectId(upload_id)}, {"$set": {"status": "done"}}
    )
    return rows


def _compute_summary(rows: list[dict], filename: str, uploaded_at, detected_format: str = "") -> dict:
    total = len(rows)
    suspicious = sum(1 for r in rows if r["label"] == "Suspicious")
    normal = total - suspicious

    # Top suspicious domains (by count)
    sus_domains = Counter(r["domain"] for r in rows if r["label"] == "Suspicious")
    top_suspicious = [{"domain": d, "count": c} for d, c in sus_domains.most_common(10)]

    # Entropy distribution buckets (0-1, 1-2, 2-3, 3+)
    buckets = {"0-1": 0, "1-2": 0, "2-3": 0, "3+": 0}
    for r in rows:
        e = r["feat_subdomain_entropy"]
        if e < 1:
            buckets["0-1"] += 1
        elif e < 2:
            buckets["1-2"] += 1
        elif e < 3:
            buckets["2-3"] += 1
        else:
            buckets["3+"] += 1
    entropy_dist = [{"range": k, "count": v} for k, v in buckets.items()]

    # Query volume over time (group by hour)
    time_series: dict[str, int] = {}
    for r in rows:
        ts = r["timestamp"][:13] if len(r["timestamp"]) >= 13 else r["timestamp"][:10]
        time_series[ts] = time_series.get(ts, 0) + 1
    volume_over_time = [
        {"time": k, "count": v}
        for k, v in sorted(time_series.items())
    ]

    # Query type distribution
    qtype_counts: dict[str, int] = {}
    for r in rows:
        qt = r["query_type"]
        if qt and qt.lower() not in ("nan", "none", ""):
            qtype_counts[qt] = qtype_counts.get(qt, 0) + 1
    query_type_dist = [{"type": k, "count": v} for k, v in sorted(qtype_counts.items(), key=lambda x: -x[1])]

    return {
        "filename": filename,
        "uploaded_at": uploaded_at.isoformat() if hasattr(uploaded_at, "isoformat") else str(uploaded_at),
        "total": total,
        "suspicious": suspicious,
        "normal": normal,
        "suspicious_pct": round(suspicious / total * 100, 1) if total else 0,
        "top_suspicious_domains": top_suspicious,
        "entropy_distribution": entropy_dist,
        "volume_over_time": volume_over_time,
        "query_type_distribution": query_type_dist,
        "detected_format": detected_format,
    }


@router.get("/{upload_id}")
async def get_results(
    upload_id: str,
    page: int = 1,
    page_size: int = 50,
    label_filter: str = "",
    current_user: dict = Depends(get_current_user),
):
    """Return summary stats + paginated per-row results for an upload."""
    db = get_db()
    upload_doc = await _get_upload_doc(upload_id, str(current_user["_id"]), db)
    rows = await _get_or_run_analysis(upload_id, upload_doc, db)

    # Filter
    filtered = [r for r in rows if not label_filter or r["label"] == label_filter]

    # Sort: suspicious first by default
    filtered.sort(key=lambda r: -r["score"])

    # Paginate
    total_filtered = len(filtered)
    start = (page - 1) * page_size
    page_rows = filtered[start : start + page_size]

    summary = _compute_summary(
        rows,
        upload_doc.get("filename", ""),
        upload_doc.get("uploaded_at", ""),
        upload_doc.get("detected_format", ""),
    )

    return {
        "summary": summary,
        "pagination": {
            "page": page,
            "page_size": page_size,
            "total": total_filtered,
            "total_pages": math.ceil(total_filtered / page_size) if total_filtered else 1,
        },
        "rows": page_rows,
    }


@router.get("/{upload_id}/export")
async def export_csv(
    upload_id: str,
    current_user: dict = Depends(get_current_user),
):
    """Stream a CSV of all analysis results for this upload."""
    db = get_db()
    upload_doc = await _get_upload_doc(upload_id, str(current_user["_id"]), db)
    rows = await _get_or_run_analysis(upload_id, upload_doc, db)

    if not rows:
        raise HTTPException(status_code=404, detail="No results to export")

    df = pd.DataFrame(rows)
    csv_bytes = df.to_csv(index=False).encode("utf-8")

    filename = upload_doc.get("filename", "results").replace(".csv", "") + "_analyzed.csv"
    return StreamingResponse(
        io.BytesIO(csv_bytes),
        media_type="text/csv",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )
