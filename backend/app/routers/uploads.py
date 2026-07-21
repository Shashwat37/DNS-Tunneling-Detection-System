import io
from datetime import datetime, timezone

from bson import ObjectId
from fastapi import APIRouter, Depends, File, HTTPException, UploadFile, status

from app.db import get_db
from app.dependencies import get_current_user
from app.normalizer import ACCEPTED_EXTENSIONS, detect_and_normalize

router = APIRouter(prefix="/uploads", tags=["uploads"])

MAX_FILE_SIZE_BYTES = 50 * 1024 * 1024  # 50 MB hard cap


@router.post("", status_code=status.HTTP_201_CREATED)
async def upload_file(
    file: UploadFile = File(...),
    current_user: dict = Depends(get_current_user),
):
    """
    Accept a DNS log file in any supported format, auto-detect the format,
    normalize it to the standard schema, store metadata in MongoDB.

    Supported: DTDS CSV, Zeek dns.log, Suricata eve.json, AWS Route53,
               Windows DNS Debug, dnsmasq log, BIND named log, Generic CSV/TSV
    """
    db = get_db()

    # ── 1. File-level validation ─────────────────────────────────────────────
    if not file.filename:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="No filename provided",
        )

    ext = "." + file.filename.rsplit(".", 1)[-1].lower() if "." in file.filename else ""
    if ext not in ACCEPTED_EXTENSIONS:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=(
                f"File extension '{ext}' not supported. "
                f"Accepted: {', '.join(sorted(ACCEPTED_EXTENSIONS))}"
            ),
        )

    raw = await file.read()

    if len(raw) == 0:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="Uploaded file is empty",
        )
    if len(raw) > MAX_FILE_SIZE_BYTES:
        raise HTTPException(
            status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
            detail="File exceeds the 50 MB limit",
        )

    # ── 2. Auto-detect format + normalize ───────────────────────────────────
    try:
        df, detected_format = detect_and_normalize(raw, file.filename)
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=f"Could not parse file: {exc}",
        )
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=f"Unexpected parse error: {exc}",
        )

    if df.empty:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="File parsed successfully but contained no usable rows",
        )

    row_count = len(df)

    # ── 3. Store upload metadata + raw bytes ─────────────────────────────────
    doc = {
        "user_id": str(current_user["_id"]),
        "filename": file.filename,
        "detected_format": detected_format,
        "row_count": row_count,
        "status": "pending",
        "uploaded_at": datetime.now(timezone.utc),
        "raw_csv": raw,            # keep original bytes for detection re-run
    }
    result = await db.uploads.insert_one(doc)
    upload_id = str(result.inserted_id)

    return {
        "upload_id": upload_id,
        "filename": file.filename,
        "detected_format": detected_format,
        "row_count": row_count,
        "message": (
            f"Detected format: {detected_format}. "
            f"Uploaded {row_count} rows queued for analysis."
        ),
    }


@router.get("", tags=["uploads"])
async def list_uploads(current_user: dict = Depends(get_current_user)):
    """Return a list of past uploads for the current user."""
    db = get_db()
    cursor = db.uploads.find(
        {"user_id": str(current_user["_id"])},
        sort=[("uploaded_at", -1)],
    )
    uploads = []
    async for doc in cursor:
        uploads.append(
            {
                "upload_id": str(doc["_id"]),
                "filename": doc.get("filename", "unknown"),
                "detected_format": doc.get("detected_format", "Unknown"),
                "row_count": doc.get("row_count", 0),
                "status": doc.get("status", "pending"),
                "uploaded_at": doc.get("uploaded_at", "").isoformat()
                if doc.get("uploaded_at")
                else None,
            }
        )
    return uploads


@router.get("/{upload_id}/status", tags=["uploads"])
async def get_upload_status(
    upload_id: str,
    current_user: dict = Depends(get_current_user),
):
    """Quick status check for a specific upload."""
    db = get_db()
    try:
        doc = await db.uploads.find_one({"_id": ObjectId(upload_id)})
    except Exception:
        raise HTTPException(status_code=404, detail="Upload not found")

    if not doc or doc.get("user_id") != str(current_user["_id"]):
        raise HTTPException(status_code=404, detail="Upload not found")

    return {
        "upload_id": upload_id,
        "status": doc.get("status"),
        "detected_format": doc.get("detected_format", "Unknown"),
        "row_count": doc.get("row_count"),
        "filename": doc.get("filename"),
    }
