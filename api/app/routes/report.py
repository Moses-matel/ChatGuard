from datetime import datetime, timezone
from fastapi import APIRouter, Depends, HTTPException, Request, status
import aiosqlite
from app.db import get_db
from app.schemas import ReportRequest, ReportResponse

router = APIRouter(prefix="/v1", tags=["report"])


@router.post(
    "/report",
    response_model=ReportResponse,
    status_code=status.HTTP_201_CREATED,
)
async def report(
    request: Request,
    payload: ReportRequest,
    db: aiosqlite.Connection = Depends(get_db),
) -> ReportResponse:
    content_type = request.headers.get("content-type", "").split(";")[0].strip().lower()
    if content_type and content_type != "application/json":
        raise HTTPException(
            status_code=status.HTTP_415_UNSUPPORTED_MEDIA_TYPE,
            detail="Unsupported Media Type: expected application/json",
        )

    created_at = datetime.now(timezone.utc).isoformat()
    await db.execute(
        """
        INSERT INTO verdict_reports (
            sha256,
            file_type,
            package_name,
            cert_sha256,
            shown_verdict,
            user_note,
            created_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?)
        """,
        (
            payload.sha256,
            payload.file_type,
            payload.package_name,
            payload.cert_sha256,
            payload.shown_verdict,
            payload.user_note,
            created_at,
        ),
    )
    await db.commit()

    return ReportResponse(status="recorded")
