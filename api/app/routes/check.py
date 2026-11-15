from fastapi import APIRouter, Depends, HTTPException, Request, status
import aiosqlite
from app.db import get_db
from app.schemas import CheckRequest, CheckResponse
from app.services.reputation import check_reputation

router = APIRouter(prefix="/v1", tags=["check"])


@router.post(
    "/check",
    response_model=CheckResponse,
    status_code=status.HTTP_200_OK,
)
async def check(
    request: Request,
    payload: CheckRequest,
    db: aiosqlite.Connection = Depends(get_db),
) -> CheckResponse:
    content_type = request.headers.get("content-type", "").split(";")[0].strip().lower()
    if content_type and content_type != "application/json":
        raise HTTPException(
            status_code=status.HTTP_415_UNSUPPORTED_MEDIA_TYPE,
            detail="Unsupported Media Type: expected application/json",
        )
    return await check_reputation(db, payload)
