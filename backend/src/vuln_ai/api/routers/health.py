"""Health and readiness probe router."""

from __future__ import annotations

import logging
from typing import Annotated, Any

from fastapi import APIRouter, Depends, status
from fastapi.responses import JSONResponse
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from vuln_ai.api.deps import get_app_settings, get_db
from vuln_ai.config import Settings

logger = logging.getLogger(__name__)

router = APIRouter(tags=["Health"])


@router.get("/health", summary="Basic health probe")
async def health_check(
    settings: Annotated[Settings, Depends(get_app_settings)],
) -> dict[str, Any]:
    """Return basic application liveness information."""
    return {
        "status": "ok",
        "version": settings.api.version,
    }


@router.get("/health/ready", summary="Readiness probe")
async def readiness_check(
    db: Annotated[AsyncSession, Depends(get_db)],
    settings: Annotated[Settings, Depends(get_app_settings)],
) -> JSONResponse:
    """Verify that the database is reachable and the application is ready to accept traffic."""
    try:
        await db.execute(text("SELECT 1"))
        return JSONResponse(
            status_code=status.HTTP_200_OK,
            content={
                "status": "ready",
                "database": "connected",
                "version": settings.api.version,
            },
        )
    except Exception as exc:
        logger.error("Readiness check database failure: %s", exc)
        return JSONResponse(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            content={
                "status": "unavailable",
                "database": "disconnected",
                "error": str(exc),
            },
        )
