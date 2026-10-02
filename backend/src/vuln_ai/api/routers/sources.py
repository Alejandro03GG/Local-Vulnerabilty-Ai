"""Sources router."""

from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends

from vuln_ai.api.deps import get_source_service
from vuln_ai.api.schemas.sources import SourceResponse, SourceSyncResponse
from vuln_ai.api.services.source_service import SourceService

router = APIRouter(prefix="/sources", tags=["Sources"])


@router.get("", summary="List vulnerability sources")
async def list_sources(
    service: Annotated[SourceService, Depends(get_source_service)],
) -> list[SourceResponse]:
    """Retrieve all registered vulnerability sources and their sync statuses."""
    return await service.list_sources()


@router.get("/{source_id}/status", summary="Get source sync status")
async def get_source_status(
    source_id: str,
    service: Annotated[SourceService, Depends(get_source_service)],
) -> SourceResponse:
    """Retrieve the sync status and metrics of a vulnerability source."""
    return await service.get_source_status(source_id)


@router.post("/{source_id}/sync", summary="Trigger source synchronization")
async def sync_source(
    source_id: str,
    service: Annotated[SourceService, Depends(get_source_service)],
) -> SourceSyncResponse:
    """Download fresh data from the remote feed and update local vulnerability records."""
    return await service.sync_source(source_id)
