"""Service for vulnerability data sources."""

from __future__ import annotations

import logging
import time

from vuln_ai.api.errors import NotFoundError
from vuln_ai.api.schemas.sources import SourceResponse, SourceSyncResponse
from vuln_ai.core.models import SourceStatus
from vuln_ai.db.models import VulnerabilitySourceDB
from vuln_ai.db.repositories import SourceRepository, VulnerabilityRepository
from vuln_ai.sources.registry import SourceRegistry

logger = logging.getLogger(__name__)


class SourceService:
    """Business logic for vulnerability source management and synchronization."""

    def __init__(
        self,
        source_repo: SourceRepository,
        vuln_repo: VulnerabilityRepository,
        source_registry: SourceRegistry,
    ) -> None:
        self._source_repo = source_repo
        self._vuln_repo = vuln_repo
        self._registry = source_registry

    @staticmethod
    def to_response(db_source: VulnerabilitySourceDB) -> SourceResponse:
        return SourceResponse(
            id=db_source.id,
            name=db_source.name,
            source_type=db_source.source_type,
            url=db_source.url,
            status=db_source.status,
            last_sync=db_source.last_sync,
            record_count=db_source.record_count,
            last_error=db_source.last_error,
        )

    async def list_sources(self) -> list[SourceResponse]:
        """List all vulnerability sources, ensuring registered ones exist in DB."""
        # Ensure registered sources exist in DB
        for reg_source in self._registry.list_sources():
            await self._source_repo.get_or_create(
                name=reg_source.name,
                source_type=reg_source.source_type,
                url=reg_source.url,
            )

        db_sources = await self._source_repo.list_all()
        return [self.to_response(s) for s in db_sources]

    async def get_source_status(self, source_id: str) -> SourceResponse:
        """Get the current status of a vulnerability source."""
        source = await self._source_repo.get_by_id(source_id)
        if source is None:
            raise NotFoundError(
                message=f"Vulnerability source with ID '{source_id}' not found",
                code="SOURCE_NOT_FOUND",
            )
        return self.to_response(source)

    async def sync_source(self, source_id: str) -> SourceSyncResponse:
        """Trigger synchronization of a specific vulnerability source."""
        db_source = await self._source_repo.get_by_id(source_id)
        if db_source is None:
            raise NotFoundError(
                message=f"Vulnerability source with ID '{source_id}' not found",
                code="SOURCE_NOT_FOUND",
            )

        source_impl = self._registry.get(db_source.name)
        if source_impl is None:
            raise NotFoundError(
                message=f"No provider implementation registered for source '{db_source.name}'",
                code="SOURCE_PROVIDER_NOT_FOUND",
            )

        await self._source_repo.update_sync_status(
            source_id=db_source.id,
            status=SourceStatus.SYNCING,
        )

        start_time = time.monotonic()
        sync_result = await source_impl.sync()
        duration = sync_result.duration_seconds or (time.monotonic() - start_time)

        if sync_result.success:
            # CISA KEV provides a complete feed snapshot; OSV/NVD syncs are partial.
            prune_missing = (
                db_source.source_type == "cisa_kev" and bool(source_impl.records)
            )
            await self._vuln_repo.upsert_vulnerabilities(
                source_id=db_source.id,
                records=source_impl.records,
                prune_missing=prune_missing,
            )
            # H16: report catalog size for this source, not raw batch length.
            catalog_count = await self._vuln_repo.count_by_source(db_source.id)
            await self._source_repo.update_sync_status(
                source_id=db_source.id,
                status=SourceStatus.ACTIVE,
                record_count=catalog_count,
            )
            logger.info(
                "Source '%s' successfully synced with %d catalog records",
                db_source.name,
                catalog_count,
            )
            return SourceSyncResponse(
                source=db_source.name,
                success=True,
                records=catalog_count,
                error=None,
                duration=duration,
            )
        else:
            await self._source_repo.update_sync_status(
                source_id=db_source.id,
                status=SourceStatus.ERROR,
                error=sync_result.error,
            )
            logger.error("Source '%s' sync failed: %s", db_source.name, sync_result.error)
            return SourceSyncResponse(
                source=db_source.name,
                success=False,
                records=0,
                error=sync_result.error,
                duration=duration,
            )
