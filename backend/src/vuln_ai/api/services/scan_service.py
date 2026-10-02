"""Service for project scanning orchestration."""

from __future__ import annotations

import logging

from sqlalchemy.ext.asyncio import AsyncSession

from vuln_ai.ai.registry import AIRegistry
from vuln_ai.api.errors import BadRequestError, NotFoundError
from vuln_ai.api.schemas.common import PaginatedResponse
from vuln_ai.api.schemas.scans import ScanResponse, ScanSummary
from vuln_ai.api.services.match_service import MatchService
from vuln_ai.core.engine import ScanEngine
from vuln_ai.core.models import ScanStatus
from vuln_ai.db.models import ScanDB
from vuln_ai.db.repositories import (
    MatchRepository,
    ProjectRepository,
    RiskAssessmentRepository,
    ScanRepository,
)
from vuln_ai.matching.matcher import VulnerabilityMatcher
from vuln_ai.risk.engine import DeterministicRiskEngine
from vuln_ai.scanners.registry import ScannerRegistry
from vuln_ai.sources.registry import SourceRegistry

logger = logging.getLogger(__name__)


class ScanService:
    """Business logic for scan operations, delegating to ScanEngine."""

    def __init__(
        self,
        session: AsyncSession,
        scan_repo: ScanRepository,
        project_repo: ProjectRepository,
        match_repo: MatchRepository,
        risk_assessments_repo: RiskAssessmentRepository,
        scanner_registry: ScannerRegistry,
        source_registry: SourceRegistry,
        matcher: VulnerabilityMatcher | None = None,
        ai_registry: AIRegistry | None = None,
        risk_engine: DeterministicRiskEngine | None = None,
        match_service: MatchService | None = None,
    ) -> None:
        self._session = session
        self._scan_repo = scan_repo
        self._project_repo = project_repo
        self._match_repo = match_repo
        self._risk_assessments_repo = risk_assessments_repo
        self._scanner_registry = scanner_registry
        self._source_registry = source_registry
        self._matcher = matcher or VulnerabilityMatcher()
        self._ai_registry = ai_registry
        self._risk_engine = risk_engine or DeterministicRiskEngine()
        self._match_service = match_service

    async def _compute_summary(self, scan_id: str, db_scan: ScanDB) -> ScanSummary:
        matches = await self._match_repo.get_by_scan(scan_id)
        requires_review_count = 0
        for m in matches:
            assessment = await self._risk_assessments_repo.get_by_match_id(m.id)
            if assessment and assessment.requires_human_review:
                requires_review_count += 1

        return ScanSummary(
            components=db_scan.components_found,
            matches=len(matches),
            kev_matches=db_scan.kev_matches,
            requires_review=requires_review_count,
        )

    async def _to_response(self, db_scan: ScanDB, include_matches: bool = False) -> ScanResponse:
        summary = await self._compute_summary(db_scan.id, db_scan)
        matches_resp = None
        if include_matches and self._match_service is not None:
            db_matches = await self._match_repo.get_by_scan(db_scan.id)
            matches_resp = []
            for m in db_matches:
                full_match = await self._match_service.get_match(m.id)
                matches_resp.append(full_match)

        return ScanResponse(
            id=db_scan.id,
            project_id=db_scan.project_id,
            status=db_scan.status,
            components_found=db_scan.components_found,
            vulnerabilities_found=db_scan.vulnerabilities_found,
            kev_matches=db_scan.kev_matches,
            duration_seconds=db_scan.duration_seconds,
            started_at=db_scan.started_at,
            completed_at=db_scan.completed_at,
            error=db_scan.error,
            summary=summary,
            matches=matches_resp,
        )

    async def run_scan(self, project_id: str, run_ai: bool = True) -> ScanResponse:
        """Execute a scan for the specified project using the existing ScanEngine."""
        project = await self._project_repo.get_by_id(project_id)
        if project is None:
            raise NotFoundError(
                message=f"Project with ID '{project_id}' not found",
                code="PROJECT_NOT_FOUND",
            )

        engine = ScanEngine(
            session=self._session,
            scanner_registry=self._scanner_registry,
            source_registry=self._source_registry,
            matcher=self._matcher,
            ai_registry=self._ai_registry,
            risk_engine=self._risk_engine,
            ai_enabled=run_ai,
            decision_enabled=run_ai,
        )

        result_summary = await engine.scan(project.path)
        if result_summary.scan_status == ScanStatus.FAILED and result_summary.error:
            # If path didn't exist or crashed before starting scan record
            raise BadRequestError(
                message=f"Scan execution failed: {result_summary.error}",
                code="SCAN_EXECUTION_FAILED",
            )

        # Get latest scan for this project
        project_scans = await self._scan_repo.get_by_project(project_id)
        if not project_scans:
            raise NotFoundError(
                message="No scan record was created",
                code="SCAN_NOT_FOUND",
            )
        latest_scan = project_scans[0]
        return await self._to_response(latest_scan, include_matches=True)

    async def list_scans(
        self,
        project_id: str | None = None,
        page: int = 1,
        page_size: int = 20,
    ) -> PaginatedResponse[ScanResponse]:
        """List scans with optional project filtering and pagination."""
        if project_id:
            project = await self._project_repo.get_by_id(project_id)
            if project is None:
                raise NotFoundError(
                    message=f"Project with ID '{project_id}' not found",
                    code="PROJECT_NOT_FOUND",
                )

        items, total = await self._scan_repo.list_paginated(
            project_id=project_id, page=page, page_size=page_size
        )
        responses = [await self._to_response(s, include_matches=False) for s in items]
        return PaginatedResponse(
            items=responses,
            page=page,
            page_size=page_size,
            total=total,
        )

    async def get_scan(self, scan_id: str) -> ScanResponse:
        """Get scan details by ID."""
        scan = await self._scan_repo.get_by_id(scan_id)
        if scan is None:
            raise NotFoundError(
                message=f"Scan with ID '{scan_id}' not found",
                code="SCAN_NOT_FOUND",
            )
        return await self._to_response(scan, include_matches=True)
