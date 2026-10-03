"""Service for project scanning orchestration."""

from __future__ import annotations

import logging

from sqlalchemy.ext.asyncio import AsyncSession

from vuln_ai.ai.registry import AIRegistry
from vuln_ai.api.errors import BadRequestError, NotFoundError
from vuln_ai.api.schemas.common import PaginatedResponse
from vuln_ai.api.schemas.components import (
    ComponentResponse,
    DependencyEdgeResponse,
    DependencyGraphResponse,
)
from vuln_ai.api.schemas.scans import ScanResponse, ScanSummary
from vuln_ai.api.services.component_service import ComponentService
from vuln_ai.api.services.match_service import MatchService
from vuln_ai.core.engine import ScanEngine
from vuln_ai.core.models import ScanStatus
from vuln_ai.db.models import MatchDB, ScanDB
from vuln_ai.db.repositories import (
    ComponentRepository,
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
        component_repo: ComponentRepository | None = None,
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
        self._component_repo = component_repo or ComponentRepository(session)

    def _compute_summary(self, db_matches: list[MatchDB], db_scan: ScanDB) -> ScanSummary:
        requires_review_count = 0
        for m in db_matches:
            if (
                m.risk_assessment and m.risk_assessment.requires_human_review
            ) or m.applicability == "REQUIRES_REVIEW":
                requires_review_count += 1

        return ScanSummary(
            components=db_scan.components_found,
            matches=len(db_matches),
            kev_matches=db_scan.kev_matches,
            requires_review=requires_review_count,
        )

    async def _to_response(self, db_scan: ScanDB, include_matches: bool = False) -> ScanResponse:
        db_matches = await self._match_repo.get_by_scan(db_scan.id)
        summary = self._compute_summary(db_matches, db_scan)
        matches_resp = None
        if include_matches and self._match_service is not None:
            matches_resp = [self._match_service._to_match_response(m) for m in db_matches]

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

    async def get_scan_dependencies(self, scan_id: str) -> list[ComponentResponse]:
        """Get resolved components for a scan's project."""
        scan = await self._scan_repo.get_by_id(scan_id)
        if scan is None:
            raise NotFoundError(
                message=f"Scan with ID '{scan_id}' not found",
                code="SCAN_NOT_FOUND",
            )
        comps = await self._component_repo.get_by_project(scan.project_id)
        return [ComponentService.to_response(c) for c in comps]

    async def get_scan_dependency_graph(self, scan_id: str) -> DependencyGraphResponse:
        """Get full dependency graph topology for a scan's project."""
        scan = await self._scan_repo.get_by_id(scan_id)
        if scan is None:
            raise NotFoundError(
                message=f"Scan with ID '{scan_id}' not found",
                code="SCAN_NOT_FOUND",
            )
        comps = await self._component_repo.get_by_project(scan.project_id)
        edges = await self._component_repo.get_dependency_edges(scan.project_id)

        comp_responses = [ComponentService.to_response(c) for c in comps]
        edge_responses = [
            DependencyEdgeResponse(
                parent_name=e.parent_name,
                parent_version=e.parent_version,
                child_name=e.child_name,
                child_version=e.child_version,
                scope=e.scope,
                requirement=e.requirement,
            )
            for e in edges
        ]

        direct_count = sum(1 for c in comp_responses if c.is_direct)
        transitive_count = len(comp_responses) - direct_count
        lockfiles = sorted({c.lockfile_source for c in comp_responses if c.lockfile_source})
        manifests = sorted({c.manifest_source for c in comp_responses if c.manifest_source})

        return DependencyGraphResponse(
            project_id=scan.project_id,
            direct_count=direct_count,
            transitive_count=transitive_count,
            edges_count=len(edge_responses),
            lockfiles_detected=lockfiles,
            manifests_detected=manifests,
            components=comp_responses,
            edges=edge_responses,
        )

    async def export_scan(
        self,
        scan_id: str,
        export_format: str,
    ) -> tuple[str, str, str]:
        """Export a completed scan to the specified format (sarif, cyclonedx, spdx).

        Returns:
            Tuple of (serialized_content, media_type, filename)
        """
        from vuln_ai.export.models import ExportFormat, ExportScan
        from vuln_ai.export.service import ExportService

        scan = await self._scan_repo.get_by_id(scan_id)
        if scan is None:
            raise NotFoundError(
                message=f"Scan with ID '{scan_id}' not found",
                code="SCAN_NOT_FOUND",
            )

        project = await self._project_repo.get_by_id(scan.project_id)
        comps = await self._component_repo.get_by_project(scan.project_id)
        edges = await self._component_repo.get_dependency_edges(scan.project_id)
        matches = await self._match_repo.get_by_scan(scan_id)

        export_scan_model = ExportScan.from_db(
            scan=scan,
            project=project,
            components=comps,
            edges=edges,
            matches=matches,
        )

        content = ExportService.serialize_text(export_scan_model, export_format)
        media_type = ExportService.get_media_type(export_format)

        ext_map = {
            ExportFormat.SARIF.value: "sarif",
            ExportFormat.CYCLONEDX.value: "cdx.json",
            ExportFormat.SPDX.value: "spdx.json",
        }
        proj_name = (getattr(project, "name", "project") if project else "project").replace(
            " ", "_"
        )
        ext = ext_map.get(export_format.lower(), "json")
        filename = f"{proj_name}_{scan_id[:8]}.{ext}"

        return content, media_type, filename
