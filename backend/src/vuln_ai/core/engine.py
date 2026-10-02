"""Core scan engine — orchestrates the full scan pipeline.

This engine is independent of any interface (CLI, API, Web).
It coordinates scanners, sources, matching, and persistence.
"""

from __future__ import annotations

import logging
import time
from pathlib import Path

from sqlalchemy.ext.asyncio import AsyncSession

from vuln_ai.ai.models import AnalysisContext
from vuln_ai.ai.questions import get_default_decision_questions
from vuln_ai.ai.registry import AIRegistry
from vuln_ai.core.models import (
    MatchResult,
    ScanResultSummary,
    ScanStatus,
    SourceStatus,
    VulnerabilityRecord,
)
from vuln_ai.db.models import MatchDB
from vuln_ai.db.repositories import (
    AIAnalysisRepository,
    ComponentRepository,
    DecisionRepository,
    MatchRepository,
    ProjectRepository,
    RiskAssessmentRepository,
    ScanRepository,
    SourceRepository,
    VulnerabilityRepository,
)
from vuln_ai.matching.matcher import VulnerabilityMatcher
from vuln_ai.risk.engine import DeterministicRiskEngine
from vuln_ai.scanners.registry import ScannerRegistry
from vuln_ai.sources.registry import SourceRegistry

logger = logging.getLogger(__name__)


class ScanEngine:
    """Orchestrates the full vulnerability scan pipeline.

    Pipeline:
        1. Detect/create project
        2. Run applicable scanners to find components
        3. Persist components
        4. Load locally-stored vulnerabilities
        5. Run deterministic matcher
        6. Persist matches
        7. Run AI contextual analysis (optional)
        8. Run SystemOne probabilistic decision (optional)
        9. Run deterministic Risk Engine
        10. Persist enriched findings and return structured result
    """

    def __init__(
        self,
        session: AsyncSession,
        scanner_registry: ScannerRegistry,
        source_registry: SourceRegistry,
        matcher: VulnerabilityMatcher | None = None,
        ai_registry: AIRegistry | None = None,
        risk_engine: DeterministicRiskEngine | None = None,
        ai_enabled: bool = True,
        decision_enabled: bool = True,
    ) -> None:
        self._session = session
        self._scanner_registry = scanner_registry
        self._source_registry = source_registry
        self._matcher = matcher or VulnerabilityMatcher()
        self._ai_registry = ai_registry
        self._risk_engine = risk_engine or DeterministicRiskEngine()
        self._ai_enabled = ai_enabled
        self._decision_enabled = decision_enabled

        # Repositories
        self._projects = ProjectRepository(session)
        self._components = ComponentRepository(session)
        self._sources = SourceRepository(session)
        self._vulns = VulnerabilityRepository(session)
        self._scans = ScanRepository(session)
        self._matches = MatchRepository(session)
        self._ai_analyses = AIAnalysisRepository(session)
        self._decisions = DecisionRepository(session)
        self._risk_assessments = RiskAssessmentRepository(session)

    async def scan(self, project_path: str | Path) -> ScanResultSummary:
        """Run a full vulnerability scan on a project.

        Args:
            project_path: Path to the project directory.

        Returns:
            ScanResultSummary with all findings.
        """
        project_path = Path(project_path).resolve()
        start_time = time.monotonic()

        if not project_path.is_dir():
            return ScanResultSummary(
                project_name=project_path.name,
                project_path=str(project_path),
                scan_status=ScanStatus.FAILED,
                error=f"Project path does not exist: {project_path}",
            )

        try:
            return await self._execute_scan(project_path, start_time)
        except Exception as exc:
            logger.exception("Scan failed for %s", project_path)
            return ScanResultSummary(
                project_name=project_path.name,
                project_path=str(project_path),
                scan_status=ScanStatus.FAILED,
                error=str(exc),
                duration_seconds=time.monotonic() - start_time,
            )

    async def _execute_scan(
        self,
        project_path: Path,
        start_time: float,
    ) -> ScanResultSummary:
        """Execute the scan pipeline."""
        project_name = project_path.name

        # Step 1: Get or create project
        project, _ = await self._projects.get_or_create(
            name=project_name,
            path=str(project_path),
        )

        # Step 2: Create scan record
        scan = await self._scans.create(project_id=project.id)

        # Step 3: Run scanners
        logger.info("Scanning project: %s", project_path)
        components = self._scanner_registry.scan_all(project_path)

        if not components:
            duration = time.monotonic() - start_time
            await self._scans.complete(
                scan.id,
                components_found=0,
                duration_seconds=duration,
            )
            return ScanResultSummary(
                project_name=project_name,
                project_path=str(project_path),
                scan_status=ScanStatus.COMPLETED,
                duration_seconds=duration,
            )

        logger.info("Found %d components", len(components))

        # Step 4: Persist components
        db_components = await self._components.save_components(
            project_id=project.id,
            components=components,
        )

        # Build component ID map (normalized_name -> db_id)
        component_id_map: dict[str, str] = {}
        for db_comp, domain_comp in zip(db_components, components, strict=False):
            component_id_map[domain_comp.normalized_name()] = db_comp.id

        # Step 5: Load local vulnerabilities
        vulnerabilities = await self._load_vulnerabilities()
        logger.info("Loaded %d vulnerabilities from local sources", len(vulnerabilities))

        # Step 6: Run matcher
        matches = self._matcher.match(components, vulnerabilities)
        logger.info("Found %d matches", len(matches))

        # Step 7: Persist matches
        # Build vulnerability ID map (cve_id -> db_id)
        vulnerability_id_map = await self._build_vuln_id_map()

        db_matches: list[MatchDB] = []
        if matches:
            db_matches = await self._matches.save_matches(
                scan_id=scan.id,
                matches=matches,
                component_id_map=component_id_map,
                vulnerability_id_map=vulnerability_id_map,
            )
            # Step 8: AI Contextual Analysis, SystemOne Decisions, and Risk Assessment
            await self._enrich_and_assess_matches(matches, db_matches)

        # Step 9: Complete scan
        duration = time.monotonic() - start_time

        kev_matches = sum(1 for m in matches if m.vulnerability.source_name == "CISA KEV")

        await self._scans.complete(
            scan.id,
            components_found=len(components),
            vulnerabilities_found=len(vulnerabilities),
            kev_matches=kev_matches,
            duration_seconds=duration,
        )

        return ScanResultSummary(
            project_name=project_name,
            project_path=str(project_path),
            scan_status=ScanStatus.COMPLETED,
            components_found=len(components),
            vulnerabilities_checked=len(vulnerabilities),
            matches_found=len(matches),
            kev_matches=kev_matches,
            duration_seconds=duration,
            matches=matches,
        )

    async def _enrich_and_assess_matches(
        self,
        matches: list[MatchResult],
        db_matches: list[MatchDB],
    ) -> None:
        """Run AI contextual analysis, SystemOne decisions, and Risk Engine for each match."""
        questions = get_default_decision_questions()

        ai_provider = (
            self._ai_registry.get_ai_provider() if self._ai_registry and self._ai_enabled else None
        )
        decision_provider = (
            self._ai_registry.get_decision_provider()
            if self._ai_registry and self._decision_enabled
            else None
        )

        ai_available = await ai_provider.is_available() if ai_provider else False
        decision_available = await decision_provider.is_available() if decision_provider else False

        match_id_by_index = {i: dbm.id for i, dbm in enumerate(db_matches)}

        for idx, match in enumerate(matches):
            context = AnalysisContext.from_match(match)
            db_match_id = match_id_by_index.get(idx)

            # 1. LLM Contextual Analysis
            ai_analysis = None
            if ai_available and ai_provider:
                try:
                    ai_analysis = await ai_provider.analyze(context)
                except Exception as exc:
                    logger.warning(
                        "AI analysis failed for %s / %s: %s",
                        match.component.name,
                        match.vulnerability.cve_id,
                        exc,
                    )

            # 2. SystemOne Probabilistic Decision
            decision = None
            if decision_available and decision_provider:
                try:
                    decision = await decision_provider.decide(context, questions)
                except Exception as exc:
                    logger.warning(
                        "Decision provider failed for %s / %s: %s",
                        match.component.name,
                        match.vulnerability.cve_id,
                        exc,
                    )

            # 3. Deterministic Risk Assessment
            assessment = self._risk_engine.assess(match, ai_analysis, decision)

            # Attach to domain match object
            match.ai_analysis = ai_analysis
            match.decision = decision
            match.risk_assessment = assessment

            # 4. Persist to database if match record exists
            if db_match_id:
                if ai_analysis:
                    await self._ai_analyses.save_analysis(db_match_id, ai_analysis)
                if decision:
                    await self._decisions.save_decision(db_match_id, decision)
                await self._risk_assessments.save_assessment(db_match_id, assessment)

    async def _load_vulnerabilities(self) -> list[VulnerabilityRecord]:
        """Load all vulnerabilities from local database."""

        db_vulns = await self._vulns.get_all()
        return [self._vulns.to_domain(v) for v in db_vulns]

    async def _build_vuln_id_map(self) -> dict[str, str]:
        """Build a map of CVE ID -> database vulnerability ID."""
        db_vulns = await self._vulns.get_all()
        return {v.cve_id: v.id for v in db_vulns}

    async def update_sources(self) -> list[dict]:
        """Sync all registered vulnerability sources.

        Downloads fresh data from each source and persists it locally.
        This should be called before scanning (e.g., `vuln-ai update`).
        """
        results = []

        for source in self._source_registry.list_sources():
            logger.info("Syncing source: %s", source.name)

            # Get or create source record
            db_source, _ = await self._sources.get_or_create(
                name=source.name,
                source_type=source.source_type,
                url=source.url,
            )

            # Update status to syncing
            await self._sources.update_sync_status(
                db_source.id,
                SourceStatus.SYNCING,
            )

            # Sync the source
            sync_result = await source.sync()

            if sync_result.success:
                # Persist vulnerability records
                count = await self._vulns.upsert_vulnerabilities(
                    source_id=db_source.id,
                    records=source.records,
                )

                await self._sources.update_sync_status(
                    db_source.id,
                    SourceStatus.ACTIVE,
                    record_count=count,
                )

                logger.info(
                    "Source '%s' synced: %d records",
                    source.name,
                    count,
                )
            else:
                await self._sources.update_sync_status(
                    db_source.id,
                    SourceStatus.ERROR,
                    error=sync_result.error,
                )

                logger.error(
                    "Source '%s' sync failed: %s",
                    source.name,
                    sync_result.error,
                )

            results.append(
                {
                    "source": source.name,
                    "success": sync_result.success,
                    "records": sync_result.records_synced,
                    "error": sync_result.error,
                    "duration": sync_result.duration_seconds,
                }
            )

        return results
