"""Core scan engine — orchestrates the full scan pipeline.

This engine is independent of any interface (CLI, API, Web).
It coordinates scanners, sources, matching, and persistence.
"""

from __future__ import annotations

import logging
import time
import uuid
from pathlib import Path
from typing import Any

from sqlalchemy.ext.asyncio import AsyncSession

from vuln_ai.ai.models import AnalysisContext
from vuln_ai.ai.questions import get_default_decision_questions
from vuln_ai.ai.registry import AIRegistry
from vuln_ai.container.models import ContainerImage, OSPackage
from vuln_ai.container.scanner import ContainerImageScanner
from vuln_ai.core.graph import DependencyGraph
from vuln_ai.core.models import (
    MatchResult,
    ScanResultSummary,
    ScanStatus,
    SourceStatus,
    VulnerabilityRecord,
)
from vuln_ai.db.models import MatchDB, VulnerabilityDB
from vuln_ai.db.repositories import (
    AIAnalysisRepository,
    ComponentRepository,
    ContainerRepository,
    DecisionRepository,
    MatchRepository,
    ProjectRepository,
    RiskAssessmentRepository,
    ScanRepository,
    SourceRepository,
    VulnerabilityRepository,
)
from vuln_ai.matching.conflict import ConflictResolver
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
        6. Resolve multi-source conflicts and consolidate applicability
        7. Persist matches and conflicts
        8. Run AI contextual analysis (optional)
        9. Run SystemOne probabilistic decision (optional)
        10. Run deterministic Risk Engine
        11. Persist enriched findings and return structured result
    """

    def __init__(
        self,
        session: AsyncSession,
        scanner_registry: ScannerRegistry,
        source_registry: SourceRegistry,
        matcher: VulnerabilityMatcher | None = None,
        conflict_resolver: ConflictResolver | None = None,
        ai_registry: AIRegistry | None = None,
        risk_engine: DeterministicRiskEngine | None = None,
        ai_enabled: bool = True,
        decision_enabled: bool = True,
    ) -> None:
        self._session = session
        self._scanner_registry = scanner_registry
        self._source_registry = source_registry
        self._matcher = matcher or VulnerabilityMatcher()
        self._conflict_resolver = conflict_resolver or ConflictResolver()
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
        self._containers = ContainerRepository(session)

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

    async def scan_container_image(
        self,
        archive_path: str | Path,
        reference: str | None = None,
    ) -> tuple[ScanResultSummary, ContainerImage, list[OSPackage], DependencyGraph]:
        """Execute the full vulnerability scan pipeline on a container image archive.

        Follows the canonical pipeline:
        Image Inspection -> OS & App Detection -> Container Graph -> Existing Vulnerability Catalog
        -> Version-aware Matcher -> Conflict Resolver -> AI -> Risk Engine.
        """
        archive_path = Path(archive_path).resolve()
        start_time = time.monotonic()

        if not archive_path.is_file():
            summary = ScanResultSummary(
                project_name=reference or archive_path.name,
                project_path=str(archive_path),
                scan_status=ScanStatus.FAILED,
                error=f"Image archive does not exist: {archive_path}",
                duration_seconds=time.monotonic() - start_time,
            )
            dummy_image = ContainerImage(
                id=str(uuid.uuid4()),
                reference=reference or archive_path.name,
                source_path=str(archive_path),
            )
            return summary, dummy_image, [], DependencyGraph()

        container_scanner = ContainerImageScanner()
        image, os_pkgs, components, graph = container_scanner.scan_archive(archive_path)
        if reference:
            image.reference = reference

        for comp in components:
            if not comp.metadata:
                comp.metadata = {}
            comp.metadata["container_image"] = image.reference
            if image.digest:
                comp.metadata["container_digest"] = image.digest

        # 1. Project & Scan records
        project_name = f"container:{image.reference}"
        project, _ = await self._projects.get_or_create(
            name=project_name,
            path=str(archive_path),
        )
        scan = await self._scans.create(project_id=project.id)

        # 2. Persist ContainerImage and layers
        db_image = await self._containers.create_image(
            scan_id=scan.id,
            image=image,
            commit=False,
        )
        db_layers = await self._containers.add_layers(
            image_id=db_image.id,
            layers=image.layers,
            commit=False,
        )
        layer_digest_to_id = {layer.digest: layer.id for layer in db_layers}

        # 3. Persist components & dependency graph
        db_components = await self._components.save_components(
            project_id=project.id,
            components=components,
        )
        if graph and graph.edges and hasattr(self._components, "save_dependency_edges"):
            await self._components.save_dependency_edges(
                project_id=project.id,
                edges=graph.edges,
            )

        # 4. Link components to container image & layers
        link_items: list[tuple[str, str | None, str, str, str | None, bool]] = []
        for db_c, comp in zip(db_components, components, strict=False):
            c_meta = comp.metadata or {}
            l_digest = c_meta.get("container_layer")
            layer_db_id = layer_digest_to_id.get(l_digest) if l_digest else None
            c_path = c_meta.get("container_path", comp.source_file)
            c_stage = c_meta.get("stage", "runtime")
            c_pkg_mgr = c_meta.get("package_manager")
            link_items.append(
                (
                    db_c.id,
                    layer_db_id,
                    c_path,
                    c_stage,
                    c_pkg_mgr,
                    True,
                )
            )

        await self._containers.link_components(
            image_id=db_image.id,
            components=link_items,
            commit=False,
        )

        # 5. Handle empty components case
        if not components:
            duration = time.monotonic() - start_time
            await self._scans.complete(
                scan.id,
                components_found=0,
                duration_seconds=duration,
            )
            summary = ScanResultSummary(
                project_name=project_name,
                project_path=str(archive_path),
                scan_status=ScanStatus.COMPLETED,
                scan_id=scan.id,
                duration_seconds=duration,
                dependency_graph=graph,
                metadata={
                    "container_image": image.model_dump(),
                    "container_digest": image.digest,
                    "os": image.os,
                },
            )
            return summary, image, os_pkgs, graph

        # 6. Component ID map
        component_id_map: dict[Any, str] = {}
        for db_comp, domain_comp in zip(db_components, components, strict=False):
            norm_name = domain_comp.normalized_name()
            component_id_map[(norm_name, domain_comp.version, domain_comp.source_file)] = (
                db_comp.id
            )
            component_id_map[(norm_name, domain_comp.version)] = db_comp.id
            if norm_name not in component_id_map:
                component_id_map[norm_name] = db_comp.id

        # 7. Candidate vulnerabilities
        candidate_db_vulns: list[VulnerabilityDB] = []
        if hasattr(self._vulns, "find_candidates_for_components"):
            candidate_db_vulns = await self._vulns.find_candidates_for_components(components)
        if not candidate_db_vulns:
            candidate_db_vulns = await self._vulns.get_all()

        vulnerabilities = [self._vulns.to_domain(v) for v in candidate_db_vulns]

        # 8. Version-aware matcher
        matches = self._matcher.match(components, vulnerabilities)

        # 9. Multi-source conflict resolver
        matches = self._conflict_resolver.resolve_matches(matches)

        # 10. Persist matches & enrich with Risk Engine / AI
        vulnerability_id_map = await self._build_vuln_id_map(candidate_db_vulns)
        db_matches: list[MatchDB] = []
        if matches:
            db_matches = await self._matches.save_matches(
                scan_id=scan.id,
                matches=matches,
                component_id_map=component_id_map,
                vulnerability_id_map=vulnerability_id_map,
            )
            await self._enrich_and_assess_matches(matches, db_matches)

        # 11. Complete scan
        duration = time.monotonic() - start_time
        kev_matches = sum(
            1
            for m in matches
            if getattr(m.vulnerability, "has_kev_evidence", False)
            or m.vulnerability.source_name == "CISA KEV"
        )
        direct_count = sum(1 for c in components if getattr(c, "is_direct", True))
        transitive_count = len(components) - direct_count
        edges_count = len(graph.edges) if graph else 0
        lockfiles = graph.lockfiles_detected if graph else []

        await self._scans.complete(
            scan.id,
            components_found=len(components),
            vulnerabilities_found=len(vulnerabilities),
            kev_matches=kev_matches,
            duration_seconds=duration,
        )

        summary = ScanResultSummary(
            project_name=project_name,
            project_path=str(archive_path),
            scan_status=ScanStatus.COMPLETED,
            scan_id=scan.id,
            components_found=len(components),
            direct_components_count=direct_count,
            transitive_components_count=transitive_count,
            dependency_edges_count=edges_count,
            lockfiles_detected=lockfiles,
            vulnerabilities_checked=len(vulnerabilities),
            matches_found=len(matches),
            kev_matches=kev_matches,
            duration_seconds=duration,
            matches=matches,
            dependency_graph=graph,
            metadata={
                "container_image": image.model_dump(),
                "container_digest": image.digest,
                "os": image.os,
            },
        )
        return summary, image, os_pkgs, graph

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

        # Step 3: Run scanners & build dependency graph
        logger.info("Scanning project: %s", project_path)
        graph = (
            self._scanner_registry.scan_graph(project_path)
            if hasattr(self._scanner_registry, "scan_graph")
            else None
        )
        components = (
            graph.resolve_components() if graph else self._scanner_registry.scan_all(project_path)
        )

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
                scan_id=scan.id,
                duration_seconds=duration,
                dependency_graph=graph,
            )

        logger.info("Found %d components", len(components))

        # Step 4: Persist components and dependency relations
        db_components = await self._components.save_components(
            project_id=project.id,
            components=components,
        )
        if graph and graph.edges and hasattr(self._components, "save_dependency_edges"):
            await self._components.save_dependency_edges(
                project_id=project.id,
                edges=graph.edges,
            )

        # Build component ID map supporting both (norm_name, version) and norm_name
        component_id_map: dict[Any, str] = {}
        for db_comp, domain_comp in zip(db_components, components, strict=False):
            norm_name = domain_comp.normalized_name()
            component_id_map[(norm_name, domain_comp.version, domain_comp.source_file)] = (
                db_comp.id
            )
            component_id_map[(norm_name, domain_comp.version)] = db_comp.id
            if norm_name not in component_id_map:
                component_id_map[norm_name] = db_comp.id

        # Step 5: Load candidate vulnerabilities matching detected components
        candidate_db_vulns: list[VulnerabilityDB] = []
        if hasattr(self._vulns, "find_candidates_for_components"):
            candidate_db_vulns = await self._vulns.find_candidates_for_components(components)
        if not candidate_db_vulns:
            candidate_db_vulns = await self._vulns.get_all()

        vulnerabilities = [self._vulns.to_domain(v) for v in candidate_db_vulns]
        logger.info("Loaded %d candidate vulnerabilities from local sources", len(vulnerabilities))

        # Step 6: Run matcher
        matches = self._matcher.match(components, vulnerabilities)
        logger.info("Found %d matches", len(matches))

        # Step 6.1: Multi-source conflict resolution & consolidated applicability
        matches = self._conflict_resolver.resolve_matches(matches)

        # Step 7: Persist matches and conflicts
        # Build vulnerability ID map (canonical_id / cve_id / alias -> db_id)
        vulnerability_id_map = await self._build_vuln_id_map(candidate_db_vulns)

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

        kev_matches = sum(
            1
            for m in matches
            if getattr(m.vulnerability, "has_kev_evidence", False)
            or m.vulnerability.source_name == "CISA KEV"
        )

        direct_count = sum(1 for c in components if getattr(c, "is_direct", True))
        transitive_count = len(components) - direct_count
        edges_count = len(graph.edges) if graph else 0
        lockfiles = graph.lockfiles_detected if graph else []

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
            scan_id=scan.id,
            components_found=len(components),
            direct_components_count=direct_count,
            transitive_components_count=transitive_count,
            dependency_edges_count=edges_count,
            lockfiles_detected=lockfiles,
            vulnerabilities_checked=len(vulnerabilities),
            matches_found=len(matches),
            kev_matches=kev_matches,
            duration_seconds=duration,
            matches=matches,
            dependency_graph=graph,
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

    async def _build_vuln_id_map(
        self, candidate_vulns: list[VulnerabilityDB] | None = None
    ) -> dict[str, str]:
        """Build a map of canonical_id / cve_id / aliases -> database vulnerability ID."""
        db_vulns = candidate_vulns if candidate_vulns is not None else await self._vulns.get_all()
        id_map: dict[str, str] = {}
        for v in db_vulns:
            if v.id:
                id_map[v.id] = v.id
            if v.canonical_id:
                id_map[v.canonical_id] = v.id
            if v.cve_id:
                id_map[v.cve_id] = v.id
            if getattr(v, "identifiers", None):
                for ident in v.identifiers:
                    id_map[ident.identifier] = v.id
        return id_map

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
                # Persist vulnerability records (incremental unless full-feed source)
                prune_missing = db_source.source_type == "cisa_kev" and bool(source.records)
                await self._vulns.upsert_vulnerabilities(
                    source_id=db_source.id,
                    records=source.records,
                    prune_missing=prune_missing,
                )
                catalog_count = await self._vulns.count_by_source(db_source.id)

                await self._sources.update_sync_status(
                    db_source.id,
                    SourceStatus.ACTIVE,
                    record_count=catalog_count,
                )

                logger.info(
                    "Source '%s' synced: %d records",
                    source.name,
                    catalog_count,
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
