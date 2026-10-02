"""Repository pattern for database access.

All database operations go through repositories.
The rest of the system should never execute SQL directly.
"""

from __future__ import annotations

import contextlib
import json
from datetime import UTC, datetime

from sqlalchemy import delete, func, select, update
from sqlalchemy.ext.asyncio import AsyncSession

from vuln_ai.ai.models import AIAnalysis, DecisionResult
from vuln_ai.core.models import (
    DetectedComponent,
    MatchResult,
    SourceInfo,
    SourceStatus,
    VulnerabilityRecord,
)
from vuln_ai.db.models import (
    AIAnalysisDB,
    DecisionResultDB,
    MatchDB,
    ProjectComponentDB,
    ProjectDB,
    RiskAssessmentDB,
    ScanDB,
    VulnerabilityDB,
    VulnerabilitySourceDB,
)
from vuln_ai.risk.models import RiskAssessment, RiskLevel, RiskStatus


class ProjectRepository:
    """Data access for projects."""

    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    async def create(self, name: str, path: str, description: str = "") -> ProjectDB:
        """Create a new project."""
        project = ProjectDB(name=name, path=path, description=description)
        self._session.add(project)
        await self._session.flush()
        return project

    async def get_by_id(self, project_id: str) -> ProjectDB | None:
        """Get a project by ID."""
        result = await self._session.execute(select(ProjectDB).where(ProjectDB.id == project_id))
        return result.scalar_one_or_none()

    async def get_by_path(self, path: str) -> ProjectDB | None:
        """Get a project by its filesystem path."""
        result = await self._session.execute(select(ProjectDB).where(ProjectDB.path == path))
        return result.scalar_one_or_none()

    async def get_or_create(
        self, name: str, path: str, description: str = ""
    ) -> tuple[ProjectDB, bool]:
        """Get an existing project by path, or create a new one.

        Returns:
            Tuple of (project, created) where created is True if newly created.
        """
        existing = await self.get_by_path(path)
        if existing is not None:
            existing.updated_at = datetime.now(UTC)
            return existing, False
        project = await self.create(name, path, description)
        return project, True

    async def list_all(self) -> list[ProjectDB]:
        """List all projects."""
        result = await self._session.execute(
            select(ProjectDB).order_by(ProjectDB.created_at.desc())
        )
        return list(result.scalars().all())

    async def list_paginated(
        self, page: int = 1, page_size: int = 20
    ) -> tuple[list[ProjectDB], int]:
        """List projects with pagination."""
        offset = (page - 1) * page_size
        total_result = await self._session.execute(select(func.count()).select_from(ProjectDB))
        total = total_result.scalar_one() or 0

        query = (
            select(ProjectDB).order_by(ProjectDB.created_at.desc()).offset(offset).limit(page_size)
        )
        result = await self._session.execute(query)
        return list(result.scalars().all()), total

    async def update(
        self,
        project_id: str,
        name: str | None = None,
        description: str | None = None,
        path: str | None = None,
    ) -> ProjectDB | None:
        """Update a project."""
        project = await self.get_by_id(project_id)
        if project is None:
            return None
        if name is not None:
            project.name = name
        if description is not None:
            project.description = description
        if path is not None:
            project.path = path
        project.updated_at = datetime.now(UTC)
        await self._session.flush()
        return project

    async def delete(self, project_id: str) -> bool:
        """Delete a project by ID."""
        project = await self.get_by_id(project_id)
        if project is None:
            return False
        await self._session.delete(project)
        await self._session.flush()
        return True


class ComponentRepository:
    """Data access for project components."""

    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    async def save_components(
        self,
        project_id: str,
        components: list[DetectedComponent],
    ) -> list[ProjectComponentDB]:
        """Save detected components for a project.

        Replaces all existing components for the project.
        """
        # Delete existing components for this project
        await self._session.execute(
            delete(ProjectComponentDB).where(ProjectComponentDB.project_id == project_id)
        )

        db_components = []
        for comp in components:
            db_comp = ProjectComponentDB(
                project_id=project_id,
                name=comp.name,
                version=comp.version,
                version_type=comp.version_type.value,
                version_constraint=comp.version_constraint,
                source_file=comp.source_file,
                ecosystem=comp.ecosystem.value,
                component_type=comp.component_type.value,
            )
            self._session.add(db_comp)
            db_components.append(db_comp)

        await self._session.flush()
        return db_components

    async def get_by_project(self, project_id: str) -> list[ProjectComponentDB]:
        """Get all components for a project."""
        result = await self._session.execute(
            select(ProjectComponentDB).where(ProjectComponentDB.project_id == project_id)
        )
        return list(result.scalars().all())

    async def get_by_id(self, component_id: str) -> ProjectComponentDB | None:
        """Get a component by ID."""
        result = await self._session.execute(
            select(ProjectComponentDB).where(ProjectComponentDB.id == component_id)
        )
        return result.scalar_one_or_none()

    async def get_by_project_paginated(
        self, project_id: str, page: int = 1, page_size: int = 20
    ) -> tuple[list[ProjectComponentDB], int]:
        """Get paginated components for a project."""
        offset = (page - 1) * page_size
        total_stmt = (
            select(func.count())
            .select_from(ProjectComponentDB)
            .where(ProjectComponentDB.project_id == project_id)
        )
        total_res = await self._session.execute(total_stmt)
        total = total_res.scalar_one() or 0

        stmt = (
            select(ProjectComponentDB)
            .where(ProjectComponentDB.project_id == project_id)
            .order_by(ProjectComponentDB.name.asc())
            .offset(offset)
            .limit(page_size)
        )
        result = await self._session.execute(stmt)
        return list(result.scalars().all()), total


class SourceRepository:
    """Data access for vulnerability sources."""

    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    async def get_or_create(
        self,
        name: str,
        source_type: str,
        url: str = "",
    ) -> tuple[VulnerabilitySourceDB, bool]:
        """Get or create a vulnerability source."""
        result = await self._session.execute(
            select(VulnerabilitySourceDB).where(VulnerabilitySourceDB.name == name)
        )
        existing = result.scalar_one_or_none()
        if existing is not None:
            return existing, False

        source = VulnerabilitySourceDB(
            name=name,
            source_type=source_type,
            url=url,
        )
        self._session.add(source)
        await self._session.flush()
        return source, True

    async def update_sync_status(
        self,
        source_id: str,
        status: SourceStatus,
        record_count: int = 0,
        error: str | None = None,
    ) -> None:
        """Update the sync status of a source."""
        values: dict = {
            "status": status.value,
            "record_count": record_count,
            "last_error": error,
        }
        if status == SourceStatus.ACTIVE:
            values["last_sync"] = datetime.now(UTC)

        await self._session.execute(
            update(VulnerabilitySourceDB)
            .where(VulnerabilitySourceDB.id == source_id)
            .values(**values)
        )

    async def get_by_name(self, name: str) -> VulnerabilitySourceDB | None:
        """Get a source by name."""
        result = await self._session.execute(
            select(VulnerabilitySourceDB).where(VulnerabilitySourceDB.name == name)
        )
        return result.scalar_one_or_none()

    async def list_all(self) -> list[VulnerabilitySourceDB]:
        """List all vulnerability sources."""
        result = await self._session.execute(select(VulnerabilitySourceDB))
        return list(result.scalars().all())

    async def get_by_id(self, source_id: str) -> VulnerabilitySourceDB | None:
        """Get a source by ID."""
        result = await self._session.execute(
            select(VulnerabilitySourceDB).where(VulnerabilitySourceDB.id == source_id)
        )
        return result.scalar_one_or_none()

    def to_source_info(self, db_source: VulnerabilitySourceDB) -> SourceInfo:
        """Convert a DB source to a domain SourceInfo."""
        return SourceInfo(
            name=db_source.name,
            source_type=db_source.source_type,
            url=db_source.url,
            status=SourceStatus(db_source.status),
            last_sync=db_source.last_sync,
            record_count=db_source.record_count,
            last_error=db_source.last_error,
        )


class VulnerabilityRepository:
    """Data access for vulnerabilities."""

    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    async def upsert_vulnerabilities(
        self,
        source_id: str,
        records: list[VulnerabilityRecord],
    ) -> int:
        """Insert or update vulnerabilities for a source.

        Replaces all existing vulnerabilities for the source.
        Returns the number of records saved.
        """
        # Delete existing vulnerabilities for this source
        await self._session.execute(
            delete(VulnerabilityDB).where(VulnerabilityDB.source_id == source_id)
        )

        for record in records:
            db_vuln = VulnerabilityDB(
                cve_id=record.cve_id,
                source_id=source_id,
                vendor_project=record.vendor_project,
                product=record.product,
                vulnerability_name=record.vulnerability_name,
                short_description=record.short_description,
                required_action=record.required_action,
                date_added=record.date_added.isoformat() if record.date_added else None,
                due_date=record.due_date.isoformat() if record.due_date else None,
                known_ransomware_use=record.known_ransomware_use,
                cwes=json.dumps(record.cwes),
                notes=record.notes,
            )
            self._session.add(db_vuln)

        await self._session.flush()
        return len(records)

    async def get_all_by_source(self, source_id: str) -> list[VulnerabilityDB]:
        """Get all vulnerabilities from a specific source."""
        result = await self._session.execute(
            select(VulnerabilityDB).where(VulnerabilityDB.source_id == source_id)
        )
        return list(result.scalars().all())

    async def get_all(self) -> list[VulnerabilityDB]:
        """Get all vulnerabilities from all sources."""
        result = await self._session.execute(select(VulnerabilityDB))
        return list(result.scalars().all())

    async def get_by_cve(self, cve_id: str) -> list[VulnerabilityDB]:
        """Get vulnerabilities by CVE ID."""
        result = await self._session.execute(
            select(VulnerabilityDB).where(VulnerabilityDB.cve_id == cve_id)
        )
        return list(result.scalars().all())

    async def get_by_id(self, vuln_id: str) -> VulnerabilityDB | None:
        """Get a vulnerability by ID."""
        result = await self._session.execute(
            select(VulnerabilityDB).where(VulnerabilityDB.id == vuln_id)
        )
        return result.scalar_one_or_none()

    async def list_filtered_paginated(
        self,
        cve: str | None = None,
        source: str | None = None,
        vendor: str | None = None,
        product: str | None = None,
        page: int = 1,
        page_size: int = 20,
    ) -> tuple[list[VulnerabilityDB], int]:
        """List vulnerabilities with optional filters and pagination."""
        offset = (page - 1) * page_size
        conditions = []
        if cve:
            conditions.append(VulnerabilityDB.cve_id.ilike(f"%{cve}%"))
        if vendor:
            conditions.append(VulnerabilityDB.vendor_project.ilike(f"%{vendor}%"))
        if product:
            conditions.append(VulnerabilityDB.product.ilike(f"%{product}%"))
        if source:
            source_subquery = select(VulnerabilitySourceDB.id).where(
                (VulnerabilitySourceDB.name.ilike(f"%{source}%"))
                | (VulnerabilitySourceDB.id == source)
            )
            conditions.append(VulnerabilityDB.source_id.in_(source_subquery))

        count_stmt = select(func.count()).select_from(VulnerabilityDB)
        if conditions:
            count_stmt = count_stmt.where(*conditions)
        total_res = await self._session.execute(count_stmt)
        total = total_res.scalar_one() or 0

        stmt = select(VulnerabilityDB).order_by(VulnerabilityDB.cve_id.asc())
        if conditions:
            stmt = stmt.where(*conditions)
        stmt = stmt.offset(offset).limit(page_size)

        res = await self._session.execute(stmt)
        return list(res.scalars().all()), total

    async def count_by_source(self, source_id: str) -> int:
        """Count vulnerabilities for a source."""
        result = await self._session.execute(
            select(VulnerabilityDB).where(VulnerabilityDB.source_id == source_id)
        )
        return len(result.scalars().all())

    def to_domain(self, db_vuln: VulnerabilityDB) -> VulnerabilityRecord:
        """Convert a DB vulnerability to a domain VulnerabilityRecord."""
        from datetime import date

        date_added = None
        if db_vuln.date_added:
            try:
                d = date.fromisoformat(db_vuln.date_added)
                date_added = datetime(d.year, d.month, d.day, tzinfo=UTC)
            except ValueError:
                pass

        due_date = None
        if db_vuln.due_date:
            try:
                d = date.fromisoformat(db_vuln.due_date)
                due_date = datetime(d.year, d.month, d.day, tzinfo=UTC)
            except ValueError:
                pass

        cwes = []
        with contextlib.suppress(json.JSONDecodeError, TypeError):
            cwes = json.loads(db_vuln.cwes)

        return VulnerabilityRecord(
            cve_id=db_vuln.cve_id,
            source_name="",  # Will be set by caller if needed
            vendor_project=db_vuln.vendor_project,
            product=db_vuln.product,
            vulnerability_name=db_vuln.vulnerability_name,
            short_description=db_vuln.short_description,
            required_action=db_vuln.required_action,
            date_added=date_added,
            due_date=due_date,
            known_ransomware_use=db_vuln.known_ransomware_use,
            cwes=cwes,
            notes=db_vuln.notes,
        )


class ScanRepository:
    """Data access for scans."""

    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    async def create(self, project_id: str) -> ScanDB:
        """Create a new scan record."""
        scan = ScanDB(project_id=project_id, status="running")
        self._session.add(scan)
        await self._session.flush()
        return scan

    async def complete(
        self,
        scan_id: str,
        *,
        components_found: int = 0,
        vulnerabilities_found: int = 0,
        kev_matches: int = 0,
        duration_seconds: float = 0.0,
        error: str | None = None,
    ) -> None:
        """Mark a scan as completed."""
        status = "failed" if error else "completed"
        await self._session.execute(
            update(ScanDB)
            .where(ScanDB.id == scan_id)
            .values(
                status=status,
                components_found=components_found,
                vulnerabilities_found=vulnerabilities_found,
                kev_matches=kev_matches,
                duration_seconds=duration_seconds,
                completed_at=datetime.now(UTC),
                error=error,
            )
        )

    async def get_by_id(self, scan_id: str) -> ScanDB | None:
        """Get a scan by ID."""
        result = await self._session.execute(select(ScanDB).where(ScanDB.id == scan_id))
        return result.scalar_one_or_none()

    async def get_by_project(self, project_id: str) -> list[ScanDB]:
        """Get all scans for a project."""
        result = await self._session.execute(
            select(ScanDB)
            .where(ScanDB.project_id == project_id)
            .order_by(ScanDB.started_at.desc())
        )
        return list(result.scalars().all())

    async def list_paginated(
        self,
        project_id: str | None = None,
        page: int = 1,
        page_size: int = 20,
    ) -> tuple[list[ScanDB], int]:
        """List scans with optional project filtering and pagination."""
        offset = (page - 1) * page_size
        count_stmt = select(func.count()).select_from(ScanDB)
        if project_id:
            count_stmt = count_stmt.where(ScanDB.project_id == project_id)
        total_res = await self._session.execute(count_stmt)
        total = total_res.scalar_one() or 0

        stmt = select(ScanDB).order_by(ScanDB.started_at.desc())
        if project_id:
            stmt = stmt.where(ScanDB.project_id == project_id)
        stmt = stmt.offset(offset).limit(page_size)

        result = await self._session.execute(stmt)
        return list(result.scalars().all()), total


class MatchRepository:
    """Data access for vulnerability matches."""

    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    async def save_matches(
        self,
        scan_id: str,
        matches: list[MatchResult],
        component_id_map: dict[str, str],
        vulnerability_id_map: dict[str, str],
    ) -> list[MatchDB]:
        """Save match results for a scan.

        Args:
            scan_id: The scan ID.
            matches: List of domain match results.
            component_id_map: Maps normalized component name to DB component ID.
            vulnerability_id_map: Maps CVE ID to DB vulnerability ID.
        """
        db_matches = []
        for match in matches:
            comp_key = match.component.normalized_name()
            vuln_key = match.vulnerability.cve_id

            comp_id = component_id_map.get(comp_key)
            vuln_id = vulnerability_id_map.get(vuln_key)
            if comp_id is None or vuln_id is None:
                continue

            db_match = MatchDB(
                scan_id=scan_id,
                component_id=comp_id,
                vulnerability_id=vuln_id,
                match_type=match.match_type.value,
                match_confidence=match.match_confidence,
                applicability=match.applicability.value,
                evidence=json.dumps(match.evidence),
            )
            self._session.add(db_match)
            db_matches.append(db_match)

        await self._session.flush()
        return db_matches

    async def get_by_scan(self, scan_id: str) -> list[MatchDB]:
        """Get all matches for a scan."""
        result = await self._session.execute(select(MatchDB).where(MatchDB.scan_id == scan_id))
        return list(result.scalars().all())

    async def get_by_id(self, match_id: str) -> MatchDB | None:
        """Get a match by ID with joined related records."""
        from sqlalchemy.orm import selectinload

        stmt = (
            select(MatchDB)
            .where(MatchDB.id == match_id)
            .options(
                selectinload(MatchDB.component),
                selectinload(MatchDB.vulnerability),
                selectinload(MatchDB.ai_analysis),
                selectinload(MatchDB.decision_result),
                selectinload(MatchDB.risk_assessment),
            )
        )
        result = await self._session.execute(stmt)
        return result.scalar_one_or_none()


class AIAnalysisRepository:
    """Data access for AI contextual analysis results."""

    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    async def save_analysis(self, match_id: str, analysis: AIAnalysis) -> AIAnalysisDB:
        """Create or update an AI analysis for a match."""
        result = await self._session.execute(
            select(AIAnalysisDB).where(AIAnalysisDB.match_id == match_id)
        )
        db_obj = result.scalar_one_or_none()

        if db_obj is None:
            db_obj = AIAnalysisDB(
                match_id=match_id,
                provider=analysis.provider,
                model=analysis.model,
                explanation=analysis.explanation,
                evidence=json.dumps(analysis.evidence),
                contextual_findings=json.dumps(analysis.contextual_findings),
                requires_human_review=analysis.requires_human_review,
                duration_seconds=analysis.analysis_duration_seconds,
                tokens_used=analysis.tokens_used,
            )
            self._session.add(db_obj)
        else:
            db_obj.provider = analysis.provider
            db_obj.model = analysis.model
            db_obj.explanation = analysis.explanation
            db_obj.evidence = json.dumps(analysis.evidence)
            db_obj.contextual_findings = json.dumps(analysis.contextual_findings)
            db_obj.requires_human_review = analysis.requires_human_review
            db_obj.duration_seconds = analysis.analysis_duration_seconds
            db_obj.tokens_used = analysis.tokens_used

        await self._session.flush()
        return db_obj

    async def get_by_match_id(self, match_id: str) -> AIAnalysisDB | None:
        """Get the AI analysis for a specific match."""
        result = await self._session.execute(
            select(AIAnalysisDB).where(AIAnalysisDB.match_id == match_id)
        )
        return result.scalar_one_or_none()

    @staticmethod
    def to_domain(db_analysis: AIAnalysisDB) -> AIAnalysis:
        """Convert a database AIAnalysisDB into an AIAnalysis domain model."""
        return AIAnalysis(
            provider=db_analysis.provider,
            model=db_analysis.model,
            explanation=db_analysis.explanation,
            evidence=json.loads(db_analysis.evidence),
            contextual_findings=json.loads(db_analysis.contextual_findings),
            requires_human_review=db_analysis.requires_human_review,
            analysis_duration_seconds=db_analysis.duration_seconds,
            tokens_used=db_analysis.tokens_used,
            analyzed_at=db_analysis.created_at,
        )


class DecisionRepository:
    """Data access for probabilistic decision results."""

    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    async def save_decision(self, match_id: str, decision: DecisionResult) -> DecisionResultDB:
        """Create or update a decision result for a match."""
        result = await self._session.execute(
            select(DecisionResultDB).where(DecisionResultDB.match_id == match_id)
        )
        db_obj = result.scalar_one_or_none()

        raw_str = json.dumps(decision.raw_response) if decision.raw_response else None

        if db_obj is None:
            db_obj = DecisionResultDB(
                match_id=match_id,
                provider=decision.provider,
                model=decision.model,
                responses=json.dumps(decision.responses),
                decision_probabilities=json.dumps(decision.decision_probabilities),
                applicability_probability=decision.applicability_probability,
                urgency_score=decision.urgency_score,
                latency_seconds=decision.latency_seconds,
                raw_response=raw_str,
            )
            self._session.add(db_obj)
        else:
            db_obj.provider = decision.provider
            db_obj.model = decision.model
            db_obj.responses = json.dumps(decision.responses)
            db_obj.decision_probabilities = json.dumps(decision.decision_probabilities)
            db_obj.applicability_probability = decision.applicability_probability
            db_obj.urgency_score = decision.urgency_score
            db_obj.latency_seconds = decision.latency_seconds
            db_obj.raw_response = raw_str

        await self._session.flush()
        return db_obj

    async def get_by_match_id(self, match_id: str) -> DecisionResultDB | None:
        """Get the decision result for a specific match."""
        result = await self._session.execute(
            select(DecisionResultDB).where(DecisionResultDB.match_id == match_id)
        )
        return result.scalar_one_or_none()

    @staticmethod
    def to_domain(db_decision: DecisionResultDB) -> DecisionResult:
        """Convert a database DecisionResultDB into a DecisionResult domain model."""
        raw_dict = json.loads(db_decision.raw_response) if db_decision.raw_response else None
        return DecisionResult(
            provider=db_decision.provider,
            model=db_decision.model,
            responses=json.loads(db_decision.responses),
            decision_probabilities=json.loads(db_decision.decision_probabilities),
            applicability_probability=db_decision.applicability_probability,
            urgency_score=db_decision.urgency_score,
            latency_seconds=db_decision.latency_seconds,
            timestamp=db_decision.created_at,
            raw_response=raw_dict,
        )


class RiskAssessmentRepository:
    """Data access for final deterministic risk assessments."""

    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    async def save_assessment(self, match_id: str, assessment: RiskAssessment) -> RiskAssessmentDB:
        """Create or update a risk assessment for a match."""
        result = await self._session.execute(
            select(RiskAssessmentDB).where(RiskAssessmentDB.match_id == match_id)
        )
        db_obj = result.scalar_one_or_none()

        if db_obj is None:
            db_obj = RiskAssessmentDB(
                match_id=match_id,
                status=assessment.status.value,
                risk_level=assessment.risk_level.value,
                certainty=assessment.certainty,
                rationale=assessment.rationale,
                recommended_action=assessment.recommended_action,
                requires_human_review=assessment.requires_human_review,
                rule_ids=json.dumps(assessment.rule_ids),
            )
            self._session.add(db_obj)
        else:
            db_obj.status = assessment.status.value
            db_obj.risk_level = assessment.risk_level.value
            db_obj.certainty = assessment.certainty
            db_obj.rationale = assessment.rationale
            db_obj.recommended_action = assessment.recommended_action
            db_obj.requires_human_review = assessment.requires_human_review
            db_obj.rule_ids = json.dumps(assessment.rule_ids)

        await self._session.flush()
        return db_obj

    async def get_by_match_id(self, match_id: str) -> RiskAssessmentDB | None:
        """Get the risk assessment for a specific match."""
        result = await self._session.execute(
            select(RiskAssessmentDB).where(RiskAssessmentDB.match_id == match_id)
        )
        return result.scalar_one_or_none()

    @staticmethod
    def to_domain(db_assessment: RiskAssessmentDB) -> RiskAssessment:
        """Convert a database RiskAssessmentDB into a RiskAssessment domain model."""
        return RiskAssessment(
            status=RiskStatus(db_assessment.status),
            risk_level=RiskLevel(db_assessment.risk_level),
            certainty=db_assessment.certainty,
            rationale=db_assessment.rationale,
            recommended_action=db_assessment.recommended_action,
            requires_human_review=db_assessment.requires_human_review,
            rule_ids=json.loads(db_assessment.rule_ids),
            assessed_at=db_assessment.created_at,
        )
