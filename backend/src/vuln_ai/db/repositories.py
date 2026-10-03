"""Repository pattern for database access.

All database operations go through repositories.
The rest of the system should never execute SQL directly.
"""

from __future__ import annotations

import contextlib
import json
import uuid
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import and_, delete, func, or_, select, update
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from vuln_ai.ai.models import AIAnalysis, DecisionResult
from vuln_ai.container.models import ContainerImage, ImageLayer
from vuln_ai.core.models import (
    AffectedVersionRange,
    Applicability,
    ComponentType,
    DependencyScope,
    DependencyType,
    DetectedComponent,
    Ecosystem,
    IdentifierType,
    MatchEvidence,
    MatchResult,
    MatchType,
    SourceInfo,
    SourceStatus,
    VersionType,
    VulnerabilityIdentifier,
    VulnerabilityRecord,
    VulnerabilitySourceRecord,
)
from vuln_ai.db.models import (
    AffectedVersionRangeDB,
    AIAnalysisDB,
    ContainerImageComponentDB,
    ContainerImageDB,
    ContainerLayerDB,
    DecisionResultDB,
    DependencyEdgeDB,
    MatchDB,
    MatchEvidenceDB,
    PolicyDB,
    PolicyEvaluationDB,
    PolicyRuleDB,
    ProjectComponentDB,
    ProjectDB,
    RiskAssessmentDB,
    ScanDB,
    SourceConflictDB,
    SuppressionDB,
    VulnerabilityDB,
    VulnerabilityIdentifierDB,
    VulnerabilitySourceDB,
    VulnerabilitySourceRecordDB,
)
from vuln_ai.matching.conflict import SourceConflict
from vuln_ai.policy.models import (
    Policy,
    PolicyAction,
    PolicyCondition,
    PolicyEvaluationResult,
    PolicyRule,
    PolicyThresholds,
    Suppression,
    SuppressionMatchCriteria,
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
            ver_type = (
                comp.version_type.value
                if hasattr(comp.version_type, "value")
                else str(comp.version_type)
            )
            eco_val = (
                comp.ecosystem.value if hasattr(comp.ecosystem, "value") else str(comp.ecosystem)
            )
            comp_type_val = (
                comp.component_type.value
                if hasattr(comp.component_type, "value")
                else str(comp.component_type)
            )
            dep_type_val = (
                comp.dependency_type.value
                if hasattr(comp.dependency_type, "value")
                else str(getattr(comp, "dependency_type", "direct"))
            )
            scope_val = (
                comp.scope.value
                if hasattr(comp.scope, "value")
                else str(getattr(comp, "scope", "runtime"))
            )

            db_comp = ProjectComponentDB(
                project_id=project_id,
                name=comp.name,
                version=comp.version,
                version_type=ver_type,
                version_constraint=comp.version_constraint,
                source_file=comp.source_file,
                ecosystem=eco_val,
                component_type=comp_type_val,
                is_direct=getattr(comp, "is_direct", True),
                dependency_type=dep_type_val,
                scope=scope_val,
                manifest_source=getattr(comp, "manifest_source", None),
                lockfile_source=getattr(comp, "lockfile_source", None),
                parent_name=getattr(comp, "parent_name", None),
                dependency_path=json.dumps(getattr(comp, "dependency_path", [])),
            )
            self._session.add(db_comp)
            db_components.append(db_comp)

        await self._session.flush()
        return db_components

    async def save_dependency_edges(
        self,
        project_id: str,
        edges: list[Any],
    ) -> list[DependencyEdgeDB]:
        """Save dependency relations for a project."""
        await self._session.execute(
            delete(DependencyEdgeDB).where(DependencyEdgeDB.project_id == project_id)
        )
        db_edges = []
        for edge in edges:
            scope_val = (
                edge.scope.value
                if hasattr(edge.scope, "value")
                else str(getattr(edge, "scope", "runtime"))
            )
            db_edge = DependencyEdgeDB(
                project_id=project_id,
                parent_name=edge.parent_name,
                parent_version=getattr(edge, "parent_version", None),
                child_name=edge.child_name,
                child_version=getattr(edge, "child_version", None),
                scope=scope_val,
                requirement=getattr(edge, "requirement", None),
            )
            self._session.add(db_edge)
            db_edges.append(db_edge)

        await self._session.flush()
        return db_edges

    async def get_dependency_edges(self, project_id: str) -> list[DependencyEdgeDB]:
        """Get all dependency edges for a project."""
        result = await self._session.execute(
            select(DependencyEdgeDB).where(DependencyEdgeDB.project_id == project_id)
        )
        return list(result.scalars().all())

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
        """Insert or update canonical vulnerabilities for a source.

        Deduplicates against existing vulnerabilities using known identifiers and aliases.
        Preserves canonical UUID identity, updates source records, and idempotently adds ranges.
        Cleans up obsolete vulnerabilities solely owned by this source if not present in the new set.
        """
        touched_vuln_ids: set[str] = set()

        for record in records:
            canonical_id = record.canonical_id or record.cve_id or ""

            # Gather candidate keys for deduplication
            candidate_keys: list[str] = []
            if canonical_id:
                candidate_keys.append(canonical_id)
            if record.cve_id and record.cve_id not in candidate_keys:
                candidate_keys.append(record.cve_id)
            for ident in record.identifiers:
                if ident.identifier not in candidate_keys:
                    candidate_keys.append(ident.identifier)

            existing_vuln: VulnerabilityDB | None = None
            for key in candidate_keys:
                existing_vuln = await self.get_by_identifier(key)
                if existing_vuln:
                    break

            if existing_vuln:
                db_vuln = existing_vuln
                # Deterministic canonical_id promotion: CVE > GHSA > OSV
                if not db_vuln.canonical_id.upper().startswith("CVE-"):
                    cves = sorted([k for k in candidate_keys if k.upper().startswith("CVE-")])
                    if cves:
                        db_vuln.canonical_id = cves[0]
                        db_vuln.cve_id = cves[0]
                    elif not db_vuln.canonical_id.upper().startswith("GHSA-"):
                        ghsas = sorted(
                            [k for k in candidate_keys if k.upper().startswith("GHSA-")]
                        )
                        if ghsas:
                            db_vuln.canonical_id = ghsas[0]

                if not db_vuln.vulnerability_name and record.vulnerability_name:
                    db_vuln.vulnerability_name = record.vulnerability_name
                if not db_vuln.short_description and record.short_description:
                    db_vuln.short_description = record.short_description
                if not db_vuln.vendor_project and record.vendor_project:
                    db_vuln.vendor_project = record.vendor_project
                if not db_vuln.product and record.product:
                    db_vuln.product = record.product
                if not db_vuln.required_action and record.required_action:
                    db_vuln.required_action = record.required_action
                if not db_vuln.date_added and record.date_added:
                    db_vuln.date_added = record.date_added.isoformat()
                if not db_vuln.due_date and record.due_date:
                    db_vuln.due_date = record.due_date.isoformat()
                if not db_vuln.notes and record.notes:
                    db_vuln.notes = record.notes
                if (not db_vuln.cwes or db_vuln.cwes == "[]") and record.cwes:
                    db_vuln.cwes = json.dumps(record.cwes)
                if not db_vuln.severity and record.severity:
                    db_vuln.severity = record.severity
                if db_vuln.cvss_score is None and record.cvss_score is not None:
                    db_vuln.cvss_score = record.cvss_score
                if (
                    not db_vuln.known_ransomware_use or db_vuln.known_ransomware_use == "Unknown"
                ) and record.known_ransomware_use != "Unknown":
                    db_vuln.known_ransomware_use = record.known_ransomware_use
            else:
                db_vuln = VulnerabilityDB(
                    canonical_id=canonical_id,
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
                    severity=record.severity,
                    cvss_score=record.cvss_score,
                )
                self._session.add(db_vuln)
                await self._session.flush()

            touched_vuln_ids.add(db_vuln.id)

            # 1. Deduplicate & Save Identifiers
            existing_idents_list = await self.get_identifiers(db_vuln.id)
            known_idents = {i.identifier for i in existing_idents_list}

            if db_vuln.canonical_id and db_vuln.canonical_id not in known_idents:
                known_idents.add(db_vuln.canonical_id)
                self._session.add(
                    VulnerabilityIdentifierDB(
                        vulnerability_id=db_vuln.id,
                        identifier=db_vuln.canonical_id,
                        identifier_type="cve"
                        if db_vuln.canonical_id.upper().startswith("CVE-")
                        else "canonical",
                        source=record.source_name,
                    )
                )

            for ident in record.identifiers:
                if ident.identifier not in known_idents:
                    known_idents.add(ident.identifier)
                    self._session.add(
                        VulnerabilityIdentifierDB(
                            vulnerability_id=db_vuln.id,
                            identifier=ident.identifier,
                            identifier_type=str(ident.identifier_type),
                            source=ident.source,
                        )
                    )

            # 2. Deduplicate & Save Source Records
            existing_srs = await self.get_source_records(db_vuln.id)
            sr_by_ident = {(sr.source_id, sr.source_identifier): sr for sr in existing_srs}

            if record.source_records:
                for sr in record.source_records:
                    payload_str = (
                        json.dumps(sr.raw_payload)
                        if isinstance(sr.raw_payload, (dict, list))
                        else (sr.raw_payload or "{}")
                    )
                    sr_key = (source_id, sr.source_identifier)
                    if sr_key in sr_by_ident:
                        existing_sr = sr_by_ident[sr_key]
                        existing_sr.raw_payload = payload_str
                        existing_sr.has_kev_evidence = sr.has_kev_evidence
                        existing_sr.has_affected_range = sr.has_affected_range
                        existing_sr.synced_at = datetime.now(UTC)
                    else:
                        self._session.add(
                            VulnerabilitySourceRecordDB(
                                vulnerability_id=db_vuln.id,
                                source_id=source_id,
                                source_name=sr.source_name,
                                source_identifier=sr.source_identifier,
                                has_kev_evidence=sr.has_kev_evidence,
                                has_affected_range=sr.has_affected_range,
                                raw_payload=payload_str,
                            )
                        )
            else:
                has_kev = (
                    record.known_ransomware_use.lower() in ("known", "yes")
                    or "kev" in record.source_name.lower()
                )
                source_ident = canonical_id or db_vuln.canonical_id
                sr_key = (source_id, source_ident)
                if sr_key in sr_by_ident:
                    existing_sr = sr_by_ident[sr_key]
                    existing_sr.has_kev_evidence = has_kev
                    existing_sr.has_affected_range = bool(record.affected_ranges)
                    existing_sr.synced_at = datetime.now(UTC)
                else:
                    self._session.add(
                        VulnerabilitySourceRecordDB(
                            vulnerability_id=db_vuln.id,
                            source_id=source_id,
                            source_name=record.source_name,
                            source_identifier=source_ident,
                            has_kev_evidence=has_kev,
                            has_affected_range=bool(record.affected_ranges),
                            raw_payload=json.dumps(
                                {
                                    "vendor": record.vendor_project,
                                    "product": record.product,
                                    "action": record.required_action,
                                }
                            ),
                        )
                    )

            # 3. Deduplicate & Save Affected Ranges
            existing_ranges = await self.get_affected_ranges(db_vuln.id)
            known_ranges = {
                (
                    r.ecosystem,
                    r.package_name,
                    r.range_type,
                    r.introduced,
                    r.fixed,
                    r.last_affected,
                    getattr(r, "limit", None),
                    r.source_name,
                )
                for r in existing_ranges
            }

            for ar in record.affected_ranges:
                r_key = (
                    str(ar.ecosystem),
                    ar.package_name,
                    ar.range_type,
                    ar.introduced,
                    ar.fixed,
                    ar.last_affected,
                    ar.limit,
                    ar.source_name,
                )
                if r_key not in known_ranges:
                    known_ranges.add(r_key)
                    self._session.add(
                        AffectedVersionRangeDB(
                            vulnerability_id=db_vuln.id,
                            ecosystem=str(ar.ecosystem),
                            package_name=ar.package_name,
                            range_type=ar.range_type,
                            introduced=ar.introduced,
                            fixed=ar.fixed,
                            last_affected=ar.last_affected,
                            limit=ar.limit,
                            raw_range=ar.raw_range,
                            source_name=ar.source_name,
                        )
                    )

        # Cleanup obsolete vulnerabilities solely owned by this source if full batch replaced
        if records:
            obsolete_stmt = select(VulnerabilityDB.id).where(
                VulnerabilityDB.source_id == source_id,
                VulnerabilityDB.id.not_in(touched_vuln_ids),
            )
            obsolete_res = await self._session.execute(obsolete_stmt)
            obsolete_ids = list(obsolete_res.scalars().all())
            for obs_id in obsolete_ids:
                other_sources = await self._session.execute(
                    select(VulnerabilitySourceRecordDB).where(
                        VulnerabilitySourceRecordDB.vulnerability_id == obs_id,
                        VulnerabilitySourceRecordDB.source_id != source_id,
                    )
                )
                if not other_sources.scalars().first():
                    await self._session.execute(
                        delete(VulnerabilityDB).where(VulnerabilityDB.id == obs_id)
                    )
                else:
                    await self._session.execute(
                        delete(VulnerabilitySourceRecordDB).where(
                            VulnerabilitySourceRecordDB.vulnerability_id == obs_id,
                            VulnerabilitySourceRecordDB.source_id == source_id,
                        )
                    )
        elif not records:
            await self._session.execute(
                delete(VulnerabilityDB).where(VulnerabilityDB.source_id == source_id)
            )

        await self._session.flush()
        return len(records)

    _LOAD_OPTIONS = (
        selectinload(VulnerabilityDB.affected_ranges),
        selectinload(VulnerabilityDB.identifiers),
        selectinload(VulnerabilityDB.source_records),
        selectinload(VulnerabilityDB.source),
    )

    async def get_all_by_source(self, source_id: str) -> list[VulnerabilityDB]:
        """Get all vulnerabilities from a specific source."""
        result = await self._session.execute(
            select(VulnerabilityDB)
            .where(VulnerabilityDB.source_id == source_id)
            .options(*self._LOAD_OPTIONS)
        )
        return list(result.scalars().all())

    async def get_all(self) -> list[VulnerabilityDB]:
        """Get all vulnerabilities from all sources."""
        result = await self._session.execute(select(VulnerabilityDB).options(*self._LOAD_OPTIONS))
        return list(result.scalars().all())

    async def get_by_canonical_id(self, canonical_id: str) -> VulnerabilityDB | None:
        """Get vulnerability by canonical ID."""
        result = await self._session.execute(
            select(VulnerabilityDB)
            .where(VulnerabilityDB.canonical_id == canonical_id)
            .options(*self._LOAD_OPTIONS)
        )
        return result.scalar_one_or_none()

    async def get_by_identifier(self, identifier: str) -> VulnerabilityDB | None:
        """Find a vulnerability by any identifier or alias."""
        # Direct check on canonical_id or cve_id
        result = await self._session.execute(
            select(VulnerabilityDB)
            .where(
                (VulnerabilityDB.canonical_id == identifier)
                | (VulnerabilityDB.cve_id == identifier)
            )
            .options(*self._LOAD_OPTIONS)
        )
        vuln = result.scalar_one_or_none()
        if vuln:
            return vuln

        # Check aliases in vulnerability_identifiers
        ident_res = await self._session.execute(
            select(VulnerabilityIdentifierDB).where(
                VulnerabilityIdentifierDB.identifier == identifier
            )
        )
        ident_record = ident_res.scalar_one_or_none()
        if ident_record:
            return await self.get_by_id(ident_record.vulnerability_id)
        return None

    async def find_by_package(self, ecosystem: str, package_name: str) -> list[VulnerabilityDB]:
        """Find vulnerabilities with affected version ranges matching ecosystem and package."""
        stmt = (
            select(VulnerabilityDB)
            .join(
                AffectedVersionRangeDB,
                VulnerabilityDB.id == AffectedVersionRangeDB.vulnerability_id,
            )
            .where(
                AffectedVersionRangeDB.ecosystem == ecosystem,
                AffectedVersionRangeDB.package_name == package_name,
            )
            .options(*self._LOAD_OPTIONS)
            .distinct()
        )
        result = await self._session.execute(stmt)
        return list(result.scalars().all())

    async def find_candidates_for_components(
        self, components: list[DetectedComponent]
    ) -> list[VulnerabilityDB]:
        """Find candidate vulnerabilities matching detected components by package or product."""
        if not components:
            return []

        # Batch in chunks of 100 to prevent SQLite parameter limit issues on large dependency graphs
        if len(components) > 100:
            found_ids: set[str] = set()
            all_candidates: list[VulnerabilityDB] = []
            chunk_size = 100
            for i in range(0, len(components), chunk_size):
                chunk = components[i : i + chunk_size]
                candidates = await self.find_candidates_for_components(chunk)
                for c in candidates:
                    if c.id not in found_ids:
                        found_ids.add(c.id)
                        all_candidates.append(c)
            return all_candidates

        package_criteria = []
        product_names = set()
        for comp in components:
            eco = (
                comp.ecosystem.value
                if hasattr(comp.ecosystem, "value")
                else str(comp.ecosystem).lower()
            )
            name = comp.name
            norm_name = comp.normalized_name()
            package_criteria.append((eco, name))
            if norm_name != name:
                package_criteria.append((eco, norm_name))
            product_names.add(name)
            product_names.add(norm_name)

        # 1. Match via affected version ranges
        range_conditions = []
        for eco, pkg in package_criteria:
            range_conditions.append(
                and_(
                    AffectedVersionRangeDB.ecosystem == eco,
                    AffectedVersionRangeDB.package_name == pkg,
                )
            )

        # 2. Match via product or vendor (for CISA KEV / legacy product catalog)
        product_conditions = []
        for p in product_names:
            product_conditions.append(VulnerabilityDB.product.ilike(p))
            product_conditions.append(VulnerabilityDB.vendor_project.ilike(p))

        # Combine
        combined_conditions = []
        if range_conditions:
            combined_conditions.append(
                VulnerabilityDB.id.in_(
                    select(AffectedVersionRangeDB.vulnerability_id).where(or_(*range_conditions))
                )
            )
        if product_conditions:
            combined_conditions.append(or_(*product_conditions))

        if not combined_conditions:
            return []

        stmt = (
            select(VulnerabilityDB)
            .where(or_(*combined_conditions))
            .options(*self._LOAD_OPTIONS)
            .distinct()
        )
        result = await self._session.execute(stmt)
        return list(result.scalars().all())

    async def get_by_cve(self, cve_id: str) -> list[VulnerabilityDB]:
        """Get vulnerabilities by CVE ID."""
        result = await self._session.execute(
            select(VulnerabilityDB)
            .where((VulnerabilityDB.cve_id == cve_id) | (VulnerabilityDB.canonical_id == cve_id))
            .options(*self._LOAD_OPTIONS)
        )
        vulns = list(result.scalars().all())
        if not vulns:
            by_ident = await self.get_by_identifier(cve_id)
            if by_ident:
                return [by_ident]
        return vulns

    async def get_by_id(self, vuln_id: str) -> VulnerabilityDB | None:
        """Get a vulnerability by ID."""
        result = await self._session.execute(
            select(VulnerabilityDB)
            .where(VulnerabilityDB.id == vuln_id)
            .options(*self._LOAD_OPTIONS)
        )
        return result.scalar_one_or_none()

    async def get_identifiers(self, vuln_id: str) -> list[VulnerabilityIdentifierDB]:
        """Get all identifiers for a vulnerability."""
        result = await self._session.execute(
            select(VulnerabilityIdentifierDB).where(
                VulnerabilityIdentifierDB.vulnerability_id == vuln_id
            )
        )
        return list(result.scalars().all())

    async def get_affected_ranges(self, vuln_id: str) -> list[AffectedVersionRangeDB]:
        """Get all affected version ranges for a vulnerability."""
        result = await self._session.execute(
            select(AffectedVersionRangeDB).where(
                AffectedVersionRangeDB.vulnerability_id == vuln_id
            )
        )
        return list(result.scalars().all())

    async def get_source_records(self, vuln_id: str) -> list[VulnerabilitySourceRecordDB]:
        """Get all source evidence records for a vulnerability."""
        result = await self._session.execute(
            select(VulnerabilitySourceRecordDB).where(
                VulnerabilitySourceRecordDB.vulnerability_id == vuln_id
            )
        )
        return list(result.scalars().all())

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
            conditions.append(
                (VulnerabilityDB.canonical_id.ilike(f"%{cve}%"))
                | (VulnerabilityDB.cve_id.ilike(f"%{cve}%"))
            )
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

        stmt = select(VulnerabilityDB).order_by(VulnerabilityDB.canonical_id.asc())
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

        canonical_id = db_vuln.canonical_id or db_vuln.cve_id or ""

        # Safely convert relationships if loaded
        ranges = []
        with contextlib.suppress(Exception):
            if db_vuln.affected_ranges:
                ranges = [
                    AffectedVersionRange(
                        ecosystem=r.ecosystem,
                        package_name=r.package_name,
                        range_type=r.range_type,
                        introduced=r.introduced,
                        fixed=r.fixed,
                        last_affected=r.last_affected,
                        limit=getattr(r, "limit", None),
                        raw_range=r.raw_range,
                        source_name=r.source_name,
                    )
                    for r in db_vuln.affected_ranges
                ]

        identifiers = []
        with contextlib.suppress(Exception):
            if db_vuln.identifiers:
                for ident in db_vuln.identifiers:
                    id_type = IdentifierType.OTHER
                    with contextlib.suppress(ValueError):
                        id_type = IdentifierType(ident.identifier_type)
                    identifiers.append(
                        VulnerabilityIdentifier(
                            identifier=ident.identifier,
                            identifier_type=id_type,
                            source=ident.source,
                        )
                    )

        source_records = []
        with contextlib.suppress(Exception):
            if db_vuln.source_records:
                for sr in db_vuln.source_records:
                    raw_payload = {}
                    if sr.raw_payload:
                        with contextlib.suppress(Exception):
                            raw_payload = (
                                json.loads(sr.raw_payload)
                                if isinstance(sr.raw_payload, str)
                                else sr.raw_payload
                            )
                    source_records.append(
                        VulnerabilitySourceRecord(
                            source_id=sr.source_id,
                            source_name=sr.source_name,
                            source_identifier=sr.source_identifier,
                            has_kev_evidence=sr.has_kev_evidence,
                            has_affected_range=sr.has_affected_range,
                            raw_payload=raw_payload,
                            synced_at=sr.synced_at,
                        )
                    )

        source_name = ""
        with contextlib.suppress(Exception):
            if db_vuln.source and getattr(db_vuln.source, "name", None):
                source_name = db_vuln.source.name
        if not source_name and source_records:
            source_name = source_records[0].source_name
        if not source_name and ranges:
            source_name = ranges[0].source_name

        return VulnerabilityRecord(
            canonical_id=canonical_id,
            cve_id=db_vuln.cve_id,
            source_name=source_name,
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
            severity=db_vuln.severity,
            cvss_score=db_vuln.cvss_score,
            identifiers=identifiers,
            source_records=source_records,
            affected_ranges=ranges,
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
            norm_name = match.component.normalized_name()
            ver = match.component.version
            src = match.component.source_file

            comp_id = (
                component_id_map.get((norm_name, ver, src))
                or component_id_map.get((norm_name, ver))
                or component_id_map.get(norm_name)
            )
            vuln_key = match.vulnerability.canonical_id or match.vulnerability.cve_id
            vuln_id = vulnerability_id_map.get(vuln_key) or (
                vulnerability_id_map.get(match.vulnerability.cve_id)
                if match.vulnerability.cve_id
                else None
            )
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

            # Save structured evidences if present
            for ev in match.structured_evidences:
                db_ev = MatchEvidenceDB(
                    match_id=db_match.id,
                    source_name=ev.source_name,
                    identifier=ev.identifier,
                    package_name=ev.package_name,
                    ecosystem=str(ev.ecosystem),
                    installed_version=ev.installed_version,
                    affected_range=ev.affected_range,
                    fixed_version=ev.fixed_version,
                    status=str(ev.status.value if hasattr(ev.status, "value") else ev.status),
                    evidence_type=str(
                        ev.evidence_type.value
                        if hasattr(ev.evidence_type, "value")
                        else ev.evidence_type
                    ),
                    details=ev.details,
                )
                self._session.add(db_ev)

            # Save conflicts if present (idempotent)
            if hasattr(match, "conflicts") and match.conflicts:
                await self.save_match_conflicts(
                    match_id=db_match.id,
                    conflicts=match.conflicts,
                    vulnerability_id=vuln_id,
                )

        await self._session.flush()
        return db_matches

    async def get_by_scan(self, scan_id: str) -> list[MatchDB]:
        """Get all matches for a scan with eagerly loaded related records."""
        from sqlalchemy.orm import selectinload

        stmt = (
            select(MatchDB)
            .where(MatchDB.scan_id == scan_id)
            .options(
                selectinload(MatchDB.component),
                selectinload(MatchDB.vulnerability).selectinload(VulnerabilityDB.identifiers),
                selectinload(MatchDB.vulnerability).selectinload(VulnerabilityDB.source),
                selectinload(MatchDB.ai_analysis),
                selectinload(MatchDB.decision_result),
                selectinload(MatchDB.risk_assessment),
                selectinload(MatchDB.structured_evidences),
                selectinload(MatchDB.conflicts),
            )
        )
        result = await self._session.execute(stmt)
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
                selectinload(MatchDB.structured_evidences),
                selectinload(MatchDB.conflicts),
            )
        )
        result = await self._session.execute(stmt)
        return result.scalar_one_or_none()

    async def list_paginated(
        self,
        page: int = 1,
        page_size: int = 20,
        scan_id: str | None = None,
        applicability: str | None = None,
    ) -> tuple[list[MatchDB], int]:
        """List matches with optional filters, paginated."""
        from sqlalchemy import func
        from sqlalchemy.orm import selectinload

        query = select(MatchDB)
        count_query = select(func.count(MatchDB.id))

        if scan_id:
            query = query.where(MatchDB.scan_id == scan_id)
            count_query = count_query.where(MatchDB.scan_id == scan_id)
        if applicability:
            app_lower = applicability.lower()
            query = query.where(MatchDB.applicability == app_lower)
            count_query = count_query.where(MatchDB.applicability == app_lower)

        total_res = await self._session.execute(count_query)
        total = total_res.scalar_one()

        offset = (page - 1) * page_size
        query = (
            query.order_by(MatchDB.matched_at.desc())
            .offset(offset)
            .limit(page_size)
            .options(
                selectinload(MatchDB.component),
                selectinload(MatchDB.vulnerability),
                selectinload(MatchDB.ai_analysis),
                selectinload(MatchDB.decision_result),
                selectinload(MatchDB.risk_assessment),
                selectinload(MatchDB.structured_evidences),
                selectinload(MatchDB.conflicts),
            )
        )
        result = await self._session.execute(query)
        return list(result.scalars().all()), total

    async def get_match_evidences(self, match_id: str) -> list[MatchEvidenceDB]:
        """Get structured evidence records for a match."""
        result = await self._session.execute(
            select(MatchEvidenceDB)
            .where(MatchEvidenceDB.match_id == match_id)
            .order_by(MatchEvidenceDB.created_at.asc())
        )
        return list(result.scalars().all())

    async def save_match_evidences(
        self, match_id: str, evidences: list[MatchEvidence]
    ) -> list[MatchEvidenceDB]:
        """Save structured evidence records for a match."""
        db_evs = []
        for ev in evidences:
            db_ev = MatchEvidenceDB(
                match_id=match_id,
                source_name=ev.source_name,
                identifier=ev.identifier,
                package_name=ev.package_name,
                ecosystem=str(ev.ecosystem),
                installed_version=ev.installed_version,
                affected_range=ev.affected_range,
                fixed_version=ev.fixed_version,
                status=str(ev.status.value if hasattr(ev.status, "value") else ev.status),
                evidence_type=str(
                    ev.evidence_type.value
                    if hasattr(ev.evidence_type, "value")
                    else ev.evidence_type
                ),
                details=ev.details,
            )
            self._session.add(db_ev)
            db_evs.append(db_ev)
        await self._session.flush()
        return db_evs

    async def get_match_conflicts(self, match_id: str) -> list[SourceConflictDB]:
        """Get source conflict records for a match."""
        result = await self._session.execute(
            select(SourceConflictDB)
            .where(SourceConflictDB.match_id == match_id)
            .order_by(SourceConflictDB.created_at.asc())
        )
        return list(result.scalars().all())

    async def save_match_conflicts(
        self,
        match_id: str,
        conflicts: list[Any],
        vulnerability_id: str | None = None,
    ) -> list[SourceConflictDB]:
        """Save source conflict records for a match with strict idempotency."""
        existing_conflicts = await self.get_match_conflicts(match_id)
        conflict_by_key: dict[tuple[str, str], SourceConflictDB] = {
            (c.conflict_type, c.field): c for c in existing_conflicts
        }

        saved_conflicts: list[SourceConflictDB] = []
        for conf in conflicts:
            conf_type = (
                conf.conflict_type.value
                if hasattr(conf.conflict_type, "value")
                else str(conf.conflict_type)
            )
            field_name = str(conf.field)
            severity_str = (
                conf.severity.value if hasattr(conf.severity, "value") else str(conf.severity)
            )
            key = (conf_type, field_name)

            sources_json = json.dumps(getattr(conf, "sources", []))
            identifiers_json = json.dumps(getattr(conf, "identifiers", []))
            values_json = json.dumps(getattr(conf, "values", {}))
            resolution_str = str(getattr(conf, "resolution", ""))
            rationale_str = str(getattr(conf, "rationale", ""))

            if key in conflict_by_key:
                existing = conflict_by_key[key]
                existing.severity = severity_str
                existing.sources = sources_json
                existing.identifiers = identifiers_json
                existing.values = values_json
                existing.resolution = resolution_str
                existing.rationale = rationale_str
                if vulnerability_id:
                    existing.vulnerability_id = vulnerability_id
                saved_conflicts.append(existing)
            else:
                new_db_conf = SourceConflictDB(
                    match_id=match_id,
                    vulnerability_id=vulnerability_id,
                    conflict_type=conf_type,
                    severity=severity_str,
                    field=field_name,
                    sources=sources_json,
                    identifiers=identifiers_json,
                    values=values_json,
                    resolution=resolution_str,
                    rationale=rationale_str,
                )
                self._session.add(new_db_conf)
                conflict_by_key[key] = new_db_conf
                saved_conflicts.append(new_db_conf)

        await self._session.flush()
        return saved_conflicts

    def to_domain(self, db_match: MatchDB) -> MatchResult:
        """Convert a DB match with relationships into a domain MatchResult."""
        db_comp = db_match.component
        dep_type = getattr(db_comp, "dependency_type", "direct")
        scope_val = getattr(db_comp, "scope", "runtime")

        comp_domain = DetectedComponent(
            name=db_comp.name,
            version=db_comp.version,
            version_type=VersionType(db_comp.version_type)
            if hasattr(db_comp, "version_type") and db_comp.version_type
            else VersionType.UNKNOWN,
            version_constraint=getattr(db_comp, "version_constraint", None),
            source_file=getattr(db_comp, "source_file", "") or "",
            ecosystem=Ecosystem(db_comp.ecosystem)
            if hasattr(db_comp, "ecosystem") and db_comp.ecosystem
            else Ecosystem.UNKNOWN,
            component_type=ComponentType(db_comp.component_type)
            if hasattr(db_comp, "component_type") and db_comp.component_type
            else ComponentType.LIBRARY,
            is_direct=getattr(db_comp, "is_direct", True),
            dependency_type=DependencyType(dep_type)
            if dep_type in [e.value for e in DependencyType]
            else DependencyType.DIRECT,
            scope=DependencyScope(scope_val)
            if scope_val in [e.value for e in DependencyScope]
            else DependencyScope.RUNTIME,
            manifest_source=getattr(db_comp, "manifest_source", None),
            lockfile_source=getattr(db_comp, "lockfile_source", None),
            parent_name=getattr(db_comp, "parent_name", None),
        )

        db_vuln = db_match.vulnerability
        vuln_domain = (
            VulnerabilityRepository(self._session).to_domain(db_vuln)
            if db_vuln
            else VulnerabilityRecord(canonical_id="unknown")
        )

        evidence = []
        if db_match.evidence:
            with contextlib.suppress(json.JSONDecodeError, TypeError):
                evidence = json.loads(db_match.evidence)

        structured_evs = []
        if getattr(db_match, "structured_evidences", None):
            for ev in db_match.structured_evidences:
                structured_evs.append(
                    MatchEvidence(
                        source_name=ev.source_name,
                        identifier=ev.identifier,
                        package_name=ev.package_name,
                        ecosystem=ev.ecosystem,
                        installed_version=ev.installed_version,
                        affected_range=ev.affected_range,
                        fixed_version=ev.fixed_version,
                        status=Applicability(ev.status)
                        if ev.status in [e.value for e in Applicability]
                        else Applicability.UNKNOWN,
                        evidence_type=ev.evidence_type,
                        details=ev.details,
                        created_at=ev.created_at,
                    )
                )

        conflicts = []
        if getattr(db_match, "conflicts", None):
            for conf in db_match.conflicts:
                sources = []
                identifiers = []
                values = {}
                with contextlib.suppress(Exception):
                    sources = (
                        json.loads(conf.sources)
                        if isinstance(conf.sources, str)
                        else (conf.sources or [])
                    )
                with contextlib.suppress(Exception):
                    identifiers = (
                        json.loads(conf.identifiers)
                        if isinstance(conf.identifiers, str)
                        else (conf.identifiers or [])
                    )
                with contextlib.suppress(Exception):
                    values = (
                        json.loads(conf.values)
                        if isinstance(conf.values, str)
                        else (conf.values or {})
                    )
                conflicts.append(
                    SourceConflict(
                        conflict_type=conf.conflict_type,
                        severity=conf.severity,
                        field=conf.field,
                        sources=sources,
                        identifiers=identifiers,
                        values=values,
                        resolution=conf.resolution,
                        rationale=conf.rationale or "",
                    )
                )

        risk = None
        if getattr(db_match, "risk_assessment", None):
            risk = RiskAssessmentRepository.to_domain(db_match.risk_assessment)

        ai_analysis = None
        if getattr(db_match, "ai_analysis", None):
            ai_analysis = AIAnalysisRepository.to_domain(db_match.ai_analysis)

        decision = None
        if getattr(db_match, "decision_result", None):
            decision = DecisionRepository.to_domain(db_match.decision_result)

        app_val = db_match.applicability or "unknown"
        applicability = (
            Applicability(app_val)
            if app_val in [e.value for e in Applicability]
            else Applicability.UNKNOWN
        )

        match_type_val = db_match.match_type or "none"
        match_type = (
            MatchType(match_type_val)
            if match_type_val in [e.value for e in MatchType]
            else MatchType.NONE
        )

        return MatchResult(
            component=comp_domain,
            vulnerability=vuln_domain,
            match_type=match_type,
            match_confidence=db_match.match_confidence,
            applicability=applicability,
            evidence=evidence if isinstance(evidence, list) else [],
            structured_evidences=structured_evs,
            ai_analysis=ai_analysis,
            decision=decision,
            risk_assessment=risk,
            conflicts=conflicts,
        )


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


class PolicyRepository:
    """Data access for declarative security policies and evaluation snapshots."""

    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    async def create(self, policy: Policy) -> PolicyDB:
        """Create a new policy and its constituent rules."""
        db_policy = PolicyDB(
            id=policy.id,
            name=policy.name,
            version=policy.version,
            description=policy.description,
            enabled=policy.enabled,
            default_action=policy.default_action.value,
            thresholds_json=policy.thresholds.model_dump_json(),
            metadata_json=json.dumps(policy.metadata),
            created_at=policy.created_at,
            updated_at=policy.updated_at,
        )
        self._session.add(db_policy)

        for rule in policy.rules:
            db_rule = PolicyRuleDB(
                id=str(uuid.uuid4()),
                policy_id=policy.id,
                rule_id=rule.id,
                description=rule.description,
                conditions_json=rule.when.model_dump_json(),
                action=rule.action.value,
                reason=rule.reason,
                enabled=rule.enabled,
                priority=rule.priority,
            )
            self._session.add(db_rule)

        await self._session.flush()
        loaded = await self.get_by_id(policy.id)
        return loaded or db_policy

    async def get_by_id(self, policy_id: str) -> PolicyDB | None:
        """Fetch policy by UUID with rules loaded."""
        stmt = (
            select(PolicyDB).options(selectinload(PolicyDB.rules)).where(PolicyDB.id == policy_id)
        )
        result = await self._session.execute(stmt)
        return result.scalar_one_or_none()

    async def get_by_name(self, name: str) -> PolicyDB | None:
        """Fetch policy by name with rules loaded."""
        stmt = select(PolicyDB).options(selectinload(PolicyDB.rules)).where(PolicyDB.name == name)
        result = await self._session.execute(stmt)
        return result.scalar_one_or_none()

    async def list_all(self) -> list[PolicyDB]:
        """List all policies ordered by name with rules loaded."""
        stmt = select(PolicyDB).options(selectinload(PolicyDB.rules)).order_by(PolicyDB.name)
        result = await self._session.execute(stmt)
        return list(result.scalars().all())

    async def update(self, policy_id: str, policy: Policy) -> PolicyDB | None:
        """Update existing policy attributes and replace rules."""
        db_policy = await self.get_by_id(policy_id)
        if not db_policy:
            return None

        db_policy.name = policy.name
        db_policy.version = policy.version
        db_policy.description = policy.description
        db_policy.enabled = policy.enabled
        db_policy.default_action = policy.default_action.value
        db_policy.thresholds_json = policy.thresholds.model_dump_json()
        db_policy.metadata_json = json.dumps(policy.metadata)
        db_policy.updated_at = datetime.now(UTC)

        # Replace rules collection (flush after clear to delete old rules before inserting new ones)
        db_policy.rules.clear()
        await self._session.flush()

        for rule in policy.rules:
            db_rule = PolicyRuleDB(
                id=str(uuid.uuid4()),
                policy_id=policy_id,
                rule_id=rule.id,
                description=rule.description,
                conditions_json=rule.when.model_dump_json(),
                action=rule.action.value,
                reason=rule.reason,
                enabled=rule.enabled,
                priority=rule.priority,
            )
            db_policy.rules.append(db_rule)

        await self._session.flush()
        return db_policy

    async def delete(self, policy_id: str) -> bool:
        """Delete policy by ID."""
        db_policy = await self.get_by_id(policy_id)
        if not db_policy:
            return False
        await self._session.delete(db_policy)
        await self._session.flush()
        return True

    @staticmethod
    def to_domain(db_policy: PolicyDB) -> Policy:
        """Convert PolicyDB into Policy domain model."""
        rules = [
            PolicyRule(
                id=r.rule_id,
                description=r.description,
                when=PolicyCondition.model_validate_json(r.conditions_json),
                action=PolicyAction(r.action),
                reason=r.reason,
                enabled=r.enabled,
                priority=r.priority,
            )
            for r in db_policy.rules
        ]
        thresholds = PolicyThresholds.model_validate_json(db_policy.thresholds_json)
        metadata = json.loads(db_policy.metadata_json) if db_policy.metadata_json else {}

        return Policy(
            id=db_policy.id,
            name=db_policy.name,
            version=db_policy.version,
            description=db_policy.description,
            enabled=db_policy.enabled,
            thresholds=thresholds,
            rules=rules,
            default_action=PolicyAction(db_policy.default_action),
            metadata=metadata,
            created_at=db_policy.created_at,
            updated_at=db_policy.updated_at,
        )

    async def save_evaluation(
        self, eval_result: PolicyEvaluationResult, scan_id: str
    ) -> PolicyEvaluationDB:
        """Save or update evaluation snapshot for a scan."""
        stmt = select(PolicyEvaluationDB).where(PolicyEvaluationDB.scan_id == scan_id)
        existing = (await self._session.execute(stmt)).scalar_one_or_none()

        eval_json = eval_result.model_dump_json()

        if existing:
            existing.policy_id = eval_result.policy_id
            existing.policy_name = eval_result.policy_name
            existing.total_findings = eval_result.total_findings
            existing.allowed_count = eval_result.allowed_count
            existing.violations_count = eval_result.violations_count
            existing.suppressed_count = eval_result.suppressed_count
            existing.accepted_risk_count = eval_result.accepted_risk_count
            existing.requires_review_count = eval_result.requires_review_count
            existing.has_violations = eval_result.has_violations
            existing.ci_exit_code = eval_result.ci_exit_code
            existing.evaluations_json = eval_json
            existing.evaluated_at = eval_result.evaluated_at
            db_obj = existing
        else:
            db_obj = PolicyEvaluationDB(
                id=str(uuid.uuid4()),
                scan_id=scan_id,
                policy_id=eval_result.policy_id,
                policy_name=eval_result.policy_name,
                total_findings=eval_result.total_findings,
                allowed_count=eval_result.allowed_count,
                violations_count=eval_result.violations_count,
                suppressed_count=eval_result.suppressed_count,
                accepted_risk_count=eval_result.accepted_risk_count,
                requires_review_count=eval_result.requires_review_count,
                has_violations=eval_result.has_violations,
                ci_exit_code=eval_result.ci_exit_code,
                evaluations_json=eval_json,
                evaluated_at=eval_result.evaluated_at,
            )
            self._session.add(db_obj)

        await self._session.flush()
        return db_obj

    async def get_evaluation_by_scan_id(self, scan_id: str) -> PolicyEvaluationDB | None:
        """Fetch policy evaluation snapshot for a scan."""
        stmt = select(PolicyEvaluationDB).where(PolicyEvaluationDB.scan_id == scan_id)
        result = await self._session.execute(stmt)
        return result.scalar_one_or_none()


class SuppressionRepository:
    """Data access for finding exemptions and suppressions."""

    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    async def create(self, suppression: Suppression) -> SuppressionDB:
        """Create a new suppression record."""
        db_sup = SuppressionDB(
            id=suppression.id,
            project_id=suppression.project_id,
            vulnerability_id=suppression.match_criteria.vulnerability_id,
            package_name=suppression.match_criteria.package_name,
            ecosystem=suppression.match_criteria.ecosystem,
            package_version=suppression.match_criteria.package_version,
            finding_id=suppression.match_criteria.finding_id,
            reason=suppression.reason,
            owner=suppression.owner,
            reference=suppression.reference,
            expires_at=suppression.expires_at,
            enabled=suppression.enabled,
            created_by=suppression.created_by,
            created_at=suppression.created_at,
            updated_at=suppression.updated_at,
            metadata_json=json.dumps(suppression.metadata),
        )
        self._session.add(db_sup)
        await self._session.flush()
        return db_sup

    async def get_by_id(self, suppression_id: str) -> SuppressionDB | None:
        """Fetch suppression by UUID."""
        stmt = select(SuppressionDB).where(SuppressionDB.id == suppression_id)
        result = await self._session.execute(stmt)
        return result.scalar_one_or_none()

    async def list_all(
        self,
        project_id: str | None = None,
        enabled_only: bool = False,
    ) -> list[SuppressionDB]:
        """List suppressions, optionally filtered by project scope (including globals)."""
        stmt = select(SuppressionDB)
        if project_id is not None:
            stmt = stmt.where(
                or_(SuppressionDB.project_id == project_id, SuppressionDB.project_id.is_(None))
            )
        if enabled_only:
            stmt = stmt.where(SuppressionDB.enabled.is_(True))
        stmt = stmt.order_by(SuppressionDB.created_at.desc())
        result = await self._session.execute(stmt)
        return list(result.scalars().all())

    async def update(self, suppression_id: str, updates: dict[str, Any]) -> SuppressionDB | None:
        """Update fields of an existing suppression."""
        db_sup = await self.get_by_id(suppression_id)
        if not db_sup:
            return None

        for k, v in updates.items():
            if hasattr(db_sup, k):
                setattr(db_sup, k, v)
        db_sup.updated_at = datetime.now(UTC)

        await self._session.flush()
        return db_sup

    async def delete(self, suppression_id: str) -> bool:
        """Delete suppression by ID."""
        db_sup = await self.get_by_id(suppression_id)
        if not db_sup:
            return False
        await self._session.delete(db_sup)
        await self._session.flush()
        return True

    @staticmethod
    def to_domain(db_sup: SuppressionDB) -> Suppression:
        """Convert SuppressionDB into Suppression domain model."""
        criteria = SuppressionMatchCriteria(
            vulnerability_id=db_sup.vulnerability_id,
            package_name=db_sup.package_name,
            ecosystem=db_sup.ecosystem,
            package_version=db_sup.package_version,
            finding_id=db_sup.finding_id,
            project_id=db_sup.project_id,
        )
        metadata = json.loads(db_sup.metadata_json) if db_sup.metadata_json else {}

        return Suppression(
            id=db_sup.id,
            project_id=db_sup.project_id,
            match_criteria=criteria,
            reason=db_sup.reason,
            owner=db_sup.owner,
            reference=db_sup.reference,
            expires_at=db_sup.expires_at,
            enabled=db_sup.enabled,
            created_by=db_sup.created_by,
            created_at=db_sup.created_at,
            updated_at=db_sup.updated_at,
            metadata=metadata,
        )


class ContainerRepository:
    """Repository for container images, layers, and component relationships."""

    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    async def create_image(
        self,
        scan_id: str,
        image: ContainerImage,
        commit: bool = True,
    ) -> ContainerImageDB:
        meta_json = json.dumps(image.metadata) if image.metadata else "{}"
        os_family = image.operating_system.family if image.operating_system else None
        os_version = image.operating_system.version if image.operating_system else None
        os_codename = image.operating_system.codename if image.operating_system else None

        db_image = ContainerImageDB(
            id=image.id,
            scan_id=scan_id,
            reference=image.reference,
            digest=image.digest,
            architecture=image.architecture,
            os=image.os,
            os_family=os_family,
            os_version=os_version,
            os_codename=os_codename,
            source_type=image.source_type,
            source_path=image.source_path,
            created_at=image.created_at,
            metadata_json=meta_json,
        )
        self._session.add(db_image)
        if commit:
            await self._session.commit()
            await self._session.refresh(db_image)
        else:
            await self._session.flush()
        return db_image

    async def add_layers(
        self,
        image_id: str,
        layers: list[ImageLayer],
        commit: bool = True,
    ) -> list[ContainerLayerDB]:
        db_layers: list[ContainerLayerDB] = []
        for layer in layers:
            meta_json = json.dumps(layer.metadata) if layer.metadata else "{}"
            db_l = ContainerLayerDB(
                image_id=image_id,
                layer_index=layer.index,
                digest=layer.digest,
                size_bytes=layer.size_bytes,
                media_type=layer.media_type,
                command=layer.command,
                metadata_json=meta_json,
            )
            self._session.add(db_l)
            db_layers.append(db_l)

        if commit:
            await self._session.commit()
        else:
            await self._session.flush()
        return db_layers

    async def link_components(
        self,
        image_id: str,
        components: list[tuple[str, str | None, str, str, str | None, bool]],
        commit: bool = True,
    ) -> list[ContainerImageComponentDB]:
        """Link project components to the container image and layer.

        components tuple:
        (component_id, layer_id, container_path, stage, package_manager, is_runtime)
        """
        records: list[ContainerImageComponentDB] = []
        for comp_id, layer_id, c_path, stage, pkg_mgr, is_rt in components:
            rec = ContainerImageComponentDB(
                image_id=image_id,
                component_id=comp_id,
                layer_id=layer_id,
                container_path=c_path,
                stage=stage,
                package_manager=pkg_mgr,
                is_runtime=is_rt,
            )
            self._session.add(rec)
            records.append(rec)
        if commit:
            await self._session.commit()
        else:
            await self._session.flush()
        return records

    async def get_image_by_id(self, image_id: str) -> ContainerImageDB | None:
        stmt = (
            select(ContainerImageDB)
            .where(ContainerImageDB.id == image_id)
            .options(
                selectinload(ContainerImageDB.layers),
                selectinload(ContainerImageDB.image_components).selectinload(
                    ContainerImageComponentDB.component
                ),
            )
        )
        res = await self._session.execute(stmt)
        return res.scalar_one_or_none()

    async def get_image_by_scan_id(self, scan_id: str) -> ContainerImageDB | None:
        stmt = (
            select(ContainerImageDB)
            .where(ContainerImageDB.scan_id == scan_id)
            .options(
                selectinload(ContainerImageDB.layers),
                selectinload(ContainerImageDB.image_components).selectinload(
                    ContainerImageComponentDB.component
                ),
            )
        )
        res = await self._session.execute(stmt)
        return res.scalar_one_or_none()

    async def get_image_by_digest(self, digest: str) -> ContainerImageDB | None:
        stmt = (
            select(ContainerImageDB)
            .where(ContainerImageDB.digest == digest)
            .options(
                selectinload(ContainerImageDB.layers),
                selectinload(ContainerImageDB.image_components).selectinload(
                    ContainerImageComponentDB.component
                ),
            )
        )
        res = await self._session.execute(stmt)
        return res.scalar_one_or_none()

    async def list_images(self, limit: int = 50, offset: int = 0) -> list[ContainerImageDB]:
        stmt = (
            select(ContainerImageDB)
            .options(selectinload(ContainerImageDB.layers))
            .order_by(ContainerImageDB.created_at.desc())
            .offset(offset)
            .limit(limit)
        )
        res = await self._session.execute(stmt)
        return list(res.scalars().all())

    async def count_images(self) -> int:
        stmt = select(func.count(ContainerImageDB.id))
        res = await self._session.execute(stmt)
        return res.scalar_one() or 0
