"""SQLAlchemy ORM models for the database layer.

These map to database tables. Domain logic should use the Pydantic models
in core/models.py — these are for persistence only.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime

from sqlalchemy import (
    Boolean,
    DateTime,
    Float,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy.orm import (
    DeclarativeBase,
    Mapped,
    mapped_column,
    relationship,
)


def _generate_uuid() -> str:
    return str(uuid.uuid4())


def _utcnow() -> datetime:
    return datetime.now(UTC)


class Base(DeclarativeBase):
    """Base class for all ORM models."""

    pass


class ProjectDB(Base):
    """A user project that has been scanned."""

    __tablename__ = "projects"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_generate_uuid)
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    path: Mapped[str] = mapped_column(Text, nullable=False)
    description: Mapped[str] = mapped_column(Text, default="")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=_utcnow, onupdate=_utcnow
    )

    # Relationships
    components: Mapped[list[ProjectComponentDB]] = relationship(
        back_populates="project", cascade="all, delete-orphan"
    )
    dependency_edges: Mapped[list[DependencyEdgeDB]] = relationship(
        back_populates="project", cascade="all, delete-orphan"
    )
    scans: Mapped[list[ScanDB]] = relationship(
        back_populates="project", cascade="all, delete-orphan"
    )

    __table_args__ = (
        Index("ix_projects_name", "name"),
        Index("ix_projects_path", "path", unique=True),
    )


class ProjectComponentDB(Base):
    """A software component detected in a project."""

    __tablename__ = "project_components"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_generate_uuid)
    project_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("projects.id", ondelete="CASCADE"), nullable=False
    )
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    version: Mapped[str | None] = mapped_column(String(100), nullable=True)
    version_type: Mapped[str] = mapped_column(String(20), default="unknown")
    version_constraint: Mapped[str | None] = mapped_column(String(255), nullable=True)
    source_file: Mapped[str] = mapped_column(String(500), nullable=False)
    ecosystem: Mapped[str] = mapped_column(String(50), nullable=False)
    component_type: Mapped[str] = mapped_column(String(50), default="library")
    is_direct: Mapped[bool] = mapped_column(Boolean, default=True)
    dependency_type: Mapped[str] = mapped_column(String(20), default="direct")
    scope: Mapped[str] = mapped_column(String(20), default="runtime")
    manifest_source: Mapped[str | None] = mapped_column(String(500), nullable=True)
    lockfile_source: Mapped[str | None] = mapped_column(String(500), nullable=True)
    parent_name: Mapped[str | None] = mapped_column(String(255), nullable=True)
    dependency_path: Mapped[str] = mapped_column(Text, default="[]")
    detected_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)

    # Relationships
    project: Mapped[ProjectDB] = relationship(back_populates="components")
    matches: Mapped[list[MatchDB]] = relationship(
        back_populates="component", cascade="all, delete-orphan"
    )

    __table_args__ = (
        Index("ix_components_project", "project_id"),
        Index("ix_components_name", "name"),
        Index("ix_components_ecosystem", "ecosystem"),
        Index("ix_components_dep_type", "dependency_type"),
    )


class DependencyEdgeDB(Base):
    """A directed dependency relation in the project dependency graph."""

    __tablename__ = "dependency_edges"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_generate_uuid)
    project_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("projects.id", ondelete="CASCADE"), nullable=False
    )
    parent_name: Mapped[str] = mapped_column(String(255), nullable=False)
    parent_version: Mapped[str | None] = mapped_column(String(100), nullable=True)
    child_name: Mapped[str] = mapped_column(String(255), nullable=False)
    child_version: Mapped[str | None] = mapped_column(String(100), nullable=True)
    scope: Mapped[str] = mapped_column(String(30), default="runtime")
    requirement: Mapped[str | None] = mapped_column(String(255), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)

    # Relationships
    project: Mapped[ProjectDB] = relationship(back_populates="dependency_edges")

    __table_args__ = (
        Index("ix_dep_edges_project", "project_id"),
        Index("ix_dep_edges_parent", "parent_name"),
        Index("ix_dep_edges_child", "child_name"),
    )


class VulnerabilitySourceDB(Base):
    """A vulnerability data source (e.g., CISA KEV)."""

    __tablename__ = "vulnerability_sources"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_generate_uuid)
    name: Mapped[str] = mapped_column(String(255), nullable=False, unique=True)
    source_type: Mapped[str] = mapped_column(String(50), nullable=False)
    url: Mapped[str] = mapped_column(Text, default="")
    status: Mapped[str] = mapped_column(String(20), default="never_synced")
    last_sync: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    record_count: Mapped[int] = mapped_column(Integer, default=0)
    last_error: Mapped[str | None] = mapped_column(Text, nullable=True)

    # Relationships
    vulnerabilities: Mapped[list[VulnerabilityDB]] = relationship(
        back_populates="source", cascade="all, delete-orphan"
    )


class VulnerabilityDB(Base):
    """A known vulnerability in the canonical catalog.

    Can be identified by CVE, GHSA, OSV, or other identifiers, and may have
    evidence and version ranges contributed by multiple sources.
    """

    __tablename__ = "vulnerabilities"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_generate_uuid)
    canonical_id: Mapped[str] = mapped_column(String(100), nullable=False, default="")
    cve_id: Mapped[str | None] = mapped_column(String(50), nullable=True)
    source_id: Mapped[str | None] = mapped_column(
        String(36), ForeignKey("vulnerability_sources.id", ondelete="CASCADE"), nullable=True
    )
    vendor_project: Mapped[str] = mapped_column(String(255), nullable=False, default="")
    product: Mapped[str] = mapped_column(String(255), nullable=False, default="")
    vulnerability_name: Mapped[str] = mapped_column(Text, default="")
    short_description: Mapped[str] = mapped_column(Text, default="")
    required_action: Mapped[str] = mapped_column(Text, default="")
    date_added: Mapped[str | None] = mapped_column(String(20), nullable=True)
    due_date: Mapped[str | None] = mapped_column(String(20), nullable=True)
    known_ransomware_use: Mapped[str] = mapped_column(String(50), default="Unknown")
    cwes: Mapped[str] = mapped_column(Text, default="[]")  # JSON array stored as text
    notes: Mapped[str] = mapped_column(Text, default="")
    severity: Mapped[str | None] = mapped_column(String(50), nullable=True)
    cvss_score: Mapped[float | None] = mapped_column(Float, nullable=True)
    synced_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)

    # Relationships
    source: Mapped[VulnerabilitySourceDB | None] = relationship(back_populates="vulnerabilities")
    identifiers: Mapped[list[VulnerabilityIdentifierDB]] = relationship(
        back_populates="vulnerability", cascade="all, delete-orphan"
    )
    source_records: Mapped[list[VulnerabilitySourceRecordDB]] = relationship(
        back_populates="vulnerability", cascade="all, delete-orphan"
    )
    affected_ranges: Mapped[list[AffectedVersionRangeDB]] = relationship(
        back_populates="vulnerability", cascade="all, delete-orphan"
    )
    matches: Mapped[list[MatchDB]] = relationship(
        back_populates="vulnerability", cascade="all, delete-orphan"
    )
    conflicts: Mapped[list[SourceConflictDB]] = relationship(
        back_populates="vulnerability", cascade="all, delete-orphan"
    )

    __table_args__ = (
        Index("ix_vuln_canonical_id", "canonical_id"),
        Index("ix_vuln_cve_id", "cve_id"),
        Index("ix_vuln_source", "source_id"),
        Index("ix_vuln_vendor_product", "vendor_project", "product"),
    )


class VulnerabilityIdentifierDB(Base):
    """An identifier or alias mapped to a canonical vulnerability (CVE, GHSA, OSV, etc.)."""

    __tablename__ = "vulnerability_identifiers"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_generate_uuid)
    vulnerability_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("vulnerabilities.id", ondelete="CASCADE"), nullable=False
    )
    identifier: Mapped[str] = mapped_column(String(100), nullable=False)
    identifier_type: Mapped[str] = mapped_column(String(20), default="cve")
    source: Mapped[str] = mapped_column(String(50), default="unknown")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)

    # Relationships
    vulnerability: Mapped[VulnerabilityDB] = relationship(back_populates="identifiers")

    __table_args__ = (
        Index("ix_vident_identifier", "identifier"),
        Index("ix_vident_vuln_id", "vulnerability_id"),
        UniqueConstraint("vulnerability_id", "identifier", name="uq_vident_vuln_identifier"),
    )


class VulnerabilitySourceRecordDB(Base):
    """A record of evidence contributed by a vulnerability source."""

    __tablename__ = "vulnerability_source_records"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_generate_uuid)
    vulnerability_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("vulnerabilities.id", ondelete="CASCADE"), nullable=False
    )
    source_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("vulnerability_sources.id", ondelete="CASCADE"), nullable=False
    )
    source_name: Mapped[str] = mapped_column(String(50), nullable=False)
    source_identifier: Mapped[str] = mapped_column(String(100), nullable=False)
    has_kev_evidence: Mapped[bool] = mapped_column(Boolean, default=False)
    has_affected_range: Mapped[bool] = mapped_column(Boolean, default=False)
    raw_payload: Mapped[str] = mapped_column(Text, default="{}")  # JSON string
    synced_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)

    # Relationships
    vulnerability: Mapped[VulnerabilityDB] = relationship(back_populates="source_records")
    source: Mapped[VulnerabilitySourceDB] = relationship()

    __table_args__ = (
        Index("ix_vsource_vuln", "vulnerability_id"),
        Index("ix_vsource_source", "source_id"),
        UniqueConstraint(
            "vulnerability_id",
            "source_id",
            "source_identifier",
            name="uq_vsource_vuln_src_ident",
        ),
    )


class AffectedVersionRangeDB(Base):
    """An affected version range for a specific ecosystem package."""

    __tablename__ = "vulnerability_affected_ranges"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_generate_uuid)
    vulnerability_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("vulnerabilities.id", ondelete="CASCADE"), nullable=False
    )
    ecosystem: Mapped[str] = mapped_column(String(50), nullable=False)
    package_name: Mapped[str] = mapped_column(String(255), nullable=False)
    range_type: Mapped[str] = mapped_column(String(30), default="ecosystem")
    introduced: Mapped[str | None] = mapped_column(String(100), nullable=True)
    fixed: Mapped[str | None] = mapped_column(String(100), nullable=True)
    last_affected: Mapped[str | None] = mapped_column(String(100), nullable=True)
    limit: Mapped[str | None] = mapped_column(String(100), nullable=True)
    raw_range: Mapped[str | None] = mapped_column(String(255), nullable=True)
    source_name: Mapped[str] = mapped_column(String(50), default="unknown")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)

    # Relationships
    vulnerability: Mapped[VulnerabilityDB] = relationship(back_populates="affected_ranges")

    __table_args__ = (
        Index("ix_aff_ranges_eco_pkg", "ecosystem", "package_name"),
        Index("ix_aff_ranges_vuln", "vulnerability_id"),
    )


class MatchEvidenceDB(Base):
    """Structured, auditable evidence supporting a component match."""

    __tablename__ = "match_evidences"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_generate_uuid)
    match_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("matches.id", ondelete="CASCADE"), nullable=False
    )
    source_name: Mapped[str] = mapped_column(String(50), nullable=False)
    identifier: Mapped[str] = mapped_column(String(100), nullable=False)
    package_name: Mapped[str] = mapped_column(String(255), nullable=False)
    ecosystem: Mapped[str] = mapped_column(String(50), nullable=False)
    installed_version: Mapped[str | None] = mapped_column(String(100), nullable=True)
    affected_range: Mapped[str | None] = mapped_column(String(255), nullable=True)
    fixed_version: Mapped[str | None] = mapped_column(String(100), nullable=True)
    status: Mapped[str] = mapped_column(String(30), default="unknown")
    evidence_type: Mapped[str] = mapped_column(String(50), default="product_name_only")
    details: Mapped[str] = mapped_column(Text, default="")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)

    # Relationships
    match: Mapped[MatchDB] = relationship(back_populates="structured_evidences")

    __table_args__ = (Index("ix_match_evidence_match", "match_id"),)


class ScanDB(Base):
    """A scan operation on a project."""

    __tablename__ = "scans"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_generate_uuid)
    project_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("projects.id", ondelete="CASCADE"), nullable=False
    )
    status: Mapped[str] = mapped_column(String(20), default="pending")
    components_found: Mapped[int] = mapped_column(Integer, default=0)
    vulnerabilities_found: Mapped[int] = mapped_column(Integer, default=0)
    kev_matches: Mapped[int] = mapped_column(Integer, default=0)
    duration_seconds: Mapped[float] = mapped_column(Float, default=0.0)
    started_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    error: Mapped[str | None] = mapped_column(Text, nullable=True)

    # Relationships
    project: Mapped[ProjectDB] = relationship(back_populates="scans")
    matches: Mapped[list[MatchDB]] = relationship(
        back_populates="scan", cascade="all, delete-orphan"
    )
    container_image: Mapped[ContainerImageDB | None] = relationship(
        back_populates="scan", uselist=False, cascade="all, delete-orphan"
    )

    __table_args__ = (
        Index("ix_scans_project", "project_id"),
        Index("ix_scans_status", "status"),
        Index("ix_scans_started", "started_at"),
    )


class MatchDB(Base):
    """A match between a project component and a known vulnerability."""

    __tablename__ = "matches"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_generate_uuid)
    scan_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("scans.id", ondelete="CASCADE"), nullable=False
    )
    component_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("project_components.id", ondelete="CASCADE"), nullable=False
    )
    vulnerability_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("vulnerabilities.id", ondelete="CASCADE"), nullable=False
    )
    match_type: Mapped[str] = mapped_column(String(30), nullable=False)
    match_confidence: Mapped[float] = mapped_column(Float, default=0.0)
    applicability: Mapped[str] = mapped_column(String(30), default="unknown")
    evidence: Mapped[str] = mapped_column(Text, default="[]")  # JSON array stored as text
    matched_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)

    # Relationships
    scan: Mapped[ScanDB] = relationship(back_populates="matches")
    component: Mapped[ProjectComponentDB] = relationship(back_populates="matches")
    vulnerability: Mapped[VulnerabilityDB] = relationship(back_populates="matches")
    ai_analysis: Mapped[AIAnalysisDB | None] = relationship(
        back_populates="match", uselist=False, cascade="all, delete-orphan"
    )
    decision_result: Mapped[DecisionResultDB | None] = relationship(
        back_populates="match", uselist=False, cascade="all, delete-orphan"
    )
    risk_assessment: Mapped[RiskAssessmentDB | None] = relationship(
        back_populates="match", uselist=False, cascade="all, delete-orphan"
    )
    structured_evidences: Mapped[list[MatchEvidenceDB]] = relationship(
        back_populates="match", cascade="all, delete-orphan"
    )
    conflicts: Mapped[list[SourceConflictDB]] = relationship(
        back_populates="match", cascade="all, delete-orphan"
    )

    __table_args__ = (
        Index("ix_matches_scan", "scan_id"),
        Index("ix_matches_component", "component_id"),
        Index("ix_matches_vulnerability", "vulnerability_id"),
    )


class SourceConflictDB(Base):
    """Auditable record of a discrepancy between vulnerability sources."""

    __tablename__ = "source_conflicts"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_generate_uuid)
    match_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("matches.id", ondelete="CASCADE"), nullable=False
    )
    vulnerability_id: Mapped[str | None] = mapped_column(
        String(36), ForeignKey("vulnerabilities.id", ondelete="CASCADE"), nullable=True
    )
    conflict_type: Mapped[str] = mapped_column(String(50), nullable=False)
    severity: Mapped[str] = mapped_column(String(20), nullable=False)
    field: Mapped[str] = mapped_column(String(50), nullable=False)
    sources: Mapped[str] = mapped_column(Text, default="[]")  # JSON list[str]
    identifiers: Mapped[str] = mapped_column(Text, default="[]")  # JSON list[str]
    values: Mapped[str] = mapped_column(Text, default="{}")  # JSON dict[str, Any]
    resolution: Mapped[str] = mapped_column(String(50), nullable=False)
    rationale: Mapped[str] = mapped_column(Text, default="")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)

    # Relationships
    match: Mapped[MatchDB] = relationship(back_populates="conflicts")
    vulnerability: Mapped[VulnerabilityDB | None] = relationship(back_populates="conflicts")

    __table_args__ = (
        Index("ix_source_conflicts_match", "match_id"),
        Index("ix_source_conflicts_vuln", "vulnerability_id"),
        Index("ix_source_conflicts_type", "conflict_type"),
        UniqueConstraint(
            "match_id", "conflict_type", "field", name="uq_source_conflict_match_field"
        ),
    )


class AIAnalysisDB(Base):
    """Contextual narrative generated by an LLM for a specific match."""

    __tablename__ = "ai_analyses"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_generate_uuid)
    match_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("matches.id", ondelete="CASCADE"), nullable=False, unique=True
    )
    provider: Mapped[str] = mapped_column(String(50), nullable=False)
    model: Mapped[str] = mapped_column(String(100), nullable=False)
    explanation: Mapped[str] = mapped_column(Text, nullable=False)
    evidence: Mapped[str] = mapped_column(Text, default="[]")  # JSON array
    contextual_findings: Mapped[str] = mapped_column(Text, default="[]")  # JSON array
    requires_human_review: Mapped[bool] = mapped_column(Boolean, default=True)
    duration_seconds: Mapped[float] = mapped_column(Float, default=0.0)
    tokens_used: Mapped[int | None] = mapped_column(Integer, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)

    # Relationships
    match: Mapped[MatchDB] = relationship(back_populates="ai_analysis")

    __table_args__ = (Index("ix_ai_analyses_match", "match_id"),)


class DecisionResultDB(Base):
    """Structured responses and probabilities from a decision provider for a match."""

    __tablename__ = "decision_results"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_generate_uuid)
    match_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("matches.id", ondelete="CASCADE"), nullable=False, unique=True
    )
    provider: Mapped[str] = mapped_column(String(50), nullable=False)
    model: Mapped[str] = mapped_column(String(100), nullable=False)
    responses: Mapped[str] = mapped_column(Text, default="{}")  # JSON dict
    decision_probabilities: Mapped[str] = mapped_column(Text, default="{}")  # JSON dict
    applicability_probability: Mapped[float | None] = mapped_column(Float, nullable=True)
    urgency_score: Mapped[float | None] = mapped_column(Float, nullable=True)
    latency_seconds: Mapped[float] = mapped_column(Float, default=0.0)
    raw_response: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)

    # Relationships
    match: Mapped[MatchDB] = relationship(back_populates="decision_result")

    __table_args__ = (Index("ix_decision_results_match", "match_id"),)


class RiskAssessmentDB(Base):
    """Auditable risk assessment concluded by the deterministic Risk Engine."""

    __tablename__ = "risk_assessments"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_generate_uuid)
    match_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("matches.id", ondelete="CASCADE"), nullable=False, unique=True
    )
    status: Mapped[str] = mapped_column(String(30), nullable=False)
    risk_level: Mapped[str] = mapped_column(String(30), nullable=False)
    certainty: Mapped[float] = mapped_column(Float, default=0.0)
    rationale: Mapped[str] = mapped_column(Text, nullable=False)
    recommended_action: Mapped[str] = mapped_column(Text, nullable=False)
    requires_human_review: Mapped[bool] = mapped_column(Boolean, default=True)
    rule_ids: Mapped[str] = mapped_column(Text, default="[]")  # JSON array
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)

    # Relationships
    match: Mapped[MatchDB] = relationship(back_populates="risk_assessment")

    __table_args__ = (Index("ix_risk_assessments_match", "match_id"),)


class PolicyDB(Base):
    """Declarative security policy stored for compliance evaluation."""

    __tablename__ = "policies"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_generate_uuid)
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    version: Mapped[str] = mapped_column(String(50), default="1")
    description: Mapped[str] = mapped_column(Text, default="")
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    default_action: Mapped[str] = mapped_column(String(50), default="ALLOW")
    thresholds_json: Mapped[str] = mapped_column(Text, default="{}")
    metadata_json: Mapped[str] = mapped_column(Text, default="{}")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=_utcnow, onupdate=_utcnow
    )

    # Relationships
    rules: Mapped[list[PolicyRuleDB]] = relationship(
        back_populates="policy", cascade="all, delete-orphan", order_by="PolicyRuleDB.priority"
    )

    __table_args__ = (Index("ix_policies_name", "name"),)


class PolicyRuleDB(Base):
    """An individual rule within a persistent policy."""

    __tablename__ = "policy_rules"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_generate_uuid)
    policy_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("policies.id", ondelete="CASCADE"), nullable=False
    )
    rule_id: Mapped[str] = mapped_column(String(100), nullable=False)
    description: Mapped[str] = mapped_column(Text, default="")
    conditions_json: Mapped[str] = mapped_column(Text, nullable=False)
    action: Mapped[str] = mapped_column(String(50), nullable=False)
    reason: Mapped[str | None] = mapped_column(Text, nullable=True)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    priority: Mapped[int] = mapped_column(Integer, default=100)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)

    # Relationships
    policy: Mapped[PolicyDB] = relationship(back_populates="rules")

    __table_args__ = (
        Index("ix_policy_rules_policy", "policy_id"),
        UniqueConstraint("policy_id", "rule_id", name="uq_policy_rule_id"),
    )


class SuppressionDB(Base):
    """Documented exemption for a security finding."""

    __tablename__ = "suppressions"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_generate_uuid)
    project_id: Mapped[str | None] = mapped_column(
        String(36), ForeignKey("projects.id", ondelete="CASCADE"), nullable=True
    )
    vulnerability_id: Mapped[str | None] = mapped_column(String(100), nullable=True)
    package_name: Mapped[str | None] = mapped_column(String(255), nullable=True)
    ecosystem: Mapped[str | None] = mapped_column(String(50), nullable=True)
    package_version: Mapped[str | None] = mapped_column(String(100), nullable=True)
    finding_id: Mapped[str | None] = mapped_column(String(255), nullable=True)
    reason: Mapped[str] = mapped_column(Text, nullable=False)
    owner: Mapped[str] = mapped_column(String(255), nullable=False)
    reference: Mapped[str] = mapped_column(String(255), nullable=False)
    expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    created_by: Mapped[str] = mapped_column(String(255), default="system")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=_utcnow, onupdate=_utcnow
    )
    metadata_json: Mapped[str] = mapped_column(Text, default="{}")

    __table_args__ = (
        Index("ix_suppressions_project", "project_id"),
        Index("ix_suppressions_vuln", "vulnerability_id"),
        Index("ix_suppressions_pkg", "package_name"),
    )


class PolicyEvaluationDB(Base):
    """Snapshot of policy evaluation for a completed scan."""

    __tablename__ = "policy_evaluations"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_generate_uuid)
    scan_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("scans.id", ondelete="CASCADE"), nullable=False, unique=True
    )
    policy_id: Mapped[str | None] = mapped_column(String(36), nullable=True)
    policy_name: Mapped[str] = mapped_column(String(255), nullable=False)
    total_findings: Mapped[int] = mapped_column(Integer, default=0)
    allowed_count: Mapped[int] = mapped_column(Integer, default=0)
    violations_count: Mapped[int] = mapped_column(Integer, default=0)
    suppressed_count: Mapped[int] = mapped_column(Integer, default=0)
    accepted_risk_count: Mapped[int] = mapped_column(Integer, default=0)
    requires_review_count: Mapped[int] = mapped_column(Integer, default=0)
    has_violations: Mapped[bool] = mapped_column(Boolean, default=False)
    ci_exit_code: Mapped[int] = mapped_column(Integer, default=0)
    evaluations_json: Mapped[str] = mapped_column(Text, nullable=False)
    evaluated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)

    __table_args__ = (Index("ix_policy_evaluations_scan", "scan_id"),)


class ContainerImageDB(Base):
    """A container image artifact registered and scanned in the system."""

    __tablename__ = "container_images"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_generate_uuid)
    scan_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("scans.id", ondelete="CASCADE"), nullable=False, unique=True
    )
    reference: Mapped[str] = mapped_column(String(255), nullable=False)
    digest: Mapped[str | None] = mapped_column(String(100), nullable=True)
    architecture: Mapped[str] = mapped_column(String(50), default="amd64")
    os: Mapped[str] = mapped_column(String(100), default="linux")
    os_family: Mapped[str | None] = mapped_column(String(50), nullable=True)
    os_version: Mapped[str | None] = mapped_column(String(50), nullable=True)
    os_codename: Mapped[str | None] = mapped_column(String(50), nullable=True)
    source_type: Mapped[str] = mapped_column(String(50), default="docker_archive")
    source_path: Mapped[str] = mapped_column(String(500), default="")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)
    metadata_json: Mapped[str] = mapped_column(Text, default="{}")

    # Relationships
    scan: Mapped[ScanDB] = relationship(back_populates="container_image")
    layers: Mapped[list[ContainerLayerDB]] = relationship(
        back_populates="image",
        cascade="all, delete-orphan",
        order_by="ContainerLayerDB.layer_index",
    )
    image_components: Mapped[list[ContainerImageComponentDB]] = relationship(
        back_populates="image", cascade="all, delete-orphan"
    )

    __table_args__ = (
        Index("ix_container_images_scan", "scan_id"),
        Index("ix_container_images_digest", "digest"),
        Index("ix_container_images_reference", "reference"),
    )


class ContainerLayerDB(Base):
    """An individual filesystem layer of a scanned container image."""

    __tablename__ = "container_layers"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_generate_uuid)
    image_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("container_images.id", ondelete="CASCADE"), nullable=False
    )
    layer_index: Mapped[int] = mapped_column(Integer, nullable=False)
    digest: Mapped[str] = mapped_column(String(100), nullable=False)
    size_bytes: Mapped[int] = mapped_column(Integer, default=0)
    media_type: Mapped[str] = mapped_column(String(100), default="")
    command: Mapped[str | None] = mapped_column(Text, nullable=True)
    metadata_json: Mapped[str] = mapped_column(Text, default="{}")

    # Relationships
    image: Mapped[ContainerImageDB] = relationship(back_populates="layers")
    components: Mapped[list[ContainerImageComponentDB]] = relationship(back_populates="layer")

    __table_args__ = (
        Index("ix_container_layers_image", "image_id"),
        Index("ix_container_layers_digest", "digest"),
    )


class ContainerImageComponentDB(Base):
    """Links a project component to a container image, layer, and container path."""

    __tablename__ = "container_image_components"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_generate_uuid)
    image_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("container_images.id", ondelete="CASCADE"), nullable=False
    )
    component_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("project_components.id", ondelete="CASCADE"), nullable=False
    )
    layer_id: Mapped[str | None] = mapped_column(
        String(36), ForeignKey("container_layers.id", ondelete="SET NULL"), nullable=True
    )
    container_path: Mapped[str] = mapped_column(String(500), default="")
    stage: Mapped[str] = mapped_column(String(100), default="runtime")
    package_manager: Mapped[str | None] = mapped_column(String(50), nullable=True)
    is_runtime: Mapped[bool] = mapped_column(Boolean, default=True)
    metadata_json: Mapped[str] = mapped_column(Text, default="{}")

    # Relationships
    image: Mapped[ContainerImageDB] = relationship(back_populates="image_components")
    component: Mapped[ProjectComponentDB] = relationship()
    layer: Mapped[ContainerLayerDB | None] = relationship(back_populates="components")

    __table_args__ = (
        Index("ix_cont_img_comp_image", "image_id"),
        Index("ix_cont_img_comp_component", "component_id"),
        Index("ix_cont_img_comp_layer", "layer_id"),
    )
