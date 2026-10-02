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
    """A known vulnerability from an external source."""

    __tablename__ = "vulnerabilities"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_generate_uuid)
    cve_id: Mapped[str] = mapped_column(String(30), nullable=False)
    source_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("vulnerability_sources.id", ondelete="CASCADE"), nullable=False
    )
    vendor_project: Mapped[str] = mapped_column(String(255), nullable=False)
    product: Mapped[str] = mapped_column(String(255), nullable=False)
    vulnerability_name: Mapped[str] = mapped_column(Text, default="")
    short_description: Mapped[str] = mapped_column(Text, default="")
    required_action: Mapped[str] = mapped_column(Text, default="")
    date_added: Mapped[str | None] = mapped_column(String(20), nullable=True)
    due_date: Mapped[str | None] = mapped_column(String(20), nullable=True)
    known_ransomware_use: Mapped[str] = mapped_column(String(50), default="Unknown")
    cwes: Mapped[str] = mapped_column(Text, default="[]")  # JSON array stored as text
    notes: Mapped[str] = mapped_column(Text, default="")
    synced_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)

    # Relationships
    source: Mapped[VulnerabilitySourceDB] = relationship(back_populates="vulnerabilities")
    matches: Mapped[list[MatchDB]] = relationship(
        back_populates="vulnerability", cascade="all, delete-orphan"
    )

    __table_args__ = (
        Index("ix_vuln_cve_id", "cve_id"),
        Index("ix_vuln_source", "source_id"),
        Index("ix_vuln_vendor_product", "vendor_project", "product"),
        Index("ix_vuln_cve_source", "cve_id", "source_id", unique=True),
    )


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

    __table_args__ = (
        Index("ix_matches_scan", "scan_id"),
        Index("ix_matches_component", "component_id"),
        Index("ix_matches_vulnerability", "vulnerability_id"),
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
