"""Domain models for Local Vulnerability AI.

These Pydantic models represent the core domain concepts.
They are independent of the database layer (SQLAlchemy) and can be used
across CLI, API, and any other interface.
"""

from __future__ import annotations

import enum
from datetime import datetime
from typing import Any

from pydantic import BaseModel, Field

# --- Enums ---


class Ecosystem(enum.StrEnum):
    """Package ecosystem identifiers."""

    PYPI = "pypi"
    NPM = "npm"
    CARGO = "cargo"
    GO = "go"
    MAVEN = "maven"
    NUGET = "nuget"
    UNKNOWN = "unknown"


class ComponentType(enum.StrEnum):
    """Type of detected component."""

    LIBRARY = "library"
    FRAMEWORK = "framework"
    RUNTIME = "runtime"
    TOOL = "tool"
    UNKNOWN = "unknown"


class VersionType(enum.StrEnum):
    """How the version was determined."""

    EXACT = "exact"  # e.g., "==1.2.3" or "1.2.3"
    RANGE = "range"  # e.g., ">=1.0,<2.0"
    MINIMUM = "minimum"  # e.g., ">=1.0"
    UNKNOWN = "unknown"  # No version specified


class SourceStatus(enum.StrEnum):
    """Status of a vulnerability source."""

    ACTIVE = "active"
    ERROR = "error"
    DISABLED = "disabled"
    SYNCING = "syncing"
    NEVER_SYNCED = "never_synced"


class ScanStatus(enum.StrEnum):
    """Status of a scan operation."""

    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"


class MatchType(enum.StrEnum):
    """How the match was determined."""

    EXACT_NAME = "exact_name"  # Component name matches product exactly
    VENDOR_PRODUCT = "vendor_product"  # Matches vendor + product combination
    NORMALIZED = "normalized"  # Matched after normalization
    NONE = "none"


class Applicability(enum.StrEnum):
    """How likely the vulnerability applies to the specific deployment."""

    DETECTED = "detected"  # Component found in known vulnerability list
    LIKELY_AFFECTED = "likely_affected"  # Strong evidence of being affected
    LIKELY_NOT_AFFECTED = "likely_not_affected"
    UNKNOWN = "unknown"  # Insufficient evidence
    REQUIRES_REVIEW = "requires_review"  # Needs human judgment


# --- Domain Models ---


class DetectedComponent(BaseModel):
    """A software component detected in a project."""

    name: str = Field(description="Package/component name as declared")
    version: str | None = Field(default=None, description="Version string if available")
    version_type: VersionType = Field(
        default=VersionType.UNKNOWN,
        description="How the version was specified",
    )
    version_constraint: str | None = Field(
        default=None,
        description="Original version constraint (e.g., '>=2.0,<3.0')",
    )
    ecosystem: Ecosystem = Field(description="Package ecosystem")
    source_file: str = Field(description="File where component was detected")
    component_type: ComponentType = Field(default=ComponentType.LIBRARY)

    def normalized_name(self) -> str:
        """Return normalized component name for matching."""
        return normalize_component_name(self.name)


class VulnerabilityRecord(BaseModel):
    """A vulnerability record from an external source."""

    cve_id: str = Field(description="CVE identifier (e.g., 'CVE-2024-1234')")
    source_name: str = Field(description="Name of the source (e.g., 'CISA KEV')")
    vendor_project: str = Field(description="Vendor or project name")
    product: str = Field(description="Product name")
    vulnerability_name: str = Field(default="", description="Human-readable vulnerability name")
    short_description: str = Field(default="", description="Brief description")
    required_action: str = Field(default="", description="Recommended action")
    date_added: datetime | None = Field(default=None, description="Date added to source")
    due_date: datetime | None = Field(default=None, description="Remediation due date")
    known_ransomware_use: str = Field(
        default="Unknown",
        description="Known ransomware campaign use",
    )
    cwes: list[str] = Field(default_factory=list, description="Associated CWE identifiers")
    notes: str = Field(default="", description="Additional notes or references")

    def normalized_vendor(self) -> str:
        """Return normalized vendor name."""
        return normalize_component_name(self.vendor_project)

    def normalized_product(self) -> str:
        """Return normalized product name."""
        return normalize_component_name(self.product)


class MatchResult(BaseModel):
    """Result of matching a component against a vulnerability."""

    component: DetectedComponent
    vulnerability: VulnerabilityRecord
    match_type: MatchType = Field(description="How the match was determined")
    match_confidence: float = Field(
        ge=0.0,
        le=1.0,
        description="Confidence score of the match (0.0 to 1.0)",
    )
    applicability: Applicability = Field(
        default=Applicability.UNKNOWN,
        description="Applicability assessment",
    )
    evidence: list[str] = Field(
        default_factory=list,
        description="Evidence supporting the match",
    )
    ai_analysis: Any = Field(
        default=None,
        description="Contextual LLM analysis if available",
    )
    decision: Any = Field(
        default=None,
        description="Probabilistic SystemOne decision if available",
    )
    risk_assessment: Any = Field(
        default=None,
        description="Deterministic risk assessment if evaluated",
    )


class SyncResult(BaseModel):
    """Result of synchronizing a vulnerability source."""

    source_name: str
    success: bool
    records_synced: int = 0
    records_total: int = 0
    error: str | None = None
    duration_seconds: float = 0.0


class ScanResultSummary(BaseModel):
    """Summary of a completed scan."""

    project_name: str
    project_path: str
    scan_status: ScanStatus
    components_found: int = 0
    vulnerabilities_checked: int = 0
    matches_found: int = 0
    kev_matches: int = 0
    duration_seconds: float = 0.0
    error: str | None = None
    matches: list[MatchResult] = Field(default_factory=list)


class SourceInfo(BaseModel):
    """Information about a configured vulnerability source."""

    name: str
    source_type: str
    url: str
    status: SourceStatus
    last_sync: datetime | None = None
    record_count: int = 0
    last_error: str | None = None


# --- Utility Functions ---


def normalize_component_name(name: str) -> str:
    """Normalize a component/package name for consistent matching.

    Rules:
    - Convert to lowercase
    - Replace hyphens with underscores (PEP 503 normalization for PyPI)
    - Replace dots with underscores
    - Strip leading/trailing whitespace
    - Collapse multiple underscores

    Examples:
        >>> normalize_component_name("My-Package")
        'my_package'
        >>> normalize_component_name("my.package")
        'my_package'
        >>> normalize_component_name("  FortiMail  ")
        'fortimail'
    """
    normalized = name.strip().lower()
    normalized = normalized.replace("-", "_")
    normalized = normalized.replace(".", "_")
    # Collapse multiple underscores
    while "__" in normalized:
        normalized = normalized.replace("__", "_")
    # Strip leading/trailing underscores
    normalized = normalized.strip("_")
    return normalized
