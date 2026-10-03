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
    DEB = "deb"
    APK = "apk"
    RPM = "rpm"
    UNKNOWN = "unknown"


class ComponentType(enum.StrEnum):
    """Type of detected component."""

    LIBRARY = "library"
    FRAMEWORK = "framework"
    RUNTIME = "runtime"
    TOOL = "tool"
    OS_PACKAGE = "os_package"
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


class DependencyType(enum.StrEnum):
    """Direct vs Transitive dependency classification."""

    DIRECT = "direct"
    TRANSITIVE = "transitive"
    UNKNOWN = "unknown"


class DependencyScope(enum.StrEnum):
    """Dependency installation or runtime scope."""

    RUNTIME = "runtime"
    DEV = "dev"
    OPTIONAL = "optional"
    PEER = "peer"
    UNKNOWN = "unknown"


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
    is_direct: bool = Field(default=True, description="Whether component is a direct dependency")
    dependency_type: DependencyType | str = Field(
        default=DependencyType.DIRECT, description="Direct or transitive"
    )
    scope: DependencyScope | str = Field(
        default=DependencyScope.RUNTIME, description="Lifecycle or install scope"
    )
    manifest_source: str | None = Field(
        default=None, description="Manifest declaring the dependency"
    )
    lockfile_source: str | None = Field(
        default=None, description="Lockfile resolving the exact version"
    )
    parent_name: str | None = Field(
        default=None, description="Parent dependency package name if transitive"
    )
    dependency_path: list[str] = Field(
        default_factory=list, description="Ancestor dependency chain from project root"
    )
    metadata: dict[str, Any] = Field(
        default_factory=dict, description="Additional dependency metadata"
    )

    def normalized_name(self) -> str:
        """Return normalized component name for matching."""
        return normalize_component_name(self.name)

    def component_key(self) -> tuple[str, str | None, str]:
        """Return unique component identity tuple (name, version, source_file)."""
        return (self.normalized_name(), self.version, self.source_file)


class IdentifierType(enum.StrEnum):
    """Types of vulnerability identifiers."""

    CVE = "cve"
    GHSA = "ghsa"
    OSV = "osv"
    PYSEC = "pysec"
    ALIAS = "alias"
    OTHER = "other"


class EvidenceType(enum.StrEnum):
    """Categorization of match evidence."""

    RANGE_CONFIRMED = "range_confirmed"
    OUTSIDE_RANGE = "outside_range"
    PRODUCT_NAME_ONLY = "product_name_only"
    SOURCE_CONFLICT = "source_conflict"
    VERSION_UNKNOWN = "version_unknown"


class VulnerabilityIdentifier(BaseModel):
    """An identifier or alias for a vulnerability (CVE, GHSA, OSV, etc.)."""

    identifier: str = Field(description="Identifier string (e.g. 'CVE-2024-1234', 'GHSA-xxxx')")
    identifier_type: IdentifierType | str = Field(
        default=IdentifierType.CVE,
        description="Type of identifier",
    )
    source: str = Field(default="unknown", description="Source that reported this identifier")


class AffectedVersionRange(BaseModel):
    """An affected version range for a specific ecosystem package."""

    ecosystem: Ecosystem | str = Field(description="Package ecosystem (e.g. pypi, npm)")
    package_name: str = Field(description="Target package name")
    range_type: str = Field(
        default="ecosystem", description="Range standard (e.g. ecosystem, semver, pep440)"
    )
    introduced: str | None = Field(default=None, description="Starting version introduced")
    fixed: str | None = Field(default=None, description="Version where vulnerability was fixed")
    last_affected: str | None = Field(
        default=None, description="Last vulnerable version before fix"
    )
    limit: str | None = Field(
        default=None,
        description="Exclusive upper bound (OSV 'limit' event, not a fix)",
    )
    raw_range: str | None = Field(
        default=None, description="Raw expression if available (e.g. '< 2.32.0')"
    )
    source_name: str = Field(default="unknown", description="Source reporting this range")


class VulnerabilitySourceRecord(BaseModel):
    """A record of evidence contributed by a specific vulnerability source."""

    source_id: str | None = Field(default=None, description="Database ID of vulnerability source")
    source_name: str = Field(description="Name of the source (e.g. 'CISA KEV', 'OSV', 'NVD')")
    source_identifier: str = Field(description="Identifier used by this source")
    has_kev_evidence: bool = Field(
        default=False, description="Whether source provides KEV confirmation"
    )
    has_affected_range: bool = Field(
        default=False, description="Whether source provides version ranges"
    )
    raw_payload: dict[str, Any] = Field(default_factory=dict, description="Raw source payload")
    synced_at: datetime | None = Field(default=None, description="Sync timestamp")


class MatchEvidence(BaseModel):
    """Structured, auditable evidence supporting a match determination."""

    source_name: str = Field(description="Source contributing this evidence")
    identifier: str = Field(description="Vulnerability identifier")
    package_name: str = Field(description="Package evaluated")
    ecosystem: Ecosystem | str = Field(description="Package ecosystem")
    installed_version: str | None = Field(default=None, description="Installed component version")
    affected_range: str | None = Field(
        default=None, description="Affected version range evaluated"
    )
    fixed_version: str | None = Field(default=None, description="Fixed version if specified")
    status: Applicability = Field(
        default=Applicability.UNKNOWN, description="Source-level applicability"
    )
    evidence_type: EvidenceType | str = Field(
        default=EvidenceType.PRODUCT_NAME_ONLY,
        description="Type of evidence",
    )
    details: str = Field(default="", description="Human-readable explanation of evaluation")
    created_at: datetime | None = Field(default=None, description="Timestamp")


class VulnerabilityRecord(BaseModel):
    """A canonical vulnerability record independent of any specific source.

    May represent vulnerabilities identified via CVE, GHSA, OSV, PYSEC, or other schemes.
    Retains backwards compatibility with cve_id while making canonical_id the primary identifier.
    """

    canonical_id: str = Field(
        default="", description="Primary canonical identifier (CVE, GHSA, OSV, etc.)"
    )
    cve_id: str | None = Field(default=None, description="CVE identifier if assigned")
    source_name: str = Field(default="unknown", description="Primary or discovering source name")
    vendor_project: str = Field(default="", description="Vendor or project name")
    product: str = Field(default="", description="Product name")
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
    severity: str | None = Field(default=None, description="Severity rating if known")
    cvss_score: float | None = Field(default=None, description="CVSS numerical score")
    identifiers: list[VulnerabilityIdentifier] = Field(
        default_factory=list,
        description="All known identifiers/aliases",
    )
    source_records: list[VulnerabilitySourceRecord] = Field(
        default_factory=list,
        description="Source-specific records and evidence",
    )
    affected_ranges: list[AffectedVersionRange] = Field(
        default_factory=list,
        description="Known affected version ranges",
    )

    def model_post_init(self, __context: Any) -> None:
        """Ensure canonical_id and cve_id coherence for backward compatibility."""
        if not self.canonical_id:
            if self.cve_id:
                self.canonical_id = self.cve_id
            elif self.identifiers:
                self.canonical_id = self.identifiers[0].identifier
            else:
                self.canonical_id = "UNKNOWN-VULN"

        if not self.cve_id and self.canonical_id.upper().startswith("CVE-"):
            self.cve_id = self.canonical_id

        # Populate initial identifier if empty
        if not self.identifiers and self.canonical_id:
            id_type = (
                IdentifierType.CVE
                if self.canonical_id.upper().startswith("CVE-")
                else (
                    IdentifierType.GHSA
                    if self.canonical_id.upper().startswith("GHSA-")
                    else IdentifierType.OTHER
                )
            )
            self.identifiers.append(
                VulnerabilityIdentifier(
                    identifier=self.canonical_id,
                    identifier_type=id_type,
                    source=self.source_name,
                )
            )

    def normalized_vendor(self) -> str:
        """Return normalized vendor name."""
        return normalize_component_name(self.vendor_project)

    def normalized_product(self) -> str:
        """Return normalized product name."""
        return normalize_component_name(self.product)

    @property
    def has_kev_evidence(self) -> bool:
        """Return True if this vulnerability has KEV confirmation from any source."""
        if self.source_name == "CISA KEV":
            return True
        return any(
            getattr(sr, "has_kev_evidence", False) or getattr(sr, "source_name", "") == "CISA KEV"
            for sr in self.source_records
        )


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
        description="Evidence supporting the match (legacy summary format)",
    )
    structured_evidences: list[MatchEvidence] = Field(
        default_factory=list,
        description="Structured, auditable evidence records",
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
    conflicts: list[Any] = Field(
        default_factory=list,
        description="Source conflicts detected during multi-source correlation",
    )
    conflict_resolution: Any = Field(
        default=None,
        description="Consolidated applicability resolution summary",
    )

    def model_post_init(self, __context: Any) -> None:
        """Sync evidence strings with structured_evidences if empty."""
        if not self.evidence and self.structured_evidences:
            for ev in self.structured_evidences:
                self.evidence.append(
                    f"[{ev.source_name}] {ev.identifier} for {ev.package_name}: "
                    f"{ev.status.value.upper()} (type: {ev.evidence_type}) - {ev.details}"
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
    direct_components_count: int = 0
    transitive_components_count: int = 0
    dependency_edges_count: int = 0
    lockfiles_detected: list[str] = Field(default_factory=list)
    vulnerabilities_checked: int = 0
    matches_found: int = 0
    kev_matches: int = 0
    duration_seconds: float = 0.0
    error: str | None = None
    matches: list[MatchResult] = Field(default_factory=list)
    dependency_graph: Any = Field(
        default=None, description="In-memory dependency graph if resolved"
    )
    scan_id: str | None = Field(default=None, description="Database scan ID if persisted")
    metadata: dict[str, Any] = Field(default_factory=dict, description="Arbitrary scan metadata")


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
