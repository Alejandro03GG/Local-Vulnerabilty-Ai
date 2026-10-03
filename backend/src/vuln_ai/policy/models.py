"""Domain models for Policy & Suppression Engine (Etapa 16).

Maintains a strict boundary:
- Security findings represent technical ground truth.
- Policies represent organizational compliance rules.
- Suppressions represent documented, auditable exemptions.
"""

from __future__ import annotations

import enum
import uuid
from datetime import UTC, datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from vuln_ai.policy.clock import Clock


def _generate_uuid() -> str:
    return str(uuid.uuid4())


def _utcnow() -> datetime:
    return datetime.now(UTC)


class PolicyAction(enum.StrEnum):
    """Actions resulting from policy rule matching or default policy behavior."""

    ALLOW = "ALLOW"
    BLOCK = "BLOCK"
    REQUIRE_REVIEW = "REQUIRE_REVIEW"
    SUPPRESS = "SUPPRESS"
    ACCEPT_RISK = "ACCEPT_RISK"


class PolicyStatus(enum.StrEnum):
    """Consolidated policy evaluation status for a finding."""

    ALLOWED = "ALLOWED"
    VIOLATION = "VIOLATION"
    SUPPRESSED = "SUPPRESSED"
    ACCEPTED_RISK = "ACCEPTED_RISK"
    REQUIRES_REVIEW = "REQUIRES_REVIEW"


class SuppressionStatus(enum.StrEnum):
    """Lifecycle status of a suppression rule."""

    ACTIVE = "ACTIVE"
    EXPIRED = "EXPIRED"
    DISABLED = "DISABLED"


class CVSSComparator(enum.StrEnum):
    """Comparison operators for CVSS score evaluation."""

    GTE = ">="
    GT = ">"
    EQ = "=="
    LTE = "<="
    LT = "<"


class PolicyCondition(BaseModel):
    """Conditions that a finding must meet for a policy rule to match."""

    model_config = ConfigDict(extra="forbid")

    severity: list[str] | str | None = Field(
        default=None,
        description="Vulnerability severity level(s), e.g. ['HIGH', 'CRITICAL']",
    )
    risk_level: list[str] | str | None = Field(
        default=None,
        description="Deterministic risk engine level(s), e.g. ['HIGH', 'CRITICAL']",
    )
    applicability: list[str] | str | None = Field(
        default=None,
        description="Canonical applicability status(es), e.g. ['LIKELY_AFFECTED']",
    )
    dependency_type: list[str] | str | None = Field(
        default=None,
        description="Dependency type: 'DIRECT' or 'TRANSITIVE'",
    )
    scope: list[str] | str | None = Field(
        default=None,
        description="Dependency scope, e.g. 'RUNTIME', 'DEV', 'OPTIONAL', 'PEER'",
    )
    ecosystem: list[str] | str | None = Field(
        default=None,
        description="Packaging ecosystem(s), e.g. 'pypi', 'npm', 'cargo'",
    )
    package_name: list[str] | str | None = Field(
        default=None,
        description="Package name(s) to match (exact or normalized)",
    )
    package_version: str | None = Field(
        default=None,
        description="Package version exact string",
    )
    vulnerability_id: list[str] | str | None = Field(
        default=None,
        description="Vulnerability identifier(s) (canonical_id or aliases like CVE-*, GHSA-*)",
    )
    source: list[str] | str | None = Field(
        default=None,
        description="Vulnerability source(s), e.g. 'CISA KEV', 'OSV', 'NVD'",
    )
    has_kev_evidence: bool | None = Field(
        default=None,
        description="Match if vulnerability is known exploited in the wild (CISA KEV)",
    )
    cvss_score: float | None = Field(
        default=None,
        description="CVSS score threshold for numerical comparison",
    )
    cvss_comparator: CVSSComparator = Field(
        default=CVSSComparator.GTE,
        description="Comparator operator for cvss_score",
    )
    requires_human_review: bool | None = Field(
        default=None,
        description="Match if finding has requires_human_review flag set",
    )
    conflict_detected: bool | None = Field(
        default=None,
        description="Match if multi-source discrepancies exist",
    )
    conflict_type: str | None = Field(
        default=None,
        description="Match specific conflict category, e.g. 'APPLICABILITY'",
    )
    image_digest: list[str] | str | None = Field(
        default=None,
        description="Container image digest(s) to restrict rule matching (sha256:...)",
    )

    @model_validator(mode="before")
    @classmethod
    def _normalize_common_aliases(cls, data: Any) -> Any:
        if isinstance(data, dict):
            data = dict(data)
            if "package" in data and "package_name" not in data:
                data["package_name"] = data.pop("package")
            if "risk" in data and "risk_level" not in data:
                data["risk_level"] = data.pop("risk")
        return data

    @field_validator("applicability")
    @classmethod
    def validate_no_prohibited_terms(cls, v: list[str] | str | None) -> list[str] | str | None:
        """Enforce prohibition of non-canonical status terms like 'VULNERABLE'."""
        if v is None:
            return None
        items = [v] if isinstance(v, str) else v
        for item in items:
            if str(item).upper().strip() == "VULNERABLE":
                raise ValueError(
                    "Status 'VULNERABLE' is prohibited across all layers. "
                    "Use canonical states: LIKELY_AFFECTED, LIKELY_NOT_AFFECTED, "
                    "REQUIRES_REVIEW, DETECTED, UNKNOWN."
                )
        return v


class PolicyRule(BaseModel):
    """An individual rule within a policy."""

    model_config = ConfigDict(extra="forbid")

    id: str = Field(description="Unique alphanumeric identifier for the rule")
    description: str = Field(default="", description="Human-readable description of rule intent")
    when: PolicyCondition = Field(
        default_factory=PolicyCondition,
        description="Conditions required to trigger this rule",
    )
    action: PolicyAction = Field(
        default=PolicyAction.BLOCK,
        description="Action to take when conditions match",
    )
    reason: str | None = Field(
        default=None,
        description="Specific explanation emitted when rule matches",
    )
    enabled: bool = Field(default=True, description="Whether the rule is evaluated")
    priority: int = Field(
        default=100, description="Evaluation order priority (lower runs earlier)"
    )


class PolicyThresholds(BaseModel):
    """Global security thresholds configured for the policy."""

    model_config = ConfigDict(extra="forbid")

    fail_on: list[str] = Field(
        default_factory=list,
        description="Severities or risk levels that fail CI/CD if matched, e.g. ['HIGH', 'CRITICAL']",
    )
    fail_on_review: bool = Field(
        default=False,
        description="Trigger CI/CD violation if any finding requires human review",
    )


class Policy(BaseModel):
    """Complete declarative security policy definition."""

    model_config = ConfigDict(extra="forbid")

    id: str = Field(default_factory=_generate_uuid, description="Unique policy UUID or key")
    name: str = Field(description="Policy name")
    version: str = Field(default="1", description="Policy format/schema version")
    description: str = Field(default="", description="Policy description")
    enabled: bool = Field(default=True, description="Whether the policy is enabled")
    thresholds: PolicyThresholds = Field(
        default_factory=PolicyThresholds,
        description="Global policy thresholds",
    )
    rules: list[PolicyRule] = Field(
        default_factory=list,
        description="Ordered list of policy rules",
    )
    suppressions: list[Suppression] = Field(
        default_factory=list,
        description="Inline suppressions declared within the policy document",
    )
    default_action: PolicyAction = Field(
        default=PolicyAction.ALLOW,
        description="Fallback action if no rules or thresholds match",
    )
    metadata: dict[str, Any] = Field(default_factory=dict, description="Custom metadata")
    created_at: datetime = Field(default_factory=_utcnow)
    updated_at: datetime = Field(default_factory=_utcnow)


class SuppressionMatchCriteria(BaseModel):
    """Target criteria determining what findings a suppression applies to."""

    model_config = ConfigDict(extra="forbid")

    vulnerability_id: str | None = Field(
        default=None,
        description="Match specific vulnerability canonical_id or alias (CVE, GHSA, etc.)",
    )
    package_name: str | None = Field(
        default=None,
        description="Match specific package name",
    )
    ecosystem: str | None = Field(
        default=None,
        description="Match specific packaging ecosystem ('pypi', 'npm', 'cargo')",
    )
    package_version: str | None = Field(
        default=None,
        description="Match specific component version string",
    )
    finding_id: str | None = Field(
        default=None,
        description="Match specific finding ID",
    )
    project_id: str | None = Field(
        default=None,
        description="Scope suppression to specific project UUID",
    )
    image_digest: str | None = Field(
        default=None,
        description="Scope suppression to specific container image digest (sha256:...)",
    )


class Suppression(BaseModel):
    """Documented, auditable exemption for a specific vulnerability or package."""

    model_config = ConfigDict(extra="forbid")

    id: str = Field(default_factory=_generate_uuid, description="Unique suppression UUID")
    project_id: str | None = Field(
        default=None,
        description="Optional project ID scope. If None, applies globally.",
    )
    match_criteria: SuppressionMatchCriteria = Field(
        default_factory=SuppressionMatchCriteria,
        description="Target criteria for suppression",
    )
    reason: str = Field(
        min_length=3,
        description="Mandatory human justification explaining why this finding is exempted",
    )
    owner: str = Field(
        min_length=1,
        description="Mandatory responsible individual, team, or email",
    )
    reference: str = Field(
        min_length=1,
        description="Mandatory external tracking reference (e.g. 'SEC-2026-0042', 'JIRA-999')",
    )
    expires_at: datetime | None = Field(
        default=None,
        description="Expiration timestamp. If passed, suppression ceases to exempt findings.",
    )
    enabled: bool = Field(default=True, description="Whether the suppression is active")
    created_by: str = Field(
        default="system", description="User or entity that created suppression"
    )
    created_at: datetime = Field(default_factory=_utcnow)
    updated_at: datetime = Field(default_factory=_utcnow)
    metadata: dict[str, Any] = Field(default_factory=dict)

    def status(self, clock: Clock | None = None) -> SuppressionStatus:
        """Determine lifecycle status (ACTIVE, EXPIRED, DISABLED) with injected clock."""
        if not self.enabled:
            return SuppressionStatus.DISABLED
        if self.expires_at is not None:
            now_dt = clock.now() if clock else datetime.now(UTC)
            exp = (
                self.expires_at if self.expires_at.tzinfo else self.expires_at.replace(tzinfo=UTC)
            )
            if now_dt >= exp:
                return SuppressionStatus.EXPIRED
        return SuppressionStatus.ACTIVE

    def is_active(self, clock: Clock | None = None) -> bool:
        """Return True if suppression is currently valid and active."""
        return self.status(clock) == SuppressionStatus.ACTIVE


class FindingEvaluation(BaseModel):
    """Policy evaluation result for a single security finding."""

    finding_id: str
    component_name: str
    component_version: str
    ecosystem: str
    vulnerability_id: str
    action: PolicyAction
    status: PolicyStatus
    matched_rules: list[str] = Field(default_factory=list)
    matched_suppression_id: str | None = None
    reason: str = ""
    is_violation: bool = False
    requires_human_review: bool = False
    audit_trace: dict[str, Any] = Field(default_factory=dict)


class PolicyEvaluationResult(BaseModel):
    """Aggregate policy evaluation report for an entire scan."""

    policy_id: str
    policy_name: str
    total_findings: int = 0
    allowed_count: int = 0
    violations_count: int = 0
    suppressed_count: int = 0
    accepted_risk_count: int = 0
    requires_review_count: int = 0
    has_violations: bool = False
    evaluations: list[FindingEvaluation] = Field(default_factory=list)
    violations: list[FindingEvaluation] = Field(default_factory=list)
    suppressions_applied: list[dict[str, Any]] = Field(default_factory=list)
    evaluated_at: datetime = Field(default_factory=_utcnow)
    duration_seconds: float = 0.0
    ci_exit_code: int = 0
