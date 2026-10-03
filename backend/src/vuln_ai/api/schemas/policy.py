"""Pydantic schemas for Policy and Suppression REST API endpoints."""

from __future__ import annotations

from datetime import datetime
from typing import Any

from pydantic import BaseModel, Field

from vuln_ai.policy.models import (
    PolicyAction,
)


class PolicyConditionSchema(BaseModel):
    severity: str | list[str] | None = None
    risk_level: str | list[str] | None = None
    applicability: str | list[str] | None = None
    dependency_type: str | list[str] | None = None
    scope: str | list[str] | None = None
    ecosystem: str | list[str] | None = None
    package_name: str | list[str] | None = None
    package_version: str | None = None
    vulnerability_id: str | list[str] | None = None
    source: str | list[str] | None = None
    has_kev_evidence: bool | None = None
    cvss_score: float | None = None
    cvss_comparator: str = ">="
    requires_human_review: bool | None = None
    conflict_detected: bool | None = None
    conflict_type: str | list[str] | None = None


class PolicyRuleSchema(BaseModel):
    id: str
    description: str = ""
    when: PolicyConditionSchema = Field(default_factory=PolicyConditionSchema)
    action: PolicyAction = PolicyAction.BLOCK
    reason: str | None = None
    enabled: bool = True
    priority: int = 100


class PolicyThresholdsSchema(BaseModel):
    fail_on: list[str] = Field(default_factory=list)
    fail_on_review: bool = False


class PolicyCreateRequest(BaseModel):
    name: str
    version: str = "1"
    description: str = ""
    enabled: bool = True
    thresholds: PolicyThresholdsSchema = Field(default_factory=PolicyThresholdsSchema)
    rules: list[PolicyRuleSchema] = Field(default_factory=list)
    default_action: PolicyAction = PolicyAction.ALLOW
    metadata: dict[str, Any] = Field(default_factory=dict)


class PolicyUpdateRequest(BaseModel):
    name: str | None = None
    description: str | None = None
    enabled: bool | None = None
    thresholds: PolicyThresholdsSchema | None = None
    rules: list[PolicyRuleSchema] | None = None
    default_action: PolicyAction | None = None
    metadata: dict[str, Any] | None = None


class PolicyResponse(BaseModel):
    id: str
    name: str
    version: str
    description: str
    enabled: bool
    thresholds: PolicyThresholdsSchema
    rules: list[PolicyRuleSchema]
    default_action: str
    metadata: dict[str, Any]
    created_at: datetime
    updated_at: datetime


class PolicyValidateRequest(BaseModel):
    yaml_content: str | None = None
    policy: PolicyCreateRequest | None = None


class PolicyValidateResponse(BaseModel):
    valid: bool
    errors: list[str] = Field(default_factory=list)
    policy: PolicyResponse | None = None


class SuppressionMatchCriteriaSchema(BaseModel):
    vulnerability_id: str | None = None
    package_name: str | None = None
    ecosystem: str | None = None
    package_version: str | None = None
    finding_id: str | None = None
    project_id: str | None = None


class SuppressionCreateRequest(BaseModel):
    project_id: str | None = None
    match_criteria: SuppressionMatchCriteriaSchema = Field(
        default_factory=SuppressionMatchCriteriaSchema
    )
    reason: str
    owner: str
    reference: str
    expires_at: datetime | None = None
    enabled: bool = True


class SuppressionUpdateRequest(BaseModel):
    reason: str | None = None
    owner: str | None = None
    reference: str | None = None
    expires_at: datetime | None = None
    enabled: bool | None = None
    match_criteria: SuppressionMatchCriteriaSchema | None = None


class SuppressionResponse(BaseModel):
    id: str
    project_id: str | None
    match_criteria: SuppressionMatchCriteriaSchema
    reason: str
    owner: str
    reference: str
    expires_at: datetime | None
    enabled: bool
    status: str
    created_by: str
    created_at: datetime
    updated_at: datetime


class FindingEvaluationResponse(BaseModel):
    finding_id: str
    component_name: str
    component_version: str
    ecosystem: str
    vulnerability_id: str
    action: str
    status: str
    matched_rules: list[str]
    matched_suppression_id: str | None
    reason: str
    is_violation: bool
    requires_human_review: bool
    audit_trace: dict[str, Any]


class PolicyEvaluateRequest(BaseModel):
    policy_id: str | None = Field(
        None, description="Optional stored policy ID to evaluate against"
    )
    policy_content: str | None = Field(
        None, description="Optional raw YAML policy string to evaluate against"
    )


class PolicyEvaluationResponse(BaseModel):
    policy_id: str
    policy_name: str
    status: str = "ALLOWED"
    total_findings: int = 0
    allowed_count: int = 0
    violations_count: int = 0
    suppressed_count: int = 0
    accepted_risk_count: int = 0
    requires_review_count: int = 0
    has_violations: bool = False
    ci_exit_code: int = 0
    evaluations: list[FindingEvaluationResponse] = Field(default_factory=list)
    violations: list[FindingEvaluationResponse] = Field(default_factory=list)
    suppressions_applied: list[dict[str, Any]] = Field(default_factory=list)
    evaluated_at: datetime
