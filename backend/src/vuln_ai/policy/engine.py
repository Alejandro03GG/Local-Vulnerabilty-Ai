"""Deterministic Policy Engine (Etapa 16 §1, §3, §7, §11, §12, §13).

Evaluates security findings against declarative policies, rules, thresholds,
and active/expired suppressions without altering core security findings.
"""

from __future__ import annotations

import time
from typing import Any

from vuln_ai.core.models import (
    Applicability,
    MatchResult,
    ScanResultSummary,
    normalize_component_name,
)
from vuln_ai.policy.clock import Clock, SystemClock
from vuln_ai.policy.models import (
    CVSSComparator,
    FindingEvaluation,
    Policy,
    PolicyAction,
    PolicyCondition,
    PolicyEvaluationResult,
    PolicyRule,
    PolicyStatus,
    Suppression,
    SuppressionStatus,
)
from vuln_ai.policy.suppression import SuppressionMatcher


class ConditionEvaluator:
    """Evaluates whether a MatchResult meets a PolicyCondition."""

    @classmethod
    def evaluate(cls, condition: PolicyCondition, match: MatchResult) -> bool:
        comp = match.component
        vuln = match.vulnerability
        risk = match.risk_assessment

        # 1. Severity
        if condition.severity is not None:
            target_sevs = [
                s.upper().strip()
                for s in (
                    [condition.severity]
                    if isinstance(condition.severity, str)
                    else condition.severity
                )
            ]
            actual_sev = (vuln.severity or "").upper().strip()
            if actual_sev not in target_sevs:
                return False

        # 2. Risk Level
        if condition.risk_level is not None:
            target_risks = [
                r.upper().strip()
                for r in (
                    [condition.risk_level]
                    if isinstance(condition.risk_level, str)
                    else condition.risk_level
                )
            ]
            actual_risk = (
                (getattr(risk, "risk_level", None) or "UNKNOWN").upper().strip()
                if risk
                else "UNKNOWN"
            )
            if actual_risk not in target_risks:
                return False

        # 3. Applicability
        if condition.applicability is not None:
            target_apps = [
                a.upper().strip()
                for a in (
                    [condition.applicability]
                    if isinstance(condition.applicability, str)
                    else condition.applicability
                )
            ]
            actual_app = (
                (
                    match.applicability.value
                    if hasattr(match.applicability, "value")
                    else str(match.applicability)
                )
                .upper()
                .strip()
            )
            if actual_app not in target_apps:
                return False

        # 4. Dependency Type ('DIRECT' vs 'TRANSITIVE')
        if condition.dependency_type is not None:
            target_types = [
                t.upper().strip()
                for t in (
                    [condition.dependency_type]
                    if isinstance(condition.dependency_type, str)
                    else condition.dependency_type
                )
            ]
            is_direct = getattr(comp, "is_direct", True)
            actual_type = "DIRECT" if is_direct else "TRANSITIVE"
            if actual_type not in target_types:
                return False

        # 5. Scope
        if condition.scope is not None:
            target_scopes = [
                s.upper().strip()
                for s in (
                    [condition.scope] if isinstance(condition.scope, str) else condition.scope
                )
            ]
            actual_scope = str(getattr(comp, "scope", "runtime") or "runtime").upper().strip()
            if actual_scope not in target_scopes:
                return False

        # 6. Ecosystem
        if condition.ecosystem is not None:
            target_ecos = [
                e.lower().strip()
                for e in (
                    [condition.ecosystem]
                    if isinstance(condition.ecosystem, str)
                    else condition.ecosystem
                )
            ]
            actual_eco = (
                str(comp.ecosystem.value if hasattr(comp.ecosystem, "value") else comp.ecosystem)
                .lower()
                .strip()
            )
            if actual_eco not in target_ecos:
                return False

        # 7. Package Name
        if condition.package_name is not None:
            target_pkgs = [
                normalize_component_name(p)
                for p in (
                    [condition.package_name]
                    if isinstance(condition.package_name, str)
                    else condition.package_name
                )
            ]
            actual_pkg = normalize_component_name(comp.name)
            if actual_pkg not in target_pkgs:
                return False

        # 8. Package Version
        if condition.package_version is not None and (
            not comp.version or condition.package_version.strip() != comp.version.strip()
        ):
            return False

        # 9. Vulnerability ID
        if condition.vulnerability_id is not None:
            target_vids = [
                v.upper().strip()
                for v in (
                    [condition.vulnerability_id]
                    if isinstance(condition.vulnerability_id, str)
                    else condition.vulnerability_id
                )
            ]
            all_vuln_ids: set[str] = set()
            if vuln.canonical_id:
                all_vuln_ids.add(vuln.canonical_id.upper().strip())
            if vuln.cve_id:
                all_vuln_ids.add(vuln.cve_id.upper().strip())
            for ident in getattr(vuln, "identifiers", []):
                if ident.identifier:
                    all_vuln_ids.add(ident.identifier.upper().strip())
            if not any(vid in all_vuln_ids for vid in target_vids):
                return False

        # 10. Source
        if condition.source is not None:
            target_sources = [
                s.upper().strip()
                for s in (
                    [condition.source] if isinstance(condition.source, str) else condition.source
                )
            ]
            actual_source = str(vuln.source_name or "").upper().strip()
            if actual_source not in target_sources:
                return False

        # 11. KEV Evidence
        if condition.has_kev_evidence is not None:
            actual_kev = bool(
                getattr(vuln, "has_kev_evidence", False)
                or getattr(vuln, "source_name", "") == "CISA KEV"
            )
            if actual_kev != condition.has_kev_evidence:
                return False

        # 12. CVSS Score
        if condition.cvss_score is not None:
            actual_cvss = getattr(vuln, "cvss_score", None)
            if actual_cvss is None:
                return False
            comp_op = condition.cvss_comparator
            target_cvss = condition.cvss_score
            if comp_op == CVSSComparator.GTE and not (actual_cvss >= target_cvss):
                return False
            if comp_op == CVSSComparator.GT and not (actual_cvss > target_cvss):
                return False
            if comp_op == CVSSComparator.EQ and actual_cvss != target_cvss:
                return False
            if comp_op == CVSSComparator.LTE and not (actual_cvss <= target_cvss):
                return False
            if comp_op == CVSSComparator.LT and not (actual_cvss < target_cvss):
                return False

        # 13. Requires Human Review
        if condition.requires_human_review is not None:
            actual_review = bool(
                getattr(risk, "requires_human_review", False)
                or match.applicability == Applicability.REQUIRES_REVIEW
            )
            if actual_review != condition.requires_human_review:
                return False

        # 14. Conflict Detected
        if condition.conflict_detected is not None:
            has_conflict = bool(
                getattr(match, "conflict_detected", False)
                or len(getattr(match, "conflicts", [])) > 0
            )
            if has_conflict != condition.conflict_detected:
                return False

        # 15. Conflict Type
        if condition.conflict_type is not None:
            target_type = condition.conflict_type.upper().strip()
            conflict_types = [
                str(getattr(c, "conflict_type", "")).upper().strip()
                for c in getattr(match, "conflicts", [])
            ]
            if hasattr(match, "conflict_type") and match.conflict_type:
                conflict_types.append(str(match.conflict_type).upper().strip())
            if target_type not in conflict_types:
                return False

        # 16. Container Image Digest
        if condition.image_digest is not None:
            target_digests = [
                d.strip()
                for d in (
                    [condition.image_digest]
                    if isinstance(condition.image_digest, str)
                    else condition.image_digest
                )
            ]
            comp_meta = comp.metadata or {}
            actual_digest = (
                comp_meta.get("container_digest") or comp_meta.get("image_digest") or ""
            )
            if not actual_digest or actual_digest not in target_digests:
                return False

        return True


class PolicyEngine:
    """Orchestrates deterministic policy evaluation over security findings."""

    def __init__(
        self,
        policy: Policy,
        suppressions: list[Suppression] | None = None,
        clock: Clock | None = None,
    ) -> None:
        self.policy = policy
        self.suppressions = suppressions or []
        self.clock = clock or SystemClock()

    def evaluate(
        self,
        matches: list[MatchResult],
        project_id: str | None = None,
    ) -> PolicyEvaluationResult:
        """Evaluate a collection of MatchResult findings against policy and suppressions."""
        t0 = time.perf_counter()

        evaluations: list[FindingEvaluation] = []
        violations: list[FindingEvaluation] = []
        applied_suppressions: list[dict[str, Any]] = []

        allowed_count = 0
        violations_count = 0
        suppressed_count = 0
        accepted_risk_count = 0
        requires_review_count = 0

        # Sort rules deterministically by priority then id
        sorted_rules = sorted(
            [r for r in self.policy.rules if r.enabled],
            key=lambda r: (r.priority, r.id),
        )

        for match in matches:
            finding_id = f"{match.component.ecosystem}:{match.component.name}:{match.component.version or 'none'}:{match.vulnerability.canonical_id}"

            # Step 1: Suppression Check
            active_sup, all_sups = SuppressionMatcher.find_matching_suppressions(
                self.suppressions,
                match,
                clock=self.clock,
                project_id=project_id,
                finding_id=finding_id,
            )

            has_conf = bool(
                len(getattr(match, "conflicts", [])) > 0
                or getattr(match, "conflict_detected", False)
            )
            c_type = (
                getattr(match, "conflict_type", None)
                or (
                    [str(getattr(c, "conflict_type", "")) for c in getattr(match, "conflicts", [])]
                    or [None]
                )[0]
            )
            audit_trace: dict[str, Any] = {
                "technical_risk": getattr(match.risk_assessment, "risk_level", "UNKNOWN")
                if match.risk_assessment
                else "UNKNOWN",
                "applicability": match.applicability.value
                if hasattr(match.applicability, "value")
                else str(match.applicability),
                "has_conflicts": has_conf,
                "conflict_detected": has_conf,
                "conflict_type": c_type,
                "has_kev_evidence": bool(
                    getattr(match.vulnerability, "has_kev_evidence", False)
                    or getattr(match.vulnerability, "source_name", "") == "CISA KEV"
                ),
            }

            if all_sups:
                audit_trace["matched_suppression_records"] = [
                    {
                        "id": s.id,
                        "status": s.status(self.clock).value,
                        "owner": s.owner,
                        "reference": s.reference,
                        "expires_at": s.expires_at.isoformat() if s.expires_at else None,
                    }
                    for s in all_sups
                ]

            # Evaluate matching rules for audit trace
            matching_rules: list[PolicyRule] = []
            for rule in sorted_rules:
                if ConditionEvaluator.evaluate(rule.when, match):
                    matching_rules.append(rule)
            matched_rule_ids = [r.id for r in matching_rules]

            if active_sup is not None:
                # Active suppression exempts finding
                suppressed_count += 1
                reason = f"Suppressed under {active_sup.reference} ({active_sup.owner}): {active_sup.reason}"
                audit_trace["decision"] = "SUPPRESSED"
                audit_trace["active_suppression_id"] = active_sup.id
                audit_trace["suppression_reason"] = active_sup.reason
                audit_trace["suppression_expires_at"] = (
                    active_sup.expires_at.isoformat() if active_sup.expires_at else None
                )
                audit_trace["matched_rules"] = matched_rule_ids

                applied_suppressions.append(
                    {
                        "finding_id": finding_id,
                        "suppression_id": active_sup.id,
                        "reference": active_sup.reference,
                        "owner": active_sup.owner,
                        "reason": active_sup.reason,
                        "expires_at": active_sup.expires_at.isoformat()
                        if active_sup.expires_at
                        else None,
                    }
                )

                evaluation = FindingEvaluation(
                    finding_id=finding_id,
                    component_name=match.component.name,
                    component_version=match.component.version or "",
                    ecosystem=str(
                        match.component.ecosystem.value
                        if hasattr(match.component.ecosystem, "value")
                        else match.component.ecosystem
                    ),
                    vulnerability_id=match.vulnerability.canonical_id,
                    action=PolicyAction.SUPPRESS,
                    status=PolicyStatus.SUPPRESSED,
                    matched_rules=matched_rule_ids,
                    matched_suppression_id=active_sup.id,
                    reason=reason,
                    is_violation=False,
                    requires_human_review=False,
                    audit_trace=audit_trace,
                )
                evaluations.append(evaluation)
                continue

            # If an expired suppression was matched, record it in audit trace
            expired_sups = [
                s for s in all_sups if s.status(self.clock) == SuppressionStatus.EXPIRED
            ]
            if expired_sups:
                audit_trace["suppression_warning"] = f"Suppression {expired_sups[0].id} is EXPIRED"
                audit_trace["expired_suppression_warning"] = (
                    f"Suppression {expired_sups[0].id} expired on {expired_sups[0].expires_at}. Finding evaluated under active rules."
                )

            # Step 2: Explicit Rules Evaluation
            matching_rules: list[PolicyRule] = []
            for rule in sorted_rules:
                if ConditionEvaluator.evaluate(rule.when, match):
                    matching_rules.append(rule)

            chosen_action: PolicyAction | None = None
            chosen_status: PolicyStatus | None = None
            rule_reason: str = ""
            matched_rule_ids = [r.id for r in matching_rules]

            if matching_rules:
                # Precedence among actions: BLOCK > REQUIRE_REVIEW > ACCEPT_RISK > ALLOW
                action_hierarchy = [
                    PolicyAction.BLOCK,
                    PolicyAction.REQUIRE_REVIEW,
                    PolicyAction.ACCEPT_RISK,
                    PolicyAction.ALLOW,
                ]
                for priority_action in action_hierarchy:
                    matched_with_action = [
                        r for r in matching_rules if r.action == priority_action
                    ]
                    if matched_with_action:
                        winning_rule = matched_with_action[0]
                        chosen_action = winning_rule.action
                        rule_reason = (
                            winning_rule.reason
                            or winning_rule.description
                            or f"Matched rule '{winning_rule.id}'"
                        )
                        break

                if chosen_action == PolicyAction.BLOCK:
                    chosen_status = PolicyStatus.VIOLATION
                elif chosen_action == PolicyAction.REQUIRE_REVIEW:
                    chosen_status = PolicyStatus.REQUIRES_REVIEW
                elif chosen_action == PolicyAction.ACCEPT_RISK:
                    chosen_status = PolicyStatus.ACCEPTED_RISK
                elif chosen_action == PolicyAction.ALLOW:
                    chosen_status = PolicyStatus.ALLOWED

            # Step 3: Thresholds Evaluation (if no explicit rule determined outcome)
            if chosen_action is None:
                risk_lvl = (
                    (getattr(match.risk_assessment, "risk_level", None) or "").upper().strip()
                )
                sev_lvl = (match.vulnerability.severity or "").upper().strip()
                threshold_fail_on = [t.upper().strip() for t in self.policy.thresholds.fail_on]

                if (risk_lvl and risk_lvl in threshold_fail_on) or (
                    sev_lvl and sev_lvl in threshold_fail_on
                ):
                    chosen_action = PolicyAction.BLOCK
                    chosen_status = PolicyStatus.VIOLATION
                    rule_reason = f"Security threshold violated: risk={risk_lvl or sev_lvl}"
                elif self.policy.thresholds.fail_on_review and (
                    getattr(match.risk_assessment, "requires_human_review", False)
                    or match.applicability == Applicability.REQUIRES_REVIEW
                ):
                    chosen_action = PolicyAction.REQUIRE_REVIEW
                    chosen_status = PolicyStatus.REQUIRES_REVIEW
                    rule_reason = "Security threshold violated: finding requires human review"

            # Step 4: Default Fallback Action
            if chosen_action is None:
                chosen_action = self.policy.default_action
                if chosen_action == PolicyAction.BLOCK:
                    chosen_status = PolicyStatus.VIOLATION
                    rule_reason = "Blocked by policy default action"
                elif chosen_action == PolicyAction.REQUIRE_REVIEW:
                    chosen_status = PolicyStatus.REQUIRES_REVIEW
                    rule_reason = "Requires review by policy default action"
                elif chosen_action == PolicyAction.ACCEPT_RISK:
                    chosen_status = PolicyStatus.ACCEPTED_RISK
                    rule_reason = "Accepted risk by policy default action"
                else:
                    chosen_action = PolicyAction.ALLOW
                    chosen_status = PolicyStatus.ALLOWED
                    rule_reason = "Allowed by policy default action"

            # Finalize counters and status
            is_violation = chosen_status == PolicyStatus.VIOLATION
            requires_review = chosen_status == PolicyStatus.REQUIRES_REVIEW

            if chosen_status == PolicyStatus.VIOLATION:
                violations_count += 1
            elif chosen_status == PolicyStatus.REQUIRES_REVIEW:
                requires_review_count += 1
            elif chosen_status == PolicyStatus.ACCEPTED_RISK:
                accepted_risk_count += 1
            elif chosen_status == PolicyStatus.ALLOWED:
                allowed_count += 1

            audit_trace["decision"] = chosen_status.value
            audit_trace["matched_rules"] = matched_rule_ids
            audit_trace["reason"] = rule_reason

            eval_item = FindingEvaluation(
                finding_id=finding_id,
                component_name=match.component.name,
                component_version=match.component.version or "",
                ecosystem=str(
                    match.component.ecosystem.value
                    if hasattr(match.component.ecosystem, "value")
                    else match.component.ecosystem
                ),
                vulnerability_id=match.vulnerability.canonical_id,
                action=chosen_action,
                status=chosen_status,
                matched_rules=matched_rule_ids,
                matched_suppression_id=None,
                reason=rule_reason,
                is_violation=is_violation,
                requires_human_review=requires_review,
                audit_trace=audit_trace,
            )
            evaluations.append(eval_item)
            if is_violation:
                violations.append(eval_item)

        # Deterministic sort of evaluations
        evaluations.sort(
            key=lambda e: (e.ecosystem, e.component_name, e.component_version, e.vulnerability_id)
        )
        violations.sort(
            key=lambda e: (e.ecosystem, e.component_name, e.component_version, e.vulnerability_id)
        )

        has_violations = violations_count > 0
        review_failed = bool(self.policy.thresholds.fail_on_review and requires_review_count > 0)
        ci_exit_code = 1 if (has_violations or review_failed) else 0

        duration = time.perf_counter() - t0

        return PolicyEvaluationResult(
            policy_id=self.policy.id,
            policy_name=self.policy.name,
            total_findings=len(matches),
            allowed_count=allowed_count,
            violations_count=violations_count,
            suppressed_count=suppressed_count,
            accepted_risk_count=accepted_risk_count,
            requires_review_count=requires_review_count,
            has_violations=has_violations,
            evaluations=evaluations,
            violations=violations,
            suppressions_applied=applied_suppressions,
            duration_seconds=round(duration, 5),
            ci_exit_code=ci_exit_code,
        )

    def evaluate_scan(
        self,
        scan_result: ScanResultSummary,
        scan_id: str | None = None,
        project_id: str | None = None,
    ) -> PolicyEvaluationResult:
        """Evaluate findings from a ScanResultSummary."""
        return self.evaluate(
            matches=scan_result.matches,
            project_id=project_id,
        )

    @classmethod
    def evaluate_summary(
        cls,
        summary: ScanResultSummary,
        policy: Policy,
        suppressions: list[Suppression] | None = None,
        clock: Clock | None = None,
        project_id: str | None = None,
    ) -> PolicyEvaluationResult:
        """Helper to evaluate directly from ScanResultSummary."""
        engine = cls(policy=policy, suppressions=suppressions, clock=clock)
        return engine.evaluate(summary.matches, project_id=project_id)
