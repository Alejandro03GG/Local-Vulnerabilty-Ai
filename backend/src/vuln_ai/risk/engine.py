"""Deterministic, explainable Risk Engine for Local Vulnerability AI."""

from __future__ import annotations

import logging
from datetime import UTC, datetime

from vuln_ai.ai.models import AIAnalysis, DecisionResult
from vuln_ai.core.models import MatchResult, VersionType
from vuln_ai.risk.models import RiskAssessment, RiskLevel, RiskStatus

logger = logging.getLogger(__name__)


def _utcnow() -> datetime:
    return datetime.now(UTC)


class DeterministicRiskEngine:
    """Evaluates scan findings, AI contextual narratives, and decision probabilities.

    Applies explicit deterministic rules. Does NOT rely on model hallucination,
    black-box voting, or unverified probability-to-exploit conversions.
    """

    def assess(
        self,
        match: MatchResult,
        ai_analysis: AIAnalysis | None = None,
        decision: DecisionResult | None = None,
    ) -> RiskAssessment:
        """Evaluate all available evidence for a single match and return an audit-ready assessment."""
        rules_triggered: list[str] = []
        rationales: list[str] = []

        # 1. Base deterministic match rule
        rules_triggered.append("MATCH_COMPONENT_ONLY")
        rationales.append(
            f"Component '{match.component.name}' matched catalog product "
            f"'{match.vulnerability.product}' with {match.match_confidence * 100:.0f}% confidence."
        )

        # 2. Version evidence check
        has_version = bool(match.component.version) and (
            match.component.version_type != VersionType.UNKNOWN
        )
        if not has_version:
            rules_triggered.append("NO_VERSION_EVIDENCE")
            rationales.append(
                "No exact version evidence detected in project manifests; applicability cannot be verified automatically."
            )
        else:
            rules_triggered.append("VERSION_DECLARED")
            rationales.append(f"Component declared with version '{match.component.version}'.")

        # 3. Catalog Threat Signals (e.g. Known Ransomware in CISA KEV)
        is_ransomware_threat = match.vulnerability.known_ransomware_use.lower() == "known"
        if is_ransomware_threat:
            rules_triggered.append("RANSOMWARE_CAMPAIGN_ASSOCIATED")
            rationales.append("Vulnerability has documented use in active ransomware campaigns.")

        # 4. Handle AI unavailable / disabled fallback scenario
        if ai_analysis is None and decision is None:
            rules_triggered.append("AI_UNAVAILABLE_FALLBACK")
            rationales.append(
                "AI analysis and decision layers are unavailable or disabled; falling back to conservative deterministic baseline."
            )

            status = RiskStatus.REQUIRES_REVIEW if not has_version else RiskStatus.DETECTED
            risk_level = RiskLevel.HIGH if is_ransomware_threat else RiskLevel.MEDIUM
            certainty = round(match.match_confidence * 0.5, 2)
            recommended_action = (
                f"Verify if version '{match.component.version or 'deployed'}' is vulnerable to "
                f"{match.vulnerability.cve_id} and consult vendor remediation: {match.vulnerability.required_action or 'Apply latest security patches.'}"
            )

            return RiskAssessment(
                status=status,
                risk_level=risk_level,
                certainty=certainty,
                rationale=" | ".join(rationales),
                recommended_action=recommended_action,
                requires_human_review=True,
                rule_ids=rules_triggered,
                assessed_at=_utcnow(),
            )

        # 5. Evaluate Decision Signals
        applicability_prob = decision.applicability_probability if decision else None
        urgency_score = decision.urgency_score if decision else None
        exposure_posture = (
            decision.responses.get("exposure") if decision and decision.responses else "unknown"
        )

        # 6. Check for Conflicting Signals
        conflicting_signals = False
        if (
            ai_analysis
            and decision
            and applicability_prob is not None
            and (
                (ai_analysis.requires_human_review and applicability_prob > 0.85)
                or (applicability_prob < 0.20 and match.match_confidence >= 0.95)
            )
        ):
            conflicting_signals = True

        if conflicting_signals:
            rules_triggered.append("CONFLICTING_SIGNALS")
            rationales.append(
                "Discrepancy detected between AI contextual evidence and decision probabilities."
            )

        # 7. Evaluate Applicability Rules
        if applicability_prob is not None:
            if applicability_prob >= 0.75:
                rules_triggered.append("AI_APPLICABILITY_HIGH")
                rationales.append(
                    f"Decision model indicates high probability ({applicability_prob:.2f}) of applicability."
                )
            elif applicability_prob <= 0.25:
                rules_triggered.append("AI_APPLICABILITY_LOW")
                rationales.append(
                    f"Decision model indicates low probability ({applicability_prob:.2f}) of applicability."
                )
            else:
                rules_triggered.append("AI_APPLICABILITY_MODERATE")
                rationales.append(
                    f"Decision model indicates moderate/uncertain probability ({applicability_prob:.2f})."
                )

        # 8. Evaluate Exposure Rules
        if str(exposure_posture).lower() == "direct":
            rules_triggered.append("EXPOSURE_DIRECT")
            rationales.append("Component is declared directly in root project manifest.")
        elif str(exposure_posture).lower() == "indirect":
            rules_triggered.append("EXPOSURE_INDIRECT")
            rationales.append("Component is identified as a secondary or indirect dependency.")
        else:
            rules_triggered.append("EXPOSURE_UNKNOWN")
            rationales.append("Component runtime exposure path is unconfirmed.")

        # 9. Evaluate Urgency
        if (urgency_score is not None and urgency_score >= 8.0) or is_ransomware_threat:
            rules_triggered.append("URGENCY_HIGH")
            rationales.append(
                f"High triage urgency flagged (score: {urgency_score or 'N/A'}, ransomware: {is_ransomware_threat})."
            )

        # 10. Synthesize Final Assessment Status, RiskLevel, and Certainty
        status: RiskStatus
        risk_level: RiskLevel
        requires_human_review: bool = True
        certainty: float

        if conflicting_signals or not has_version:
            status = RiskStatus.REQUIRES_REVIEW
            requires_human_review = True
            certainty = 0.45
            risk_level = RiskLevel.HIGH if is_ransomware_threat else RiskLevel.MEDIUM
        elif applicability_prob is not None and applicability_prob <= 0.25:
            status = RiskStatus.LIKELY_NOT_AFFECTED
            requires_human_review = False
            certainty = round(0.70 + (0.25 - applicability_prob), 2)
            risk_level = RiskLevel.LOW
        elif applicability_prob is not None and applicability_prob >= 0.75 and has_version:
            status = RiskStatus.LIKELY_AFFECTED
            requires_human_review = (
                True  # Always mandate human confirmation before deployment halts
            )
            certainty = round(0.60 + (applicability_prob * 0.3), 2)
            risk_level = (
                RiskLevel.CRITICAL
                if is_ransomware_threat or (urgency_score and urgency_score >= 8)
                else RiskLevel.HIGH
            )
        else:
            status = RiskStatus.DETECTED
            requires_human_review = True
            certainty = 0.50
            risk_level = RiskLevel.MEDIUM

        if ai_analysis and ai_analysis.requires_human_review:
            requires_human_review = True

        recommended_action = match.vulnerability.required_action or (
            f"Review {match.vulnerability.cve_id} applicability for '{match.component.name}' "
            f"and update to patched release."
        )

        return RiskAssessment(
            status=status,
            risk_level=risk_level,
            certainty=min(max(certainty, 0.0), 1.0),
            rationale=" | ".join(rationales),
            recommended_action=recommended_action,
            requires_human_review=requires_human_review,
            rule_ids=rules_triggered,
            assessed_at=_utcnow(),
        )
