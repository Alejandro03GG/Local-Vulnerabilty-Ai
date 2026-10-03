"""Deterministic, explainable Risk Engine for Local Vulnerability AI."""

from __future__ import annotations

import logging
from datetime import UTC, datetime

from vuln_ai.ai.models import AIAnalysis, DecisionResult
from vuln_ai.core.models import Applicability, MatchResult, VersionType
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

        # Check KEV confirmation across vulnerability record and structured evidences
        is_kev = (
            getattr(match.vulnerability, "has_kev_evidence", False)
            or match.vulnerability.source_name == "CISA KEV"
            or any(
                getattr(ev, "source_name", "") == "CISA KEV"
                or getattr(ev, "evidence_type", "") == "kev_exploited"
                for ev in getattr(match, "structured_evidences", [])
            )
        )
        if is_kev:
            rules_triggered.append("KEV_CONFIRMED")
            rationales.append(
                "Vulnerability is cataloged in CISA Known Exploited Vulnerabilities (KEV)."
            )

        # 4. CVSS & Severity Threat Signals
        cvss = match.vulnerability.cvss_score
        severity = (match.vulnerability.severity or "").lower()
        if cvss is not None:
            if cvss >= 9.0:
                rules_triggered.append("CVSS_CRITICAL")
            elif cvss >= 7.0:
                rules_triggered.append("CVSS_HIGH")
            elif cvss >= 4.0:
                rules_triggered.append("CVSS_MEDIUM")
            else:
                rules_triggered.append("CVSS_LOW")
            rationales.append(f"CVSS score is {cvss:.1f}.")
        elif severity:
            if severity == "critical":
                rules_triggered.append("CVSS_CRITICAL")
            elif severity == "high":
                rules_triggered.append("CVSS_HIGH")
            elif severity == "medium":
                rules_triggered.append("CVSS_MEDIUM")

        # 5. Evaluate Decision Signals
        applicability_prob = decision.applicability_probability if decision else None
        urgency_score = decision.urgency_score if decision else None
        exposure_posture = (
            decision.responses.get("exposure") if decision and decision.responses else "unknown"
        )

        # 6. Fallback rule tracking
        if ai_analysis is None:
            rules_triggered.append("AI_UNAVAILABLE_FALLBACK")
            rationales.append(
                "AI contextual analysis layer is unavailable or disabled; using deterministic evidence."
            )
        if decision is None:
            rules_triggered.append("SYSTEMONE_UNAVAILABLE_FALLBACK")
            rationales.append(
                "SystemOne decision layer is unavailable or disabled; using deterministic evidence."
            )

        # 7. Check for Conflicting Signals between AI analysis and Decision
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
            rules_triggered.append("CONFLICTING_SIGNALS")
            rationales.append(
                "Discrepancy detected between AI contextual evidence and decision probabilities."
            )

        # 8. Evaluate Decision Applicability Rules (when decision is present)
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

        # 9. Evaluate Exposure Rules
        if str(exposure_posture).lower() == "direct":
            rules_triggered.append("EXPOSURE_DIRECT")
            rationales.append("Component is declared directly in root project manifest.")
        elif str(exposure_posture).lower() == "indirect":
            rules_triggered.append("EXPOSURE_INDIRECT")
            rationales.append("Component is identified as a secondary or indirect dependency.")
        elif decision is not None:
            rules_triggered.append("EXPOSURE_UNKNOWN")
            rationales.append("Component runtime exposure path is unconfirmed.")

        # 10. Evaluate Urgency
        if urgency_score is not None and urgency_score >= 8.0:
            rules_triggered.append("URGENCY_HIGH")
            rationales.append(
                f"High triage urgency flagged by decision layer (score: {urgency_score:.1f})."
            )
        elif is_ransomware_threat or is_kev:
            rules_triggered.append("URGENCY_HIGH")
            rationales.append(
                "High triage urgency flagged due to active exploitation / ransomware weaponization."
            )

        # 11. Synthesize Final Assessment Status, RiskLevel, and Certainty
        # Principle: Deterministic matcher applicability is authoritative over version ranges.
        status: RiskStatus
        risk_level: RiskLevel
        requires_human_review: bool = True
        certainty: float

        # Multi-source conflict check (Stage 9)
        has_source_conflict = match.applicability == Applicability.REQUIRES_REVIEW or any(
            str(getattr(c, "conflict_type", "")).lower() == "applicability"
            for c in getattr(match, "conflicts", [])
        )

        if has_source_conflict:
            rules_triggered.append("SOURCE_APPLICABILITY_CONFLICT")
            rationales.append(
                "Multi-source intelligence detected conflicting version range applicability between sources; human review is required."
            )
            status = RiskStatus.REQUIRES_REVIEW
            requires_human_review = True
            certainty = 0.50
            risk_level = (
                RiskLevel.HIGH
                if (is_ransomware_threat or is_kev or (cvss and cvss >= 7.0))
                else RiskLevel.MEDIUM
            )

        # Case 1: Missing or unparseable version evidence
        elif not has_version:
            status = RiskStatus.REQUIRES_REVIEW
            requires_human_review = True
            certainty = 0.40
            risk_level = (
                RiskLevel.HIGH
                if (is_ransomware_threat or is_kev or (cvss and cvss >= 7.0))
                else RiskLevel.MEDIUM
            )

        # Case 2: Range-confirmed non-applicability (installed version outside affected range)
        elif match.applicability == Applicability.LIKELY_NOT_AFFECTED:
            rules_triggered.append("APPLICABILITY_LIKELY_NOT_AFFECTED")
            rationales.append(
                "Version-aware matching confirmed component version is OUTSIDE affected range."
            )
            status = RiskStatus.LIKELY_NOT_AFFECTED
            requires_human_review = False
            certainty = 0.90
            risk_level = RiskLevel.LOW

        # Case 3: Range-confirmed applicability (installed version within affected range)
        elif match.applicability == Applicability.LIKELY_AFFECTED:
            rules_triggered.append("APPLICABILITY_LIKELY_AFFECTED")
            rationales.append(
                "Version-aware matching confirmed component version is WITHIN affected range."
            )
            status = RiskStatus.LIKELY_AFFECTED
            requires_human_review = True
            certainty = 0.85
            if (
                is_ransomware_threat
                or is_kev
                or (cvss is not None and cvss >= 9.0)
                or (urgency_score is not None and urgency_score >= 8.0)
            ):
                risk_level = RiskLevel.CRITICAL
            elif (cvss is not None and cvss >= 7.0) or severity == "high":
                risk_level = RiskLevel.HIGH
            elif (cvss is not None and cvss >= 4.0) or severity == "medium":
                risk_level = RiskLevel.MEDIUM
            else:
                risk_level = RiskLevel.LOW

        # Case 4: Conflicting AI/decision signals
        elif conflicting_signals:
            status = RiskStatus.REQUIRES_REVIEW
            requires_human_review = True
            certainty = 0.45
            risk_level = RiskLevel.HIGH if (is_ransomware_threat or is_kev) else RiskLevel.MEDIUM

        # Case 5: Name-only match with probabilistic decision available
        elif applicability_prob is not None and applicability_prob <= 0.25:
            status = RiskStatus.LIKELY_NOT_AFFECTED
            requires_human_review = False
            certainty = round(0.70 + (0.25 - applicability_prob), 2)
            risk_level = RiskLevel.LOW

        elif applicability_prob is not None and applicability_prob >= 0.75 and has_version:
            status = RiskStatus.LIKELY_AFFECTED
            requires_human_review = True
            certainty = round(0.60 + (applicability_prob * 0.3), 2)
            risk_level = (
                RiskLevel.CRITICAL
                if is_ransomware_threat or is_kev or (urgency_score and urgency_score >= 8)
                else RiskLevel.HIGH
            )

        # Case 6: Name-only match (DETECTED) without high-confidence probabilistic signals
        else:
            rules_triggered.append("APPLICABILITY_DETECTED")
            rationales.append(
                "Component name matched vulnerability catalog, but version-level range is unavailable."
            )
            status = RiskStatus.DETECTED
            requires_human_review = True
            certainty = 0.50
            risk_level = RiskLevel.HIGH if is_ransomware_threat else RiskLevel.MEDIUM

        if ai_analysis and ai_analysis.requires_human_review:
            requires_human_review = True

        vuln_ident = (
            match.vulnerability.canonical_id or match.vulnerability.cve_id or "vulnerability"
        )
        recommended_action = match.vulnerability.required_action or (
            f"Review {vuln_ident} applicability for '{match.component.name}' "
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
