"""Machine-readable JSON serialization for CLI outputs."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from vuln_ai.core.models import ScanResultSummary
from vuln_ai.risk.models import RiskLevel


def format_scan_summary_dict(
    summary: ScanResultSummary,
    policy_evaluation: Any = None,
) -> dict[str, Any]:
    """Convert ScanResultSummary into clean JSON-serializable dictionary."""
    risk_counts = {level.value: 0 for level in RiskLevel}
    requires_review_count = 0

    eval_lookup: dict[tuple[str, str, str], dict[str, Any]] = {}
    policy_eval_dict: dict[str, Any] | None = None
    if policy_evaluation:
        if hasattr(policy_evaluation, "model_dump"):
            policy_eval_dict = policy_evaluation.model_dump()
        elif hasattr(policy_evaluation, "to_dict"):
            policy_eval_dict = policy_evaluation.to_dict()
        elif isinstance(policy_evaluation, dict):
            policy_eval_dict = policy_evaluation

        evals = getattr(policy_evaluation, "evaluations", None) or (
            policy_eval_dict.get("evaluations", []) if policy_eval_dict else []
        )
        for ev in evals:
            c_name = str(
                getattr(ev, "component_name", "")
                or (ev.get("component_name") if isinstance(ev, dict) else "")
            ).lower()
            c_ver = str(
                getattr(ev, "component_version", "")
                or (ev.get("component_version") if isinstance(ev, dict) else "")
                or ""
            )
            v_id = str(
                getattr(ev, "vulnerability_id", "")
                or (ev.get("vulnerability_id") if isinstance(ev, dict) else "")
            )
            st = str(getattr(ev, "status", "") if hasattr(ev, "status") else ev.get("status", ""))
            eval_lookup[(c_name, c_ver, v_id)] = {
                "status": st,
                "is_violation": getattr(ev, "is_violation", False)
                if hasattr(ev, "is_violation")
                else ev.get("is_violation", False),
                "matched_suppression_id": getattr(ev, "matched_suppression_id", None)
                if hasattr(ev, "matched_suppression_id")
                else ev.get("matched_suppression_id"),
                "reason": getattr(ev, "reason", "")
                if hasattr(ev, "reason")
                else ev.get("reason", ""),
            }

    matches_payload = []
    for match in summary.matches:
        risk_lvl = "unknown"
        requires_review = False
        rule_ids = []
        rationale = ""
        action = ""

        if match.risk_assessment:
            risk_lvl = getattr(match.risk_assessment, "risk_level", "unknown")
            if hasattr(risk_lvl, "value"):
                risk_lvl = risk_lvl.value
            requires_review = getattr(match.risk_assessment, "requires_human_review", False)
            rule_ids = getattr(match.risk_assessment, "rule_ids", [])
            rationale = getattr(match.risk_assessment, "rationale", "")
            action = getattr(match.risk_assessment, "recommended_action", "")

        if requires_review or match.applicability.value == "requires_review":
            requires_review_count += 1

        if risk_lvl in risk_counts:
            risk_counts[risk_lvl] += 1
        else:
            risk_counts["unknown"] += 1

        # Format conflicts
        conflicts_data = []
        if getattr(match, "conflicts", None):
            for c in match.conflicts:
                conflicts_data.append(
                    {
                        "conflict_type": getattr(c, "conflict_type", str(c)),
                        "description": getattr(c, "description", ""),
                        "divergent_sources": getattr(c, "divergent_sources", []),
                    }
                )

        match_item: dict[str, Any] = {
            "component": {
                "name": match.component.name,
                "version": match.component.version,
                "ecosystem": match.component.ecosystem.value
                if hasattr(match.component.ecosystem, "value")
                else str(match.component.ecosystem),
                "file_path": getattr(match.component, "source_file", None),
                "is_direct": getattr(match.component, "is_direct", True),
                "dependency_type": str(getattr(match.component, "dependency_type", "direct")),
                "scope": str(getattr(match.component, "scope", "runtime")),
                "manifest_source": getattr(match.component, "manifest_source", None),
                "lockfile_source": getattr(match.component, "lockfile_source", None),
                "parent_name": getattr(match.component, "parent_name", None),
                "dependency_path": getattr(match.component, "dependency_path", []),
            },
            "vulnerability": {
                "id": match.vulnerability.canonical_id or match.vulnerability.cve_id,
                "cve_id": match.vulnerability.cve_id,
                "severity": match.vulnerability.severity,
                "cvss_score": match.vulnerability.cvss_score,
                "source": match.vulnerability.source_name,
                "has_kev_evidence": getattr(match.vulnerability, "has_kev_evidence", False),
            },
            "applicability": match.applicability.value,
            "risk_level": risk_lvl,
            "requires_human_review": requires_review,
            "rule_ids": rule_ids,
            "rationale": rationale,
            "recommended_action": action,
            "has_conflicts": bool(conflicts_data),
            "conflicts": conflicts_data,
        }

        v_id = match.vulnerability.canonical_id or match.vulnerability.cve_id or ""
        m_pol = eval_lookup.get(
            (match.component.name.lower(), match.component.version or "", v_id)
        )
        if m_pol:
            match_item["policy_status"] = m_pol.get("status")
            match_item["is_policy_violation"] = m_pol.get("is_violation", False)
            match_item["suppression_id"] = m_pol.get("matched_suppression_id")
            match_item["policy_reason"] = m_pol.get("reason")

        matches_payload.append(match_item)

    payload: dict[str, Any] = {
        "project_name": summary.project_name,
        "project_path": summary.project_path,
        "scan_status": summary.scan_status.value,
        "duration_seconds": round(summary.duration_seconds, 3),
        "error": summary.error,
        "summary": {
            "components_found": summary.components_found,
            "direct_components": summary.direct_components_count,
            "transitive_components": summary.transitive_components_count,
            "dependency_edges": summary.dependency_edges_count,
            "lockfiles_detected": summary.lockfiles_detected,
            "vulnerabilities_checked": summary.vulnerabilities_checked,
            "matches_found": summary.matches_found,
            "kev_matches": summary.kev_matches,
            "requires_review_count": requires_review_count,
            "risk_counts": risk_counts,
        },
        "matches": matches_payload,
    }

    if policy_eval_dict:
        payload["policy"] = {
            "id": policy_eval_dict.get("policy_id"),
            "name": policy_eval_dict.get("policy_name"),
        }
        payload["policyEvaluation"] = policy_eval_dict
        payload["violations"] = policy_eval_dict.get("violations", [])
        payload["suppressions"] = policy_eval_dict.get("applied_suppressions", [])

    return payload


def output_json_payload(
    data: dict[str, Any] | list[Any], output_file: str | Path | None = None
) -> str:
    """Serialize dictionary to formatted JSON string and optionally write to output file."""
    json_text = json.dumps(data, indent=2, default=str)
    if output_file:
        path = Path(output_file).resolve()
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json_text + "\n", encoding="utf-8")
    return json_text
