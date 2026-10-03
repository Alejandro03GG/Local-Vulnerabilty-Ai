"""SARIF 2.1.0 exporter for Local Vulnerability AI.

Generates deterministic, compliant OASIS SARIF 2.1.0 documents.
"""

from __future__ import annotations

import json
from typing import Any

from vuln_ai.export.errors import ExportValidationError
from vuln_ai.export.models import ExportFinding, ExportScan, ExportVulnerability

SARIF_SCHEMA_URI = "https://json.schemastore.org/sarif-2.1.0.json"
SARIF_VERSION = "2.1.0"


def _map_risk_level_to_sarif_level(risk_level: str, fallback_severity: str = "UNKNOWN") -> str:
    """Map deterministic Risk Engine evaluation to SARIF result level.

    Mapping policy:
    - CRITICAL / HIGH -> "error"
    - MEDIUM          -> "warning"
    - LOW / INFO/NONE -> "note"
    - If risk is UNKNOWN, fallback to vulnerability severity.
    """
    rl = risk_level.upper().strip()
    if rl in ("CRITICAL", "HIGH"):
        return "error"
    if rl == "MEDIUM":
        return "warning"
    if rl in ("LOW", "INFO", "NONE"):
        return "note"

    sev = fallback_severity.upper().strip()
    if sev in ("CRITICAL", "HIGH"):
        return "error"
    if sev == "MEDIUM":
        return "warning"
    if sev in ("LOW", "INFO", "NONE"):
        return "note"

    return "warning"


def _build_sarif_rule(vuln: ExportVulnerability) -> dict[str, Any]:
    """Convert an ExportVulnerability to a SARIF reportingDescriptor (rule)."""
    rule_id = vuln.canonical_id
    safe_name = rule_id.replace("-", "_")

    short_desc = vuln.summary or f"Vulnerability {rule_id}"
    full_desc = vuln.description or short_desc

    help_lines = [
        f"**Vulnerability ID:** {rule_id}",
        f"**Severity:** {vuln.severity}",
    ]
    if vuln.cvss_score is not None:
        help_lines.append(f"**CVSS Score:** {vuln.cvss_score}")
    if vuln.has_kev:
        help_lines.append("**CISA KEV:** Confirmed exploited in the wild.")
    if vuln.source_name:
        help_lines.append(f"**Source:** {vuln.source_name}")
    if vuln.recommendation:
        help_lines.append(f"\n**Remediation:** {vuln.recommendation}")

    help_text = "\n".join(help_lines)

    properties: dict[str, Any] = {
        "severity": vuln.severity,
        "hasKev": vuln.has_kev,
        "aliases": vuln.aliases,
    }
    if vuln.cvss_score is not None:
        properties["cvssScore"] = vuln.cvss_score
        # security-severity property for GitHub Code Scanning (0.0 to 10.0 scale)
        properties["security-severity"] = f"{vuln.cvss_score:.1f}"
    if vuln.cvss_vector:
        properties["cvssVector"] = vuln.cvss_vector
    if vuln.cwe_ids:
        properties["cwe"] = vuln.cwe_ids
    if vuln.source_name:
        properties["sourceName"] = vuln.source_name

    rule: dict[str, Any] = {
        "id": rule_id,
        "name": safe_name,
        "shortDescription": {"text": short_desc},
        "fullDescription": {"text": full_desc},
        "help": {
            "text": help_text,
            "markdown": help_text,
        },
        "properties": properties,
    }
    return rule


def _build_sarif_result(
    finding: ExportFinding, vuln: ExportVulnerability | None
) -> dict[str, Any]:
    """Convert an ExportFinding into a SARIF result item."""
    fallback_sev = vuln.severity if vuln else "UNKNOWN"
    level = _map_risk_level_to_sarif_level(finding.risk_level, fallback_sev)

    message_text = (
        f"Component '{finding.component_name}' "
        f"(version: {finding.component_version or 'unknown'}) is affected by {finding.rule_id}."
    )

    # Locations: use honest relative path or source file if known
    locations: list[dict[str, Any]] = []
    location_path = (
        finding.container_path
        or finding.lockfile_source
        or finding.manifest_source
        or finding.source_file
    )
    if location_path:
        # Standard relative path without fabricated line or column numbers
        clean_uri = location_path.replace("\\", "/")
        locations.append(
            {
                "physicalLocation": {
                    "artifactLocation": {
                        "uri": clean_uri,
                        "uriBaseId": "%SRCROOT%",
                    }
                }
            }
        )

    # Properties preserving Local Vulnerability AI domain intelligence
    props: dict[str, Any] = {
        "componentName": finding.component_name,
        "componentVersion": finding.component_version,
        "ecosystem": finding.ecosystem,
        "dependencyType": finding.dependency_type,
        "sourceFile": finding.source_file,
        "applicability": finding.applicability,
        "riskLevel": finding.risk_level,
        "requiresHumanReview": finding.requires_human_review,
        "confidence": finding.confidence,
    }
    if finding.container_image:
        props["containerImage"] = finding.container_image
    if finding.container_digest:
        props["containerDigest"] = finding.container_digest
    if finding.container_layer:
        props["containerLayer"] = finding.container_layer
    if finding.container_path:
        props["containerPath"] = finding.container_path
    if finding.package_manager:
        props["packageManager"] = finding.package_manager
    if finding.risk_score is not None:
        props["riskScore"] = finding.risk_score
    if finding.lockfile_source:
        props["lockfileSource"] = finding.lockfile_source
    if finding.manifest_source:
        props["manifestSource"] = finding.manifest_source
    if finding.dependency_path:
        props["dependencyPath"] = finding.dependency_path
    if finding.evidence:
        props["evidence"] = finding.evidence
    if finding.conflicts:
        props["sourceConflicts"] = finding.conflicts
    if finding.conflict_summary:
        props["conflictSummary"] = finding.conflict_summary

    if finding.policy_status:
        props["policyStatus"] = finding.policy_status
        props["policyRuleIds"] = finding.policy_rule_ids
        props["policyViolation"] = finding.is_policy_violation
        if finding.suppression_id:
            props["suppressionId"] = finding.suppression_id
        if finding.suppression_reason:
            props["suppressionReason"] = finding.suppression_reason
        if finding.suppression_expires_at:
            props["suppressionExpiresAt"] = finding.suppression_expires_at

    result: dict[str, Any] = {
        "ruleId": finding.rule_id,
        "level": level,
        "message": {"text": message_text},
        "locations": locations,
        "properties": props,
    }

    if finding.policy_status == "SUPPRESSED":
        sup_entry: dict[str, Any] = {
            "kind": "external",
            "status": "accepted",
        }
        if finding.suppression_reason:
            sup_entry["justification"] = finding.suppression_reason
        result["suppressions"] = [sup_entry]

    return result


def validate_sarif_dict(doc: dict[str, Any]) -> None:
    """Validate that dictionary conforms to core SARIF 2.1.0 structure."""
    if not isinstance(doc, dict):
        raise ExportValidationError("SARIF root must be a dictionary")
    if doc.get("version") != SARIF_VERSION:
        raise ExportValidationError(
            f"Expected SARIF version '{SARIF_VERSION}', got '{doc.get('version')}'"
        )
    if doc.get("$schema") != SARIF_SCHEMA_URI:
        raise ExportValidationError(f"Expected SARIF $schema '{SARIF_SCHEMA_URI}'")

    runs = doc.get("runs")
    if not isinstance(runs, list):
        raise ExportValidationError("SARIF 'runs' field must be a list")

    for run in runs:
        if not isinstance(run, dict):
            raise ExportValidationError("Each SARIF run must be a dictionary")
        tool = run.get("tool")
        if not isinstance(tool, dict) or "driver" not in tool:
            raise ExportValidationError("SARIF run must contain 'tool.driver'")
        driver = tool["driver"]
        if not driver.get("name"):
            raise ExportValidationError("SARIF tool.driver must have a 'name'")
        if not driver.get("version"):
            raise ExportValidationError("SARIF tool.driver must have a 'version'")

        results = run.get("results")
        if not isinstance(results, list):
            raise ExportValidationError("SARIF run 'results' must be a list")
        for res in results:
            if "ruleId" not in res:
                raise ExportValidationError("Each SARIF result must have a 'ruleId'")
            if res.get("level") not in ("error", "warning", "note", "none"):
                raise ExportValidationError(f"Invalid SARIF result level '{res.get('level')}'")
            if not isinstance(res.get("message"), dict) or "text" not in res["message"]:
                raise ExportValidationError("SARIF result must contain message.text")


def export_sarif_dict(scan: ExportScan) -> dict[str, Any]:
    """Generate SARIF 2.1.0 dictionary representation from canonical ExportScan."""
    vuln_by_id = {v.canonical_id: v for v in scan.vulnerabilities}

    # Generate rules sorted deterministically by ID
    rules: list[dict[str, Any]] = []
    for vuln in sorted(scan.vulnerabilities, key=lambda x: x.canonical_id):
        rules.append(_build_sarif_rule(vuln))

    # Generate results sorted deterministically
    results: list[dict[str, Any]] = []
    for finding in sorted(
        scan.findings,
        key=lambda x: (
            x.rule_id,
            x.component_name.lower(),
            x.component_version or "",
            x.source_file,
        ),
    ):
        vuln = vuln_by_id.get(finding.rule_id)
        results.append(_build_sarif_result(finding, vuln))

    sarif_doc: dict[str, Any] = {
        "$schema": SARIF_SCHEMA_URI,
        "version": SARIF_VERSION,
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": scan.tool_name,
                        "version": scan.tool_version,
                        "informationUri": scan.tool_uri,
                        "rules": rules,
                    }
                },
                "results": results,
            }
        ],
    }

    validate_sarif_dict(sarif_doc)
    return sarif_doc


def export_sarif_json(scan: ExportScan, indent: int = 2) -> str:
    """Generate pretty-printed SARIF 2.1.0 JSON text."""
    doc = export_sarif_dict(scan)
    return json.dumps(doc, indent=indent, ensure_ascii=False)
