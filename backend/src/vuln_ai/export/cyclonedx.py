"""CycloneDX 1.5 JSON SBOM exporter for Local Vulnerability AI.

Generates deterministic, compliant CycloneDX 1.5 SBOM documents with
PURL identification, dependency graph topology, and vulnerability findings.
"""

from __future__ import annotations

import json
import uuid
from typing import Any

from vuln_ai.export.errors import ExportValidationError
from vuln_ai.export.models import ExportFinding, ExportScan, ExportVulnerability

CYCLONEDX_SPEC_VERSION = "1.5"
CYCLONEDX_BOM_FORMAT = "CycloneDX"
CYCLONEDX_SCHEMA = "http://cyclonedx.org/schema/bom-1.5.schema.json"


def _map_applicability_to_cdx_state(applicability: str) -> str:
    """Map canonical applicability state to CycloneDX 1.5 vulnerability analysis state."""
    app = applicability.upper().strip()
    if app == "LIKELY_AFFECTED":
        return "exploitable"
    if app == "LIKELY_NOT_AFFECTED":
        return "not_affected"
    if app in ("REQUIRES_REVIEW", "UNKNOWN", "DETECTED"):
        return "in_triage"
    if app == "NOT_APPLICABLE":
        return "false_positive"
    return "in_triage"


def _map_severity_to_cdx(severity: str) -> str:
    """Map canonical severity to CycloneDX severity value."""
    sev = severity.lower().strip()
    if sev in ("critical", "high", "medium", "low", "info", "none"):
        return sev
    return "unknown"


def validate_cyclonedx_dict(doc: dict[str, Any]) -> None:
    """Validate that dictionary conforms to CycloneDX 1.5 JSON core structure."""
    if not isinstance(doc, dict):
        raise ExportValidationError("CycloneDX root must be a dictionary")
    if doc.get("bomFormat") != CYCLONEDX_BOM_FORMAT:
        raise ExportValidationError(
            f"Expected bomFormat '{CYCLONEDX_BOM_FORMAT}', got '{doc.get('bomFormat')}'"
        )
    if doc.get("specVersion") != CYCLONEDX_SPEC_VERSION:
        raise ExportValidationError(
            f"Expected specVersion '{CYCLONEDX_SPEC_VERSION}', got '{doc.get('specVersion')}'"
        )
    if not doc.get("serialNumber") or not str(doc["serialNumber"]).startswith("urn:uuid:"):
        raise ExportValidationError("CycloneDX serialNumber must be a valid urn:uuid URI")

    metadata = doc.get("metadata")
    if not isinstance(metadata, dict):
        raise ExportValidationError("CycloneDX 'metadata' must be a dictionary")
    if not metadata.get("timestamp"):
        raise ExportValidationError("CycloneDX metadata must include a timestamp")
    if not metadata.get("tools") or not isinstance(metadata["tools"], list):
        raise ExportValidationError("CycloneDX metadata must include a tools list")

    components = doc.get("components")
    if not isinstance(components, list):
        raise ExportValidationError("CycloneDX 'components' must be a list")
    for comp in components:
        if not comp.get("name"):
            raise ExportValidationError("Each CycloneDX component must have a 'name'")
        if not comp.get("type"):
            raise ExportValidationError("Each CycloneDX component must have a 'type'")
        if not comp.get("bom-ref"):
            raise ExportValidationError("Each CycloneDX component must have a 'bom-ref'")

    dependencies = doc.get("dependencies")
    if not isinstance(dependencies, list):
        raise ExportValidationError("CycloneDX 'dependencies' must be a list")
    for dep in dependencies:
        if "ref" not in dep or not isinstance(dep.get("dependsOn"), list):
            raise ExportValidationError(
                "CycloneDX dependency item must contain 'ref' and 'dependsOn'"
            )


def export_cyclonedx_dict(scan: ExportScan) -> dict[str, Any]:
    """Generate CycloneDX 1.5 dictionary representation from canonical ExportScan."""
    # Deterministic UUIDv5 based on project name and scan id
    namespace = uuid.UUID("6ba7b810-9dad-11d1-80b4-00c04fd430c8")
    doc_uuid = uuid.uuid5(namespace, f"cyclonedx:{scan.project_name}:{scan.scan_id}")
    serial_number = f"urn:uuid:{doc_uuid}"

    root_bom_ref = "pkg:root/project"

    # 1. Metadata
    metadata: dict[str, Any] = {
        "timestamp": scan.generated_at,
        "tools": [
            {
                "vendor": scan.tool_name,
                "name": scan.tool_name,
                "version": scan.tool_version,
            }
        ],
        "component": {
            "bom-ref": root_bom_ref,
            "type": "container" if scan.metadata.get("container_image") else "application",
            "name": scan.project_name.removeprefix("container:"),
        },
    }
    if scan.metadata.get("container_digest"):
        metadata["component"]["version"] = scan.metadata["container_digest"]

    # 2. Components
    cdx_components: list[dict[str, Any]] = []
    for c in sorted(
        scan.components,
        key=lambda x: (x.ecosystem.lower(), x.name.lower(), x.version or ""),
    ):
        comp_item: dict[str, Any] = {
            "bom-ref": c.bom_ref,
            "type": "operating-system" if c.ecosystem in ("deb", "apk", "rpm") else "library",
            "name": c.name,
        }
        if c.version:
            comp_item["version"] = c.version
        if c.purl:
            comp_item["purl"] = c.purl

        # Scope
        comp_item["scope"] = "required" if c.scope == "runtime" else "optional"

        # Provenance properties
        props: list[dict[str, str]] = [
            {"name": "vuln_ai:dependency_type", "value": c.dependency_type},
            {"name": "vuln_ai:source_file", "value": c.source_file},
        ]
        if c.container_layer:
            props.append({"name": "vuln_ai:container_layer", "value": c.container_layer})
        if c.container_path:
            props.append({"name": "vuln_ai:container_path", "value": c.container_path})
        if c.package_manager:
            props.append({"name": "vuln_ai:package_manager", "value": c.package_manager})
        if c.lockfile_source:
            props.append({"name": "vuln_ai:lockfile_source", "value": c.lockfile_source})
        if c.manifest_source:
            props.append({"name": "vuln_ai:manifest_source", "value": c.manifest_source})
        if c.dependency_path:
            props.append(
                {"name": "vuln_ai:dependency_path", "value": " -> ".join(c.dependency_path)}
            )

        comp_item["properties"] = props
        cdx_components.append(comp_item)

    # 3. Dependencies
    # Aggregate children by parent_ref
    deps_by_parent: dict[str, set[str]] = {}
    direct_bom_refs: set[str] = set()

    for c in scan.components:
        if c.is_direct:
            direct_bom_refs.add(c.bom_ref)

    deps_by_parent[root_bom_ref] = direct_bom_refs

    for d in scan.dependencies:
        if d.parent_ref not in deps_by_parent:
            deps_by_parent[d.parent_ref] = set()
        deps_by_parent[d.parent_ref].add(d.child_ref)

    cdx_dependencies: list[dict[str, Any]] = []
    for parent_ref in sorted(deps_by_parent.keys()):
        children = sorted(deps_by_parent[parent_ref])
        cdx_dependencies.append(
            {
                "ref": parent_ref,
                "dependsOn": children,
            }
        )

    # 4. Vulnerabilities
    vuln_by_id = {v.canonical_id: v for v in scan.vulnerabilities}
    cdx_vulnerabilities: list[dict[str, Any]] = []

    # Map findings by rule_id to collect affected components
    findings_by_rule: dict[str, list[ExportFinding]] = {}
    for f in scan.findings:
        findings_by_rule.setdefault(f.rule_id, []).append(f)

    for rule_id in sorted(findings_by_rule.keys()):
        vuln: ExportVulnerability | None = vuln_by_id.get(rule_id)
        rule_findings = findings_by_rule[rule_id]

        source_dict: dict[str, Any] = {
            "name": vuln.source_name if vuln and vuln.source_name else "Local Vulnerability AI"
        }
        if vuln and vuln.source_url:
            source_dict["url"] = vuln.source_url

        ratings: list[dict[str, Any]] = []
        if vuln:
            rating_item: dict[str, Any] = {
                "source": {"name": vuln.source_name or "Local Vulnerability AI"},
                "severity": _map_severity_to_cdx(vuln.severity),
            }
            if vuln.cvss_score is not None:
                rating_item["score"] = vuln.cvss_score
                rating_item["method"] = "CVSSv31"
            if vuln.cvss_vector:
                rating_item["vector"] = vuln.cvss_vector
            ratings.append(rating_item)

        affects: list[dict[str, str]] = []
        analyses: list[dict[str, Any]] = []
        for rf in rule_findings:
            affects.append({"ref": rf.component_ref})
            analyses.append(
                {
                    "state": _map_applicability_to_cdx_state(rf.applicability),
                    "detail": rf.conflict_summary
                    or f"Applicability: {rf.applicability}; Risk: {rf.risk_level}",
                }
            )

        vuln_obj: dict[str, Any] = {
            "bom-ref": f"vuln-{rule_id}",
            "id": rule_id,
            "source": source_dict,
            "ratings": ratings,
            "description": vuln.summary or vuln.description
            if vuln
            else f"Vulnerability {rule_id}",
            "affects": affects,
        }
        if analyses:
            # Use most severe / prioritized analysis
            vuln_obj["analysis"] = analyses[0]

        if vuln and vuln.recommendation:
            vuln_obj["recommendation"] = vuln.recommendation

        vuln_props: list[dict[str, str]] = []
        for rf in rule_findings:
            if rf.policy_status:
                vuln_props.append({"name": "vuln_ai:policy_status", "value": rf.policy_status})
                vuln_props.append(
                    {
                        "name": "vuln_ai:is_policy_violation",
                        "value": str(rf.is_policy_violation).lower(),
                    }
                )
                if rf.policy_rule_ids:
                    vuln_props.append(
                        {"name": "vuln_ai:policy_rules", "value": ",".join(rf.policy_rule_ids)}
                    )
                if rf.suppression_id:
                    vuln_props.append(
                        {"name": "vuln_ai:suppression_id", "value": rf.suppression_id}
                    )
                if rf.suppression_reason:
                    vuln_props.append(
                        {"name": "vuln_ai:suppression_reason", "value": rf.suppression_reason}
                    )
                if rf.suppression_expires_at:
                    vuln_props.append(
                        {
                            "name": "vuln_ai:suppression_expires_at",
                            "value": rf.suppression_expires_at,
                        }
                    )
                break
        if vuln_props:
            vuln_obj["properties"] = vuln_props

        cdx_vulnerabilities.append(vuln_obj)

    doc: dict[str, Any] = {
        "$schema": CYCLONEDX_SCHEMA,
        "bomFormat": CYCLONEDX_BOM_FORMAT,
        "specVersion": CYCLONEDX_SPEC_VERSION,
        "serialNumber": serial_number,
        "version": 1,
        "metadata": metadata,
        "components": cdx_components,
        "dependencies": cdx_dependencies,
    }
    if cdx_vulnerabilities:
        doc["vulnerabilities"] = cdx_vulnerabilities

    validate_cyclonedx_dict(doc)
    return doc


def export_cyclonedx_json(scan: ExportScan, indent: int = 2) -> str:
    """Generate pretty-printed CycloneDX 1.5 JSON text."""
    doc = export_cyclonedx_dict(scan)
    return json.dumps(doc, indent=indent, ensure_ascii=False)
