"""Canonical export models for Local Vulnerability AI.

Provides an intermediate, deterministic representation (ExportScan)
decoupled from specific export formats (SARIF, CycloneDX, SPDX).
"""

from __future__ import annotations

import datetime
import enum
import re
from typing import Any

from pydantic import BaseModel, Field

import vuln_ai
from vuln_ai.core.graph import DependencyGraph, DependencyType
from vuln_ai.core.models import (
    Ecosystem,
    ScanResultSummary,
    normalize_component_name,
)


class ExportFormat(enum.StrEnum):
    """Supported export formats."""

    SARIF = "sarif"
    CYCLONEDX = "cyclonedx"
    SPDX = "spdx"


def sanitize_spdx_id(raw_str: str) -> str:
    """Sanitize string to form a valid SPDX ID conforming to ^[a-zA-Z0-9.-]+$."""
    sanitized = re.sub(r"[^a-zA-Z0-9.-]", "-", raw_str)
    sanitized = re.sub(r"-+", "-", sanitized).strip("-.")
    if not sanitized:
        sanitized = "unknown"
    return f"SPDXRef-{sanitized}"


def generate_purl(ecosystem: str | Ecosystem, name: str, version: str | None) -> str | None:
    """Generate canonical Package URL (purl) according to package-url specification."""
    if not version:
        return None

    eco_str = (
        (ecosystem.value if isinstance(ecosystem, Ecosystem) else str(ecosystem)).lower().strip()
    )
    ver_str = version.strip()
    norm_name = name.strip()

    if eco_str in ("pypi", "python"):
        # PyPI purl specification: lowercase, replace underscores with hyphens
        pypi_name = norm_name.lower().replace("_", "-")
        return f"pkg:pypi/{pypi_name}@{ver_str}"

    if eco_str in ("npm", "javascript", "node"):
        if norm_name.startswith("@") and "/" in norm_name:
            scope, pkg = norm_name.split("/", 1)
            # URL encode '@' as '%40' according to purl standard
            encoded_scope = scope.replace("@", "%40")
            return f"pkg:npm/{encoded_scope}/{pkg}@{ver_str}"
        return f"pkg:npm/{norm_name}@{ver_str}"

    if eco_str in ("cargo", "rust", "crates.io"):
        return f"pkg:cargo/{norm_name}@{ver_str}"

    if eco_str in ("deb", "debian", "ubuntu"):
        return f"pkg:deb/{norm_name}@{ver_str}"

    if eco_str in ("apk", "alpine"):
        return f"pkg:apk/{norm_name}@{ver_str}"

    if eco_str in ("rpm", "redhat", "fedora", "centos"):
        return f"pkg:rpm/{norm_name}@{ver_str}"

    # Unknown or unsupported ecosystem for purl
    return None


def generate_bom_ref(
    ecosystem: str | Ecosystem, name: str, version: str | None, purl: str | None
) -> str:
    """Generate unique and deterministic bom-ref for CycloneDX."""
    if purl:
        return purl
    eco_str = (
        (ecosystem.value if isinstance(ecosystem, Ecosystem) else str(ecosystem)).lower().strip()
    )
    ver_str = version or "unknown"
    return f"{eco_str}:{name}:{ver_str}"


class ExportComponent(BaseModel):
    """Normalized component representation for export."""

    name: str
    version: str | None = None
    ecosystem: str
    purl: str | None = None
    is_direct: bool = True
    dependency_type: str = "direct"
    scope: str = "runtime"
    source_file: str = ""
    manifest_source: str | None = None
    lockfile_source: str | None = None
    parent_name: str | None = None
    dependency_path: list[str] = Field(default_factory=list)
    bom_ref: str
    spdx_id: str
    license_declared: str = "NOASSERTION"
    license_concluded: str = "NOASSERTION"
    container_layer: str | None = None
    container_path: str | None = None
    container_image: str | None = None
    container_digest: str | None = None
    package_manager: str | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)


class ExportDependency(BaseModel):
    """Normalized directed dependency edge for export."""

    parent_name: str
    parent_version: str | None = None
    parent_ref: str
    child_name: str
    child_version: str | None = None
    child_ref: str
    scope: str = "runtime"
    requirement: str | None = None


class ExportVulnerability(BaseModel):
    """Normalized vulnerability definition/rule for export."""

    canonical_id: str
    aliases: list[str] = Field(default_factory=list)
    summary: str = ""
    description: str = ""
    severity: str = "UNKNOWN"
    cvss_score: float | None = None
    cvss_vector: str | None = None
    cwe_ids: list[str] = Field(default_factory=list)
    has_kev: bool = False
    source_name: str = ""
    source_url: str | None = None
    recommendation: str | None = None


class ExportFinding(BaseModel):
    """Normalized vulnerability finding (component + vulnerability instance)."""

    finding_id: str
    rule_id: str
    component_name: str
    component_version: str | None = None
    component_ref: str
    ecosystem: str
    dependency_type: str = "direct"
    source_file: str = ""
    manifest_source: str | None = None
    lockfile_source: str | None = None
    dependency_path: list[str] = Field(default_factory=list)
    applicability: str = "UNKNOWN"
    risk_level: str = "UNKNOWN"
    risk_score: float | None = None
    requires_human_review: bool = False
    confidence: float = 1.0
    evidence: list[str] = Field(default_factory=list)
    conflicts: list[dict[str, Any]] = Field(default_factory=list)
    conflict_summary: str | None = None
    container_layer: str | None = None
    container_path: str | None = None
    container_image: str | None = None
    container_digest: str | None = None
    package_manager: str | None = None
    # Policy Evaluation additions
    policy_status: str | None = None
    policy_rule_ids: list[str] = Field(default_factory=list)
    is_policy_violation: bool = False
    suppression_id: str | None = None
    suppression_reason: str | None = None
    suppression_expires_at: str | None = None


def _extract_eval_lookup(
    policy_evaluation: Any,
) -> tuple[dict[tuple[str, str, str], dict[str, Any]], dict[str, Any] | None]:
    """Helper to convert PolicyEvaluationResult or dict into finding lookup map."""
    eval_lookup: dict[tuple[str, str, str], dict[str, Any]] = {}
    policy_eval_dict: dict[str, Any] | None = None
    if not policy_evaluation:
        return eval_lookup, None

    if hasattr(policy_evaluation, "to_dict"):
        policy_eval_dict = policy_evaluation.to_dict()
    elif isinstance(policy_evaluation, dict):
        policy_eval_dict = policy_evaluation

    evals = []
    if hasattr(policy_evaluation, "evaluations"):
        evals = policy_evaluation.evaluations
    elif isinstance(policy_evaluation, dict) and "evaluations" in policy_evaluation:
        evals = policy_evaluation["evaluations"]

    for ev in evals:
        if hasattr(ev, "component_name") and hasattr(ev, "vulnerability_id"):
            c_name = str(ev.component_name).lower()
            c_ver = str(ev.component_version or "")
            v_id = str(ev.vulnerability_id)
            st = ev.status.value if hasattr(ev.status, "value") else str(ev.status)
            r_ids = [
                str(r) if isinstance(r, str) else getattr(r, "id", str(r))
                for r in getattr(ev, "matched_rules", [])
            ]
            is_violation = getattr(ev, "is_violation", False) or st.upper() == "VIOLATION"
            sup_id = getattr(ev, "matched_suppression_id", None)
            audit = getattr(ev, "audit_trace", {}) or {}
            s_reason = audit.get("suppression_reason")
            s_exp = audit.get("suppression_expires_at")
            eval_lookup[(c_name, c_ver, v_id)] = {
                "status": st,
                "matched_rules": r_ids,
                "is_violation": is_violation,
                "suppression_id": sup_id,
                "suppression_reason": s_reason,
                "suppression_expires_at": s_exp,
            }
        elif isinstance(ev, dict):
            c_info = ev.get("component") if isinstance(ev.get("component"), dict) else {}
            c_name = str(ev.get("component_name") or c_info.get("name", "")).lower()
            c_ver = str(ev.get("component_version") or c_info.get("version", "") or "")
            v_info = ev.get("vulnerability") if isinstance(ev.get("vulnerability"), dict) else {}
            v_id = str(ev.get("vulnerability_id") or v_info.get("canonical_id", "") or "")
            st = str(ev.get("status", ""))
            audit = ev.get("audit_trace") or {}
            r_ids = [
                r if isinstance(r, str) else (r.get("id", "") if isinstance(r, dict) else str(r))
                for r in ev.get("matched_rules", [])
            ]
            is_violation = ev.get("is_violation", False) or st.upper() == "VIOLATION"
            sup_id = ev.get("matched_suppression_id") or (
                ev.get("active_suppression", {}).get("id")
                if isinstance(ev.get("active_suppression"), dict)
                else None
            )
            s_reason = audit.get("suppression_reason") or (
                ev.get("active_suppression", {}).get("reason")
                if isinstance(ev.get("active_suppression"), dict)
                else None
            )
            s_exp = audit.get("suppression_expires_at") or (
                ev.get("active_suppression", {}).get("expires_at")
                if isinstance(ev.get("active_suppression"), dict)
                else None
            )
            eval_lookup[(c_name, c_ver, v_id)] = {
                "status": st,
                "matched_rules": r_ids,
                "is_violation": is_violation,
                "suppression_id": sup_id,
                "suppression_reason": s_reason,
                "suppression_expires_at": s_exp,
            }

    return eval_lookup, policy_eval_dict


class ExportScan(BaseModel):
    """Canonical intermediate model representing a full scan for export."""

    scan_id: str
    project_name: str
    project_path: str
    generated_at: str
    tool_name: str = "Local Vulnerability AI"
    tool_version: str = vuln_ai.__version__
    tool_uri: str = "https://github.com/Alejandro03GG/Local-Vulnerabilty-Ai"
    components: list[ExportComponent] = Field(default_factory=list)
    dependencies: list[ExportDependency] = Field(default_factory=list)
    vulnerabilities: list[ExportVulnerability] = Field(default_factory=list)
    findings: list[ExportFinding] = Field(default_factory=list)
    lockfiles_detected: list[str] = Field(default_factory=list)
    manifests_detected: list[str] = Field(default_factory=list)
    metadata: dict[str, Any] = Field(default_factory=dict)
    policy_evaluation: dict[str, Any] | None = None

    @classmethod
    def from_scan_summary(
        cls,
        summary: ScanResultSummary,
        scan_id: str | None = None,
        generated_at: str | None = None,
        policy_evaluation: Any = None,
    ) -> ExportScan:
        """Construct canonical ExportScan from a ScanResultSummary with deterministic ordering."""
        now_iso = generated_at or datetime.datetime.now(datetime.UTC).isoformat()
        resolved_scan_id = scan_id or f"scan-{summary.project_name}"

        # 1. Collect and normalize components
        components_map: dict[str, ExportComponent] = {}

        # First extract from DependencyGraph if present
        graph = summary.dependency_graph
        if isinstance(graph, DependencyGraph):
            for node in graph.nodes.values():
                eco = (
                    node.ecosystem.value
                    if isinstance(node.ecosystem, Ecosystem)
                    else str(node.ecosystem)
                )
                purl = generate_purl(eco, node.name, node.version)
                bom_ref = generate_bom_ref(eco, node.name, node.version, purl)
                spdx_id = sanitize_spdx_id(
                    f"Package-{eco}-{node.name}-{node.version or 'unknown'}"
                )
                is_dir = (
                    node.is_direct
                    if hasattr(node, "is_direct")
                    else (node.dependency_type == DependencyType.DIRECT)
                )
                dep_type = (
                    node.dependency_type.value
                    if hasattr(node.dependency_type, "value")
                    else str(node.dependency_type)
                )
                scope_str = node.scope.value if hasattr(node.scope, "value") else str(node.scope)

                n_meta = dict(node.metadata or {})
                comp = ExportComponent(
                    name=node.name,
                    version=node.version,
                    ecosystem=eco,
                    purl=purl,
                    is_direct=is_dir,
                    dependency_type=dep_type,
                    scope=scope_str,
                    source_file=node.source_file or "",
                    manifest_source=node.manifest_source,
                    lockfile_source=node.lockfile_source,
                    parent_name=node.parent_name,
                    dependency_path=list(node.dependency_path or []),
                    bom_ref=bom_ref,
                    spdx_id=spdx_id,
                    container_layer=n_meta.get("container_layer"),
                    container_path=n_meta.get("container_path"),
                    container_image=n_meta.get("container_image"),
                    container_digest=n_meta.get("container_digest"),
                    package_manager=n_meta.get("package_manager"),
                    metadata=n_meta,
                )
                components_map[bom_ref] = comp

        # Also ensure components found in matches are present
        for m in summary.matches:
            c = m.component
            eco = c.ecosystem.value if isinstance(c.ecosystem, Ecosystem) else str(c.ecosystem)
            purl = generate_purl(eco, c.name, c.version)
            bom_ref = generate_bom_ref(eco, c.name, c.version, purl)
            if bom_ref not in components_map:
                spdx_id = sanitize_spdx_id(f"Package-{eco}-{c.name}-{c.version or 'unknown'}")
                dep_type = (
                    c.dependency_type.value
                    if hasattr(c.dependency_type, "value")
                    else str(c.dependency_type)
                )
                scope_str = c.scope.value if hasattr(c.scope, "value") else str(c.scope)
                c_meta = dict(c.metadata or {})
                comp = ExportComponent(
                    name=c.name,
                    version=c.version,
                    ecosystem=eco,
                    purl=purl,
                    is_direct=c.is_direct,
                    dependency_type=dep_type,
                    scope=scope_str,
                    source_file=c.source_file or "",
                    manifest_source=c.manifest_source,
                    lockfile_source=c.lockfile_source,
                    parent_name=c.parent_name,
                    dependency_path=list(c.dependency_path or []),
                    bom_ref=bom_ref,
                    spdx_id=spdx_id,
                    container_layer=c_meta.get("container_layer"),
                    container_path=c_meta.get("container_path"),
                    container_image=c_meta.get("container_image"),
                    container_digest=c_meta.get("container_digest"),
                    package_manager=c_meta.get("package_manager"),
                    metadata=c_meta,
                )
                components_map[bom_ref] = comp

        # 2. Extract dependencies (edges) from graph
        dependencies_list: list[ExportDependency] = []
        if isinstance(graph, DependencyGraph):
            for edge in graph.edges:
                # Find matching parent and child components if possible
                p_nodes = [
                    c
                    for c in components_map.values()
                    if normalize_component_name(c.name)
                    == normalize_component_name(edge.parent_name)
                    and (not edge.parent_version or c.version == edge.parent_version)
                ]
                c_nodes = [
                    c
                    for c in components_map.values()
                    if normalize_component_name(c.name)
                    == normalize_component_name(edge.child_name)
                    and (not edge.child_version or c.version == edge.child_version)
                ]

                p_ref = (
                    p_nodes[0].bom_ref
                    if p_nodes
                    else f"unknown:{edge.parent_name}:{edge.parent_version or 'unknown'}"
                )
                c_ref = (
                    c_nodes[0].bom_ref
                    if c_nodes
                    else f"unknown:{edge.child_name}:{edge.child_version or 'unknown'}"
                )

                scope_val = edge.scope.value if hasattr(edge.scope, "value") else str(edge.scope)
                dependencies_list.append(
                    ExportDependency(
                        parent_name=edge.parent_name,
                        parent_version=edge.parent_version,
                        parent_ref=p_ref,
                        child_name=edge.child_name,
                        child_version=edge.child_version,
                        child_ref=c_ref,
                        scope=scope_val,
                        requirement=edge.requirement,
                    )
                )

        # 3. Extract unique vulnerabilities (rules) and findings
        vulns_map: dict[str, ExportVulnerability] = {}
        findings_list: list[ExportFinding] = []

        eval_lookup, policy_eval_dict = _extract_eval_lookup(policy_evaluation)

        for m in summary.matches:
            v = m.vulnerability
            rule_id = v.canonical_id
            if rule_id not in vulns_map:
                sev_val = (
                    v.severity.value
                    if hasattr(v.severity, "value")
                    else str(v.severity or "UNKNOWN")
                )
                vuln_aliases: list[str] = []
                if hasattr(v, "identifiers") and v.identifiers:
                    vuln_aliases = [i.identifier for i in v.identifiers if i.identifier != rule_id]

                cwes = getattr(v, "cwe_ids", None) or getattr(v, "cwes", None) or []
                desc = (
                    getattr(v, "description", None)
                    or v.short_description
                    or v.vulnerability_name
                    or ""
                )
                summary_text = (
                    getattr(v, "summary", None)
                    or v.short_description
                    or v.vulnerability_name
                    or ""
                )
                has_kev = getattr(v, "has_kev_evidence", False)

                vulns_map[rule_id] = ExportVulnerability(
                    canonical_id=rule_id,
                    aliases=vuln_aliases,
                    summary=summary_text,
                    description=desc,
                    severity=sev_val,
                    cvss_score=v.cvss_score,
                    cvss_vector=getattr(v, "cvss_vector", None),
                    cwe_ids=list(cwes),
                    has_kev=has_kev,
                    source_name=v.source_name,
                    source_url=getattr(v, "source_url", None),
                    recommendation=getattr(m.decision, "recommendation", None)
                    or getattr(m.ai_analysis, "recommendation", None),
                )

            # Build finding
            c = m.component
            eco = c.ecosystem.value if isinstance(c.ecosystem, Ecosystem) else str(c.ecosystem)
            purl = generate_purl(eco, c.name, c.version)
            comp_ref = generate_bom_ref(eco, c.name, c.version, purl)

            # Determine risk and review status from RiskAssessment
            risk_level = "UNKNOWN"
            risk_score = None
            requires_review = False
            if m.risk_assessment:
                rl = getattr(m.risk_assessment, "risk_level", "UNKNOWN")
                risk_level = rl.value if hasattr(rl, "value") else str(rl)
                risk_score = getattr(m.risk_assessment, "risk_score", None)
                requires_review = getattr(m.risk_assessment, "requires_human_review", False)

            app_val = (
                m.applicability.value
                if hasattr(m.applicability, "value")
                else str(m.applicability)
            )
            if app_val == "requires_review":
                requires_review = True

            dep_type = (
                c.dependency_type.value
                if hasattr(c.dependency_type, "value")
                else str(c.dependency_type)
            )

            # Conflicts
            conflicts_data: list[dict[str, Any]] = []
            if m.conflicts:
                for conf in m.conflicts:
                    src_list = getattr(conf, "sources", [])
                    src_a = getattr(conf, "source_a", "") or (
                        src_list[0] if len(src_list) > 0 else ""
                    )
                    src_b = getattr(conf, "source_b", "") or (
                        src_list[1] if len(src_list) > 1 else ""
                    )
                    c_type = str(
                        getattr(conf, "conflict_type", "") or getattr(conf, "divergence_type", "")
                    )
                    det = str(getattr(conf, "rationale", "") or getattr(conf, "details", ""))
                    conflicts_data.append(
                        {
                            "source_a": src_a,
                            "source_b": src_b,
                            "conflict_type": c_type,
                            "details": det,
                        }
                    )

            conflict_summary = None
            if m.conflict_resolution:
                conflict_summary = getattr(m.conflict_resolution, "resolution_rationale", None)

            # Deterministic finding ID
            finding_id = f"{rule_id}:{comp_ref}:{c.source_file}"

            pol_info = eval_lookup.get((c.name.lower(), c.version or "", rule_id))
            policy_status = pol_info.get("status") if pol_info else None
            policy_rule_ids = pol_info.get("matched_rules", []) if pol_info else []
            is_policy_violation = pol_info.get("is_violation", False) if pol_info else False
            suppression_id = pol_info.get("suppression_id") if pol_info else None
            suppression_reason = pol_info.get("suppression_reason") if pol_info else None
            suppression_expires_at = pol_info.get("suppression_expires_at") if pol_info else None

            c_meta = dict(c.metadata or {})
            finding = ExportFinding(
                finding_id=finding_id,
                rule_id=rule_id,
                component_name=c.name,
                component_version=c.version,
                component_ref=comp_ref,
                ecosystem=eco,
                dependency_type=dep_type,
                source_file=c.source_file or "",
                manifest_source=c.manifest_source,
                lockfile_source=c.lockfile_source,
                dependency_path=list(c.dependency_path or []),
                applicability=app_val.upper(),
                risk_level=str(risk_level).upper(),
                risk_score=risk_score,
                requires_human_review=requires_review,
                confidence=float(m.match_confidence),
                evidence=list(m.evidence or []),
                conflicts=conflicts_data,
                conflict_summary=conflict_summary,
                container_layer=c_meta.get("container_layer"),
                container_path=c_meta.get("container_path"),
                container_image=c_meta.get("container_image"),
                container_digest=c_meta.get("container_digest"),
                package_manager=c_meta.get("package_manager"),
                policy_status=policy_status,
                policy_rule_ids=policy_rule_ids,
                is_policy_violation=is_policy_violation,
                suppression_id=suppression_id,
                suppression_reason=suppression_reason,
                suppression_expires_at=suppression_expires_at,
            )
            findings_list.append(finding)

        # 4. Deterministic sorting across all collections
        sorted_components = sorted(
            components_map.values(),
            key=lambda x: (x.ecosystem.lower(), x.name.lower(), x.version or ""),
        )
        sorted_dependencies = sorted(
            dependencies_list,
            key=lambda x: (x.parent_ref, x.child_ref),
        )
        sorted_vulnerabilities = sorted(
            vulns_map.values(),
            key=lambda x: x.canonical_id,
        )
        sorted_findings = sorted(
            findings_list,
            key=lambda x: (
                x.rule_id,
                x.component_name.lower(),
                x.component_version or "",
                x.source_file,
            ),
        )

        lockfiles = sorted(summary.lockfiles_detected or [])
        manifests = []
        if isinstance(graph, DependencyGraph):
            manifests = sorted(graph.manifests_detected or [])

        return cls(
            scan_id=resolved_scan_id,
            project_name=summary.project_name,
            project_path=summary.project_path,
            generated_at=now_iso,
            tool_name="Local Vulnerability AI",
            tool_version=vuln_ai.__version__,
            components=sorted_components,
            dependencies=sorted_dependencies,
            vulnerabilities=sorted_vulnerabilities,
            findings=sorted_findings,
            lockfiles_detected=lockfiles,
            manifests_detected=manifests,
            metadata={
                "components_found": summary.components_found,
                "matches_found": summary.matches_found,
                "kev_matches": summary.kev_matches,
                "duration_seconds": summary.duration_seconds,
            },
            policy_evaluation=policy_eval_dict,
        )

    @classmethod
    def from_db(
        cls,
        scan: Any,
        project: Any,
        components: list[Any],
        edges: list[Any],
        matches: list[Any],
        generated_at: str | None = None,
        policy_evaluation: Any = None,
    ) -> ExportScan:
        """Construct canonical ExportScan from database entities."""
        import json

        now_iso = (
            generated_at
            or (scan.completed_at.isoformat() if getattr(scan, "completed_at", None) else None)
            or (scan.started_at.isoformat() if getattr(scan, "started_at", None) else None)
            or datetime.datetime.now(datetime.UTC).isoformat()
        )
        resolved_scan_id = getattr(scan, "id", f"scan-{getattr(project, 'name', 'unknown')}")

        components_map: dict[str, ExportComponent] = {}
        for c in components:
            eco = str(c.ecosystem)
            purl = generate_purl(eco, c.name, c.version)
            bom_ref = generate_bom_ref(eco, c.name, c.version, purl)
            spdx_id = sanitize_spdx_id(f"Package-{eco}-{c.name}-{c.version or 'unknown'}")

            dep_path: list[str] = []
            if getattr(c, "dependency_path", None):
                raw_path = c.dependency_path
                if isinstance(raw_path, str):
                    try:
                        dep_path = json.loads(raw_path)
                    except Exception:
                        dep_path = [raw_path]
                elif isinstance(raw_path, list):
                    dep_path = [str(p) for p in raw_path]

            comp = ExportComponent(
                name=c.name,
                version=c.version,
                ecosystem=eco,
                purl=purl,
                is_direct=bool(c.is_direct),
                dependency_type=str(c.dependency_type),
                scope=str(c.scope),
                source_file=c.source_file or "",
                manifest_source=c.manifest_source,
                lockfile_source=c.lockfile_source,
                parent_name=c.parent_name,
                dependency_path=dep_path,
                bom_ref=bom_ref,
                spdx_id=spdx_id,
            )
            components_map[bom_ref] = comp

        dependencies_list: list[ExportDependency] = []
        for edge in edges:
            p_nodes = [
                c
                for c in components_map.values()
                if normalize_component_name(c.name) == normalize_component_name(edge.parent_name)
                and (not edge.parent_version or c.version == edge.parent_version)
            ]
            c_nodes = [
                c
                for c in components_map.values()
                if normalize_component_name(c.name) == normalize_component_name(edge.child_name)
                and (not edge.child_version or c.version == edge.child_version)
            ]

            p_ref = (
                p_nodes[0].bom_ref
                if p_nodes
                else f"unknown:{edge.parent_name}:{edge.parent_version or 'unknown'}"
            )
            c_ref = (
                c_nodes[0].bom_ref
                if c_nodes
                else f"unknown:{edge.child_name}:{edge.child_version or 'unknown'}"
            )

            dependencies_list.append(
                ExportDependency(
                    parent_name=edge.parent_name,
                    parent_version=edge.parent_version,
                    parent_ref=p_ref,
                    child_name=edge.child_name,
                    child_version=edge.child_version,
                    child_ref=c_ref,
                    scope=str(edge.scope),
                    requirement=edge.requirement,
                )
            )

        vulns_map: dict[str, ExportVulnerability] = {}
        findings_list: list[ExportFinding] = []

        eval_lookup, policy_eval_dict = _extract_eval_lookup(policy_evaluation)

        from sqlalchemy.inspection import inspect as sa_inspect

        def is_loaded(obj: Any, attr: str) -> bool:
            try:
                insp = sa_inspect(obj)
                return attr not in insp.unloaded
            except Exception:
                return hasattr(obj, attr)

        for m in matches:
            v = m.vulnerability if is_loaded(m, "vulnerability") else None
            if not v:
                continue
            rule_id = v.canonical_id
            if rule_id not in vulns_map:
                aliases: list[str] = []
                if is_loaded(v, "identifiers") and v.identifiers:
                    aliases = [i.identifier for i in v.identifiers if i.identifier != rule_id]

                cwe_ids: list[str] = []
                if hasattr(v, "cwes") and v.cwes:
                    if isinstance(v.cwes, str):
                        try:
                            parsed_cwes = json.loads(v.cwes)
                            if isinstance(parsed_cwes, list):
                                cwe_ids = [str(x) for x in parsed_cwes]
                        except Exception:
                            cwe_ids = [v.cwes]
                    elif isinstance(v.cwes, list):
                        cwe_ids = [str(x) for x in v.cwes]

                has_kev = getattr(v, "has_kev_evidence", False)
                if not has_kev and is_loaded(v, "source_records") and v.source_records:
                    has_kev = any(
                        getattr(sr, "has_kev_evidence", False) for sr in v.source_records
                    )

                source_name = ""
                source_url = None
                if is_loaded(v, "source") and v.source:
                    source_name = v.source.name
                    source_url = v.source.url

                recomm_text = None
                if is_loaded(m, "ai_analysis") and m.ai_analysis:
                    recomm_text = getattr(m.ai_analysis, "recommendation", None)

                vulns_map[rule_id] = ExportVulnerability(
                    canonical_id=rule_id,
                    aliases=aliases,
                    summary=v.short_description or v.vulnerability_name or "",
                    description=v.short_description or v.vulnerability_name or "",
                    severity=str(v.severity or "UNKNOWN"),
                    cvss_score=v.cvss_score,
                    cvss_vector=None,
                    cwe_ids=cwe_ids,
                    has_kev=has_kev,
                    source_name=source_name,
                    source_url=source_url,
                    recommendation=recomm_text,
                )

            c = m.component if is_loaded(m, "component") else None
            if not c:
                continue
            eco = str(c.ecosystem)
            purl = generate_purl(eco, c.name, c.version)
            comp_ref = generate_bom_ref(eco, c.name, c.version, purl)

            risk_level = "UNKNOWN"
            risk_score = None
            requires_review = False
            if is_loaded(m, "risk_assessment") and m.risk_assessment:
                risk_level = str(m.risk_assessment.risk_level)
                risk_score = getattr(m.risk_assessment, "risk_score", None)
                requires_review = bool(m.risk_assessment.requires_human_review)

            app_val = str(m.applicability)
            if app_val.lower() == "requires_review":
                requires_review = True

            ev_list: list[str] = []
            if hasattr(m, "evidence") and m.evidence:
                if isinstance(m.evidence, str):
                    try:
                        parsed_ev = json.loads(m.evidence)
                        if isinstance(parsed_ev, list):
                            ev_list = [str(x) for x in parsed_ev]
                    except Exception:
                        ev_list = [m.evidence]
                elif isinstance(m.evidence, list):
                    ev_list = [str(x) for x in m.evidence]

            conflicts_data: list[dict[str, Any]] = []
            if is_loaded(m, "conflicts") and m.conflicts:
                for conf in m.conflicts:
                    conflicts_data.append(
                        {
                            "source_a": getattr(conf, "source_a", ""),
                            "source_b": getattr(conf, "source_b", ""),
                            "divergence_type": str(getattr(conf, "divergence_type", "")),
                            "details": getattr(conf, "details", ""),
                        }
                    )

            finding_id = f"{rule_id}:{comp_ref}:{c.source_file}"
            dep_path = []
            if getattr(c, "dependency_path", None):
                raw_path = c.dependency_path
                if isinstance(raw_path, str):
                    try:
                        dep_path = json.loads(raw_path)
                    except Exception:
                        dep_path = [raw_path]
                elif isinstance(raw_path, list):
                    dep_path = [str(p) for p in raw_path]

            pol_info = eval_lookup.get((c.name.lower(), c.version or "", rule_id))
            policy_status = pol_info.get("status") if pol_info else None
            policy_rule_ids = pol_info.get("matched_rules", []) if pol_info else []
            is_policy_violation = pol_info.get("is_violation", False) if pol_info else False
            suppression_id = pol_info.get("suppression_id") if pol_info else None
            suppression_reason = pol_info.get("suppression_reason") if pol_info else None
            suppression_expires_at = pol_info.get("suppression_expires_at") if pol_info else None

            findings_list.append(
                ExportFinding(
                    finding_id=finding_id,
                    rule_id=rule_id,
                    component_name=c.name,
                    component_version=c.version,
                    component_ref=comp_ref,
                    ecosystem=eco,
                    dependency_type=str(c.dependency_type),
                    source_file=c.source_file or "",
                    manifest_source=c.manifest_source,
                    lockfile_source=c.lockfile_source,
                    dependency_path=dep_path,
                    applicability=app_val.upper(),
                    risk_level=risk_level.upper(),
                    risk_score=risk_score,
                    requires_human_review=requires_review,
                    confidence=float(m.match_confidence or 0.0),
                    evidence=ev_list,
                    conflicts=conflicts_data,
                    policy_status=policy_status,
                    policy_rule_ids=policy_rule_ids,
                    is_policy_violation=is_policy_violation,
                    suppression_id=suppression_id,
                    suppression_reason=suppression_reason,
                    suppression_expires_at=suppression_expires_at,
                )
            )

        sorted_components = sorted(
            components_map.values(),
            key=lambda x: (x.ecosystem.lower(), x.name.lower(), x.version or ""),
        )
        sorted_dependencies = sorted(
            dependencies_list,
            key=lambda x: (x.parent_ref, x.child_ref),
        )
        sorted_vulnerabilities = sorted(
            vulns_map.values(),
            key=lambda x: x.canonical_id,
        )
        sorted_findings = sorted(
            findings_list,
            key=lambda x: (
                x.rule_id,
                x.component_name.lower(),
                x.component_version or "",
                x.source_file,
            ),
        )

        lockfiles = sorted({c.lockfile_source for c in sorted_components if c.lockfile_source})
        manifests = sorted({c.manifest_source for c in sorted_components if c.manifest_source})

        return cls(
            scan_id=resolved_scan_id,
            project_name=getattr(project, "name", "project"),
            project_path=getattr(project, "path", ""),
            generated_at=now_iso,
            tool_name="Local Vulnerability AI",
            tool_version=vuln_ai.__version__,
            components=sorted_components,
            dependencies=sorted_dependencies,
            vulnerabilities=sorted_vulnerabilities,
            findings=sorted_findings,
            lockfiles_detected=lockfiles,
            manifests_detected=manifests,
            metadata={
                "components_found": getattr(scan, "components_found", len(sorted_components)),
                "matches_found": len(matches),
                "kev_matches": getattr(scan, "kev_matches", 0),
                "duration_seconds": getattr(scan, "duration_seconds", 0.0),
            },
            policy_evaluation=policy_eval_dict,
        )
