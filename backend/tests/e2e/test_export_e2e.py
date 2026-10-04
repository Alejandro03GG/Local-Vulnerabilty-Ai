"""End-to-End export scenarios covering Cases A through J (Etapa 15 §48, §58)."""

from __future__ import annotations

import time

from vuln_ai.core.graph import (
    DependencyEdge,
    DependencyGraph,
    DependencyNode,
)
from vuln_ai.core.models import (
    Applicability,
    DetectedComponent,
    Ecosystem,
    MatchResult,
    MatchType,
    ScanResultSummary,
    ScanStatus,
    VulnerabilityRecord,
)
from vuln_ai.export.cyclonedx import export_cyclonedx_dict, validate_cyclonedx_dict
from vuln_ai.export.models import ExportScan
from vuln_ai.export.sarif import export_sarif_dict, validate_sarif_dict
from vuln_ai.export.spdx import export_spdx_dict, validate_spdx_dict
from vuln_ai.matching.conflict import ConflictSeverity, ConflictType, SourceConflict
from vuln_ai.risk.models import RiskAssessment, RiskLevel, RiskStatus


def _make_risk(level: RiskLevel = RiskLevel.HIGH, review: bool = False) -> RiskAssessment:
    return RiskAssessment(
        status=RiskStatus.REQUIRES_REVIEW if review else RiskStatus.LIKELY_AFFECTED,
        risk_level=level,
        certainty=0.9,
        rationale="Evaluation rationale",
        recommended_action="Remediate component",
        requires_human_review=review,
    )


def test_scenario_a_project_without_vulnerabilities() -> None:
    """Caso A: Project with dependencies but 0 vulnerabilities."""
    graph = DependencyGraph()
    node = DependencyNode.create(
        name="secure-lib",
        version="1.0.0",
        ecosystem=Ecosystem.PYPI,
        source_file="poetry.lock",
        is_direct=True,
    )
    graph.add_node(node)

    summary = ScanResultSummary(
        project_name="clean-project",
        project_path="/clean",
        scan_status=ScanStatus.COMPLETED,
        dependency_graph=graph,
        matches=[],
    )
    scan = ExportScan.from_scan_summary(summary)

    sarif = export_sarif_dict(scan)
    validate_sarif_dict(sarif)
    assert len(sarif["runs"][0]["results"]) == 0
    assert len(sarif["runs"][0]["tool"]["driver"]["rules"]) == 0

    cdx = export_cyclonedx_dict(scan)
    validate_cyclonedx_dict(cdx)
    assert len(cdx["components"]) == 1
    assert "vulnerabilities" not in cdx

    spdx = export_spdx_dict(scan)
    validate_spdx_dict(spdx)
    assert len(spdx["packages"]) == 2  # Root + secure-lib


def test_scenario_b_vulnerable_direct_dependency() -> None:
    """Caso B: Vulnerable direct dependency."""
    comp = DetectedComponent(
        name="flask",
        version="0.12.0",
        ecosystem=Ecosystem.PYPI,
        source_file="requirements.txt",
        is_direct=True,
    )
    vuln = VulnerabilityRecord(
        canonical_id="CVE-2018-1000656",
        summary="Flask DoS via unexpected JSON payload",
        severity="HIGH",
        cvss_score=7.5,
        source_name="NVD",
    )
    match = MatchResult(
        component=comp,
        vulnerability=vuln,
        match_type=MatchType.EXACT_NAME,
        match_confidence=1.0,
        applicability=Applicability.LIKELY_AFFECTED,
        risk_assessment=_make_risk(RiskLevel.HIGH),
    )

    summary = ScanResultSummary(
        project_name="flask-app",
        project_path="/flask-app",
        scan_status=ScanStatus.COMPLETED,
        matches=[match],
    )
    scan = ExportScan.from_scan_summary(summary)

    sarif = export_sarif_dict(scan)
    assert sarif["runs"][0]["results"][0]["level"] == "error"
    assert sarif["runs"][0]["results"][0]["properties"]["dependencyType"] == "direct"

    cdx = export_cyclonedx_dict(scan)
    assert cdx["vulnerabilities"][0]["id"] == "CVE-2018-1000656"

    spdx = export_spdx_dict(scan)
    assert any(p["name"] == "flask" for p in spdx["packages"])


def test_scenario_c_vulnerable_transitive_dependency() -> None:
    """Caso C: Vulnerable transitive dependency with dependency path."""
    graph = DependencyGraph()
    parent = DependencyNode.create(
        name="web-framework",
        version="1.0.0",
        ecosystem=Ecosystem.NPM,
        source_file="package-lock.json",
        is_direct=True,
    )
    child = DependencyNode.create(
        name="lodash",
        version="4.17.15",
        ecosystem=Ecosystem.NPM,
        source_file="package-lock.json",
        is_direct=False,
        parent_name="web-framework",
    )
    child.dependency_path = ["web-framework", "lodash"]
    graph.add_node(parent)
    graph.add_node(child)

    edge = DependencyEdge(
        parent_name="web-framework",
        parent_version="1.0.0",
        child_name="lodash",
        child_version="4.17.15",
    )
    graph.add_edge(edge)

    comp = child.to_component()
    vuln = VulnerabilityRecord(
        canonical_id="CVE-2020-8203",
        summary="Prototype pollution in lodash",
        severity="HIGH",
        cvss_score=7.4,
        source_name="OSV",
    )
    match = MatchResult(
        component=comp,
        vulnerability=vuln,
        match_type=MatchType.EXACT_NAME,
        match_confidence=1.0,
        applicability=Applicability.LIKELY_AFFECTED,
        risk_assessment=_make_risk(RiskLevel.HIGH),
    )

    summary = ScanResultSummary(
        project_name="node-app",
        project_path="/node-app",
        scan_status=ScanStatus.COMPLETED,
        dependency_graph=graph,
        matches=[match],
    )
    scan = ExportScan.from_scan_summary(summary)

    sarif = export_sarif_dict(scan)
    res = sarif["runs"][0]["results"][0]
    assert res["properties"]["dependencyType"] == "transitive"
    assert res["properties"]["dependencyPath"] == ["web-framework", "lodash"]

    cdx = export_cyclonedx_dict(scan)
    lodash_comp = next(c for c in cdx["components"] if c["name"] == "lodash")
    path_prop = next(
        p for p in lodash_comp["properties"] if p["name"] == "vuln_ai:dependency_path"
    )
    assert path_prop["value"] == "web-framework -> lodash"


def test_scenario_d_multiple_versions_of_same_package() -> None:
    """Caso D: Multiple versions of the same package in project."""
    graph = DependencyGraph()
    n1 = DependencyNode.create(
        name="semver",
        version="5.7.1",
        ecosystem=Ecosystem.NPM,
        source_file="package-lock.json",
        is_direct=True,
    )
    n2 = DependencyNode.create(
        name="semver",
        version="7.5.4",
        ecosystem=Ecosystem.NPM,
        source_file="package-lock.json",
        is_direct=False,
    )
    graph.add_node(n1)
    graph.add_node(n2)

    vuln = VulnerabilityRecord(
        canonical_id="CVE-2022-25883",
        summary="ReDoS in semver",
        severity="MEDIUM",
    )
    match = MatchResult(
        component=n1.to_component(),
        vulnerability=vuln,
        match_type=MatchType.EXACT_NAME,
        match_confidence=1.0,
        applicability=Applicability.LIKELY_AFFECTED,
    )

    summary = ScanResultSummary(
        project_name="multi-ver-proj",
        project_path="/mvp",
        scan_status=ScanStatus.COMPLETED,
        dependency_graph=graph,
        matches=[match],
    )
    scan = ExportScan.from_scan_summary(summary)

    cdx = export_cyclonedx_dict(scan)
    assert len(cdx["components"]) == 2
    bom_refs = {c["bom-ref"] for c in cdx["components"]}
    assert "pkg:npm/semver@5.7.1" in bom_refs
    assert "pkg:npm/semver@7.5.4" in bom_refs

    spdx = export_spdx_dict(scan)
    # Distinct SPDX IDs
    semver_pkgs = [p for p in spdx["packages"] if p["name"] == "semver"]
    assert len(semver_pkgs) == 2
    assert semver_pkgs[0]["SPDXID"] != semver_pkgs[1]["SPDXID"]


def test_scenario_e_multi_source_conflict() -> None:
    """Caso E: Multi-source conflict preserving REQUIRES_REVIEW and conflict data."""
    comp = DetectedComponent(
        name="urllib3",
        version="1.26.5",
        ecosystem=Ecosystem.PYPI,
        source_file="requirements.txt",
    )
    vuln = VulnerabilityRecord(
        canonical_id="CVE-2021-33503",
        summary="Catastrophic backtracking",
        severity="MEDIUM",
    )
    conflict = SourceConflict(
        conflict_type=ConflictType.APPLICABILITY,
        severity=ConflictSeverity.HIGH,
        field="applicability",
        sources=["OSV", "NVD"],
        identifiers=["CVE-2021-33503"],
        values={"OSV": "affected", "NVD": "unaffected"},
        resolution="REQUIRES_REVIEW",
        rationale="OSV says affected, NVD says unaffected",
    )
    match = MatchResult(
        component=comp,
        vulnerability=vuln,
        match_type=MatchType.EXACT_NAME,
        match_confidence=0.7,
        applicability=Applicability.REQUIRES_REVIEW,
        conflicts=[conflict],
        risk_assessment=_make_risk(RiskLevel.MEDIUM, review=True),
    )

    summary = ScanResultSummary(
        project_name="conflict-proj",
        project_path="/cp",
        scan_status=ScanStatus.COMPLETED,
        matches=[match],
    )
    scan = ExportScan.from_scan_summary(summary)

    sarif = export_sarif_dict(scan)
    res = sarif["runs"][0]["results"][0]
    assert res["properties"]["applicability"] == "REQUIRES_REVIEW"
    assert res["properties"]["requiresHumanReview"] is True
    assert len(res["properties"]["sourceConflicts"]) == 1

    cdx = export_cyclonedx_dict(scan)
    assert cdx["vulnerabilities"][0]["analysis"]["state"] == "in_triage"


def test_scenario_f_cisa_only() -> None:
    """Caso F: CISA-only vulnerability."""
    comp = DetectedComponent(
        name="log4j-core",
        version="2.14.1",
        ecosystem=Ecosystem.UNKNOWN,
        source_file="manifest.txt",
    )
    vuln = VulnerabilityRecord(
        canonical_id="CVE-2021-44228",
        summary="Log4Shell",
        severity="CRITICAL",
        source_name="CISA KEV",
    )
    match = MatchResult(
        component=comp,
        vulnerability=vuln,
        match_type=MatchType.EXACT_NAME,
        match_confidence=0.9,
        applicability=Applicability.LIKELY_AFFECTED,
        risk_assessment=_make_risk(RiskLevel.CRITICAL),
    )

    summary = ScanResultSummary(
        project_name="cisa-proj",
        project_path="/cisa",
        scan_status=ScanStatus.COMPLETED,
        matches=[match],
    )
    scan = ExportScan.from_scan_summary(summary)

    sarif = export_sarif_dict(scan)
    assert sarif["runs"][0]["tool"]["driver"]["rules"][0]["properties"]["hasKev"] is True


def test_scenario_g_and_h_ai_and_systemone_unavailable() -> None:
    """Casos G & H: Exports succeed cleanly when AI / SystemOne are unavailable."""
    comp = DetectedComponent(
        name="requests",
        version="2.25.0",
        ecosystem=Ecosystem.PYPI,
        source_file="poetry.lock",
    )
    vuln = VulnerabilityRecord(
        canonical_id="CVE-2023-32681",
        severity="HIGH",
    )
    match = MatchResult(
        component=comp,
        vulnerability=vuln,
        match_type=MatchType.EXACT_NAME,
        match_confidence=1.0,
        applicability=Applicability.LIKELY_AFFECTED,
        ai_analysis=None,
        decision=None,
        risk_assessment=_make_risk(RiskLevel.HIGH),
    )

    summary = ScanResultSummary(
        project_name="no-ai-proj",
        project_path="/no-ai",
        scan_status=ScanStatus.COMPLETED,
        matches=[match],
    )
    scan = ExportScan.from_scan_summary(summary)

    sarif = export_sarif_dict(scan)
    validate_sarif_dict(sarif)

    cdx = export_cyclonedx_dict(scan)
    validate_cyclonedx_dict(cdx)

    spdx = export_spdx_dict(scan)
    validate_spdx_dict(spdx)


def test_scenario_i_empty_project() -> None:
    """Caso I: Empty project with no files or components."""
    summary = ScanResultSummary(
        project_name="empty-proj",
        project_path="/empty",
        scan_status=ScanStatus.COMPLETED,
        components_found=0,
        matches_found=0,
    )
    scan = ExportScan.from_scan_summary(summary)

    sarif = export_sarif_dict(scan)
    validate_sarif_dict(sarif)
    assert len(sarif["runs"][0]["results"]) == 0

    cdx = export_cyclonedx_dict(scan)
    validate_cyclonedx_dict(cdx)
    assert len(cdx["components"]) == 0

    spdx = export_spdx_dict(scan)
    validate_spdx_dict(spdx)
    assert len(spdx["packages"]) == 1  # Root only


def test_scenario_j_large_dependency_graph() -> None:
    """Caso J: Stress test with 1000+ nodes, 1000+ edges, 100+ vulnerabilities (§43, §58)."""
    graph = DependencyGraph()
    total_nodes = 1050
    total_vulns = 120

    # 1. Create 1050 dependency nodes
    for i in range(total_nodes):
        node = DependencyNode.create(
            name=f"pkg-{i}",
            version=f"1.{i % 10}.0",
            ecosystem=Ecosystem.PYPI if i % 2 == 0 else Ecosystem.NPM,
            source_file="poetry.lock" if i % 2 == 0 else "package-lock.json",
            is_direct=(i < 50),
        )
        graph.add_node(node)

    # 2. Create 1000+ directed edges
    for i in range(50, total_nodes):
        parent_idx = i % 50  # Parent is one of the 50 direct deps
        edge = DependencyEdge(
            parent_name=f"pkg-{parent_idx}",
            parent_version=f"1.{parent_idx % 10}.0",
            child_name=f"pkg-{i}",
            child_version=f"1.{i % 10}.0",
        )
        graph.add_edge(edge)

    # 3. Create 120 vulnerability matches
    matches: list[MatchResult] = []
    for v_idx in range(total_vulns):
        comp_idx = v_idx * 5  # Pick spread components
        comp_node = graph.nodes[
            f"{'pypi' if comp_idx % 2 == 0 else 'npm'}:pkg_{comp_idx}:1.{comp_idx % 10}.0"
        ]
        vuln = VulnerabilityRecord(
            canonical_id=f"CVE-2024-{1000 + v_idx}",
            summary=f"Vulnerability {v_idx} in pkg-{comp_idx}",
            severity="HIGH" if v_idx % 2 == 0 else "MEDIUM",
            cvss_score=7.0 + (v_idx % 30) / 10.0,
            source_name="OSV",
        )
        match = MatchResult(
            component=comp_node.to_component(),
            vulnerability=vuln,
            match_type=MatchType.EXACT_NAME,
            match_confidence=1.0,
            applicability=Applicability.LIKELY_AFFECTED,
            risk_assessment=_make_risk(RiskLevel.HIGH if v_idx % 2 == 0 else RiskLevel.MEDIUM),
        )
        matches.append(match)

    summary = ScanResultSummary(
        project_name="large-enterprise-repo",
        project_path="/large-repo",
        scan_status=ScanStatus.COMPLETED,
        components_found=total_nodes,
        matches_found=len(matches),
        dependency_graph=graph,
        matches=matches,
    )

    t0 = time.perf_counter()
    scan = ExportScan.from_scan_summary(summary)
    t_canonical = time.perf_counter() - t0

    # SARIF export
    t1 = time.perf_counter()
    sarif = export_sarif_dict(scan)
    validate_sarif_dict(sarif)
    t_sarif = time.perf_counter() - t1
    assert len(sarif["runs"][0]["tool"]["driver"]["rules"]) == total_vulns
    assert len(sarif["runs"][0]["results"]) == total_vulns

    # CycloneDX export
    t2 = time.perf_counter()
    cdx = export_cyclonedx_dict(scan)
    validate_cyclonedx_dict(cdx)
    t_cdx = time.perf_counter() - t2
    assert len(cdx["components"]) == total_nodes
    assert len(cdx["vulnerabilities"]) == total_vulns

    # SPDX export
    t3 = time.perf_counter()
    spdx = export_spdx_dict(scan)
    validate_spdx_dict(spdx)
    t_spdx = time.perf_counter() - t3
    assert len(spdx["packages"]) == total_nodes + 1  # Root + 1050

    total_time = t_canonical + t_sarif + t_cdx + t_spdx
    # Entire export of 1050 nodes, 1000 edges, 120 vulns must complete under 5 seconds
    # (accounting for coverage tracing/instrumentation overhead in CI runners)
    assert total_time < 5.0, f"Export took too long: {total_time:.2f}s"
