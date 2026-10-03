"""Unit tests for Policy and Suppression integration with SARIF, CycloneDX, and SPDX."""

from __future__ import annotations

from datetime import UTC, datetime

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
from vuln_ai.export.cyclonedx import export_cyclonedx_dict
from vuln_ai.export.models import ExportScan
from vuln_ai.export.sarif import export_sarif_dict
from vuln_ai.export.spdx import export_spdx_dict
from vuln_ai.policy.models import (
    PolicyAction,
    PolicyEvaluationResult,
    PolicyRule,
    Suppression,
    SuppressionMatchCriteria,
)
from vuln_ai.risk.models import RiskAssessment, RiskLevel, RiskStatus


def _create_sample_summary() -> tuple[ScanResultSummary, PolicyEvaluationResult]:
    comp1 = DetectedComponent(
        name="requests",
        version="2.25.0",
        ecosystem=Ecosystem.PYPI,
        source_file="requirements.txt",
        is_direct=True,
    )
    vuln1 = VulnerabilityRecord(
        canonical_id="CVE-2023-32681",
        severity="HIGH",
        cvss_score=7.5,
        summary="Unintended leak of Proxy-Authorization header in requests",
    )
    risk1 = RiskAssessment(
        status=RiskStatus.LIKELY_AFFECTED,
        risk_level=RiskLevel.HIGH,
        certainty=0.9,
        rationale="High severity vulnerable component used in production",
        recommended_action="Upgrade to >= 2.31.0",
        requires_human_review=False,
    )
    match1 = MatchResult(
        component=comp1,
        vulnerability=vuln1,
        match_type=MatchType.EXACT_NAME,
        match_confidence=1.0,
        applicability=Applicability.LIKELY_AFFECTED,
        risk_assessment=risk1,
    )

    comp2 = DetectedComponent(
        name="urllib3",
        version="1.26.4",
        ecosystem=Ecosystem.PYPI,
        source_file="requirements.txt",
        is_direct=False,
    )
    vuln2 = VulnerabilityRecord(
        canonical_id="CVE-2021-33503",
        severity="MEDIUM",
        cvss_score=5.3,
        summary="ReDoS vulnerability in urllib3",
    )
    risk2 = RiskAssessment(
        status=RiskStatus.LIKELY_NOT_AFFECTED,
        risk_level=RiskLevel.LOW,
        certainty=0.8,
        rationale="Low impact regex issue",
        recommended_action="Review",
        requires_human_review=False,
    )
    match2 = MatchResult(
        component=comp2,
        vulnerability=vuln2,
        match_type=MatchType.EXACT_NAME,
        match_confidence=0.9,
        applicability=Applicability.LIKELY_AFFECTED,
        risk_assessment=risk2,
    )

    summary = ScanResultSummary(
        project_name="demo-export-project",
        project_path="/tmp/demo",
        scan_status=ScanStatus.COMPLETED,
        matches=[match1, match2],
        components_found=2,
        matches_found=2,
        kev_matches=0,
        duration_seconds=0.1,
    )

    from vuln_ai.policy.engine import PolicyEngine
    from vuln_ai.policy.models import Policy, PolicyCondition

    rule1 = PolicyRule(
        id="block-high",
        description="Block high severity",
        when=PolicyCondition(severity="HIGH"),
        action=PolicyAction.BLOCK,
    )
    sup1 = Suppression(
        id="SUP-001",
        match_criteria=SuppressionMatchCriteria(vulnerability_id="CVE-2023-32681"),
        reason="Vendor fix scheduled next sprint",
        owner="sec-team@example.com",
        reference="SEC-1234",
        expires_at=datetime(2027, 1, 1, tzinfo=UTC),
    )

    policy = Policy(
        id="test-policy",
        name="Test Policy",
        rules=[rule1],
        default_action=PolicyAction.ALLOW,
    )

    engine = PolicyEngine(policy=policy, suppressions=[sup1])
    policy_result = engine.evaluate(summary.matches)

    return summary, policy_result


def test_sarif_export_with_policy() -> None:
    summary, pol_eval = _create_sample_summary()
    export_scan = ExportScan.from_scan_summary(
        summary=summary,
        policy_evaluation=pol_eval,
    )

    sarif_doc = export_sarif_dict(export_scan)
    results = sarif_doc["runs"][0]["results"]
    assert len(results) == 2

    # Check suppressed finding
    suppressed_res = next(r for r in results if r["ruleId"] == "CVE-2023-32681")
    props = suppressed_res["properties"]
    assert props["policyStatus"] == "SUPPRESSED"
    assert props["policyRuleIds"] == ["block-high"]
    assert props["suppressionId"] == "SUP-001"
    assert props["suppressionReason"] == "Vendor fix scheduled next sprint"
    assert "suppressionExpiresAt" in props
    assert props["policyViolation"] is False

    # Check native SARIF suppressions
    assert "suppressions" in suppressed_res
    assert suppressed_res["suppressions"][0]["kind"] == "external"
    assert suppressed_res["suppressions"][0]["status"] == "accepted"
    assert suppressed_res["suppressions"][0]["justification"] == "Vendor fix scheduled next sprint"

    # Check allowed finding
    allowed_res = next(r for r in results if r["ruleId"] == "CVE-2021-33503")
    assert allowed_res["properties"]["policyStatus"] == "ALLOWED"
    assert "suppressions" not in allowed_res


def test_cyclonedx_export_with_policy() -> None:
    summary, pol_eval = _create_sample_summary()
    export_scan = ExportScan.from_scan_summary(
        summary=summary,
        policy_evaluation=pol_eval,
    )

    cdx_doc = export_cyclonedx_dict(export_scan)
    vulns = cdx_doc.get("vulnerabilities", [])
    assert len(vulns) == 2

    sup_vuln = next(v for v in vulns if v["id"] == "CVE-2023-32681")
    assert "properties" in sup_vuln
    props = {p["name"]: p["value"] for p in sup_vuln["properties"]}
    assert props["vuln_ai:policy_status"] == "SUPPRESSED"
    assert props["vuln_ai:suppression_id"] == "SUP-001"
    assert props["vuln_ai:suppression_reason"] == "Vendor fix scheduled next sprint"


def test_spdx_export_with_policy() -> None:
    summary, pol_eval = _create_sample_summary()
    export_scan = ExportScan.from_scan_summary(
        summary=summary,
        policy_evaluation=pol_eval,
    )

    spdx_doc = export_spdx_dict(export_scan)
    assert spdx_doc["spdxVersion"] == "SPDX-2.3"
    # Ensure license remains NOASSERTION
    for pkg in spdx_doc["packages"]:
        assert pkg["licenseConcluded"] == "NOASSERTION"


def test_export_scan_from_db_with_edges_and_paths() -> None:
    from unittest.mock import MagicMock

    from vuln_ai.core.models import DependencyScope, DependencyType

    scan = MagicMock()
    scan.id = "scan-123"
    scan.completed_at = datetime.now(UTC)

    project = MagicMock()
    project.name = "proj-demo"
    project.path = "/tmp/proj"

    c1 = MagicMock()
    c1.name = "parent-pkg"
    c1.version = "1.0.0"
    c1.ecosystem = "pypi"
    c1.is_direct = True
    c1.dependency_type = DependencyType.DIRECT
    c1.scope = DependencyScope.RUNTIME
    c1.source_file = "requirements.txt"
    c1.manifest_source = None
    c1.lockfile_source = None
    c1.parent_name = None
    c1.dependency_path = '["parent-pkg"]'

    c2 = MagicMock()
    c2.name = "child-pkg"
    c2.version = "2.0.0"
    c2.ecosystem = "pypi"
    c2.is_direct = False
    c2.dependency_type = DependencyType.TRANSITIVE
    c2.scope = DependencyScope.RUNTIME
    c2.source_file = "requirements.txt"
    c2.manifest_source = None
    c2.lockfile_source = None
    c2.parent_name = "parent-pkg"
    c2.dependency_path = ["parent-pkg", "child-pkg"]

    c3 = MagicMock()
    c3.name = "orphan-pkg"
    c3.version = "3.0.0"
    c3.ecosystem = "pypi"
    c3.is_direct = True
    c3.dependency_type = DependencyType.DIRECT
    c3.scope = DependencyScope.RUNTIME
    c3.source_file = "requirements.txt"
    c3.manifest_source = None
    c3.lockfile_source = None
    c3.parent_name = None
    c3.dependency_path = "invalid-json-string-path"

    edge1 = MagicMock()
    edge1.parent_name = "parent-pkg"
    edge1.parent_version = "1.0.0"
    edge1.child_name = "child-pkg"
    edge1.child_version = "2.0.0"
    edge1.edge_type = "DIRECT"
    edge1.scope = "runtime"
    edge1.requirement = ">=1.0"

    edge2 = MagicMock()
    edge2.parent_name = "unknown-parent"
    edge2.parent_version = "0.1.0"
    edge2.child_name = "unknown-child"
    edge2.child_version = "0.2.0"
    edge2.edge_type = "TRANSITIVE"
    edge2.scope = "runtime"
    edge2.requirement = None

    export_scan = ExportScan.from_db(
        scan=scan,
        project=project,
        components=[c1, c2, c3],
        edges=[edge1, edge2],
        matches=[],
    )

    assert len(export_scan.components) == 3
    assert len(export_scan.dependencies) == 2
    c_map = {c.name: c for c in export_scan.components}
    assert c_map["parent-pkg"].dependency_path == ["parent-pkg"]
    assert c_map["child-pkg"].dependency_path == ["parent-pkg", "child-pkg"]
    assert c_map["orphan-pkg"].dependency_path == ["invalid-json-string-path"]
