"""Unit tests for SARIF 2.1.0 exporter (Etapa 15 §44)."""

from __future__ import annotations

import json

import pytest

from vuln_ai.core.graph import DependencyGraph, DependencyType
from vuln_ai.core.models import (
    Applicability,
    DetectedComponent,
    Ecosystem,
    MatchEvidence,
    MatchResult,
    MatchType,
    ScanResultSummary,
    ScanStatus,
    VulnerabilityRecord,
)
from vuln_ai.export.errors import ExportValidationError
from vuln_ai.export.models import ExportScan
from vuln_ai.export.sarif import (
    SARIF_SCHEMA_URI,
    SARIF_VERSION,
    _map_risk_level_to_sarif_level,
    export_sarif_dict,
    export_sarif_json,
    validate_sarif_dict,
)
from vuln_ai.risk.models import RiskAssessment, RiskLevel, RiskStatus


def _make_dummy_summary(
    matches: list[MatchResult] | None = None,
    graph: DependencyGraph | None = None,
) -> ScanResultSummary:
    """Helper to build a mock ScanResultSummary."""
    return ScanResultSummary(
        project_name="test-project",
        project_path="/tmp/test-project",
        scan_status=ScanStatus.COMPLETED,
        components_found=len(graph.nodes) if graph else 0,
        matches_found=len(matches or []),
        matches=matches or [],
        dependency_graph=graph or DependencyGraph(),
        lockfiles_detected=["poetry.lock"],
    )


def test_map_risk_level_to_sarif_level():
    """Verify deterministic mapping from Risk Engine evaluation to SARIF level."""
    assert _map_risk_level_to_sarif_level("CRITICAL") == "error"
    assert _map_risk_level_to_sarif_level("HIGH") == "error"
    assert _map_risk_level_to_sarif_level("MEDIUM") == "warning"
    assert _map_risk_level_to_sarif_level("LOW") == "note"
    assert _map_risk_level_to_sarif_level("INFO") == "note"
    assert _map_risk_level_to_sarif_level("NONE") == "note"
    # Fallback to vulnerability severity if risk is UNKNOWN
    assert _map_risk_level_to_sarif_level("UNKNOWN", "HIGH") == "error"
    assert _map_risk_level_to_sarif_level("UNKNOWN", "MEDIUM") == "warning"
    assert _map_risk_level_to_sarif_level("UNKNOWN", "LOW") == "note"
    assert _map_risk_level_to_sarif_level("UNKNOWN", "UNKNOWN") == "warning"


def test_sarif_minimum_valid_document_and_tool_metadata():
    """Verify minimum valid SARIF 2.1.0 document structure and tool.driver metadata."""
    summary = _make_dummy_summary()
    scan = ExportScan.from_scan_summary(summary)
    doc = export_sarif_dict(scan)

    assert doc["version"] == SARIF_VERSION
    assert doc["$schema"] == SARIF_SCHEMA_URI
    assert len(doc["runs"]) == 1

    driver = doc["runs"][0]["tool"]["driver"]
    assert driver["name"] == "Local Vulnerability AI"
    assert driver["version"] == "0.1.0"
    assert "https://github.com" in driver["informationUri"]
    assert driver["rules"] == []
    assert doc["runs"][0]["results"] == []


def test_sarif_rule_and_result_generation_with_evidence():
    """Verify rule generation, result mapping, and domain property preservation."""
    comp = DetectedComponent(
        name="requests",
        version="2.25.0",
        ecosystem=Ecosystem.PYPI,
        source_file="poetry.lock",
        is_direct=True,
        dependency_type=DependencyType.DIRECT,
        manifest_source="pyproject.toml",
        lockfile_source="poetry.lock",
    )
    vuln = VulnerabilityRecord(
        canonical_id="CVE-2023-32681",
        aliases=["GHSA-j8r2-6x86-q33q"],
        summary="Unintended leak of Proxy-Authorization header in requests",
        description="Requests forwards Proxy-Authorization headers to destination servers.",
        severity="HIGH",
        cvss_score=7.5,
        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:N",
        cwes=["CWE-200"],
        source_name="OSV",
    )
    risk = RiskAssessment(
        status=RiskStatus.LIKELY_AFFECTED,
        risk_level=RiskLevel.HIGH,
        certainty=0.9,
        rationale="Strong match",
        recommended_action="Update package",
        requires_human_review=False,
    )
    evidence = MatchEvidence(
        source_name="OSV",
        identifier="CVE-2023-32681",
        package_name="requests",
        ecosystem="pypi",
        installed_version="2.25.0",
        affected_range="<2.31.0",
        fixed_version="2.31.0",
        status="likely_affected",
        evidence_type="version_range",
        details="Installed 2.25.0 satisfies range <2.31.0",
    )
    match = MatchResult(
        component=comp,
        vulnerability=vuln,
        match_type=MatchType.EXACT_NAME,
        match_confidence=1.0,
        applicability=Applicability.LIKELY_AFFECTED,
        structured_evidences=[evidence],
        risk_assessment=risk,
    )

    summary = _make_dummy_summary(matches=[match])
    scan = ExportScan.from_scan_summary(summary)
    doc = export_sarif_dict(scan)

    rules = doc["runs"][0]["tool"]["driver"]["rules"]
    assert len(rules) == 1
    rule = rules[0]
    assert rule["id"] == "CVE-2023-32681"
    assert rule["properties"]["security-severity"] == "7.5"
    assert rule["properties"]["cvssScore"] == 7.5
    assert rule["properties"]["cwe"] == ["CWE-200"]

    results = doc["runs"][0]["results"]
    assert len(results) == 1
    res = results[0]
    assert res["ruleId"] == "CVE-2023-32681"
    assert res["level"] == "error"  # HIGH maps to error
    assert "requests" in res["message"]["text"]

    # Honest location check: poetry.lock, no fake line 1
    assert len(res["locations"]) == 1
    artifact_loc = res["locations"][0]["physicalLocation"]["artifactLocation"]
    assert artifact_loc["uri"] == "poetry.lock"
    assert "region" not in res["locations"][0]["physicalLocation"]

    # Domain properties preserved
    props = res["properties"]
    assert props["componentName"] == "requests"
    assert props["componentVersion"] == "2.25.0"
    assert props["ecosystem"] == "pypi"
    assert props["dependencyType"] == "direct"
    assert props["applicability"] == "LIKELY_AFFECTED"
    assert props["riskLevel"] == "HIGH"
    assert props["requiresHumanReview"] is False


def test_sarif_requires_review_and_conflict_preservation():
    """Verify REQUIRES_REVIEW and conflict details are preserved in properties."""
    comp = DetectedComponent(
        name="urllib3",
        version="1.26.4",
        ecosystem=Ecosystem.PYPI,
        source_file="requirements.txt",
    )
    vuln = VulnerabilityRecord(
        canonical_id="CVE-2021-33503",
        summary="Catastrophic backtracking in URL authority parser",
        severity="MEDIUM",
        cvss_score=5.3,
        source_name="NVD",
    )
    risk = RiskAssessment(
        status=RiskStatus.REQUIRES_REVIEW,
        risk_level=RiskLevel.MEDIUM,
        certainty=0.5,
        rationale="Discrepancy observed",
        recommended_action="Review advisory manually",
        requires_human_review=True,
    )
    match = MatchResult(
        component=comp,
        vulnerability=vuln,
        match_type=MatchType.EXACT_NAME,
        match_confidence=0.8,
        applicability=Applicability.REQUIRES_REVIEW,
        risk_assessment=risk,
    )

    summary = _make_dummy_summary(matches=[match])
    scan = ExportScan.from_scan_summary(summary)
    doc = export_sarif_dict(scan)

    res = doc["runs"][0]["results"][0]
    assert res["level"] == "warning"
    assert res["properties"]["applicability"] == "REQUIRES_REVIEW"
    assert res["properties"]["requiresHumanReview"] is True


def test_sarif_deduplication_and_deterministic_ordering():
    """Verify multiple findings referencing the same rule and deterministic ordering."""
    comp1 = DetectedComponent(
        name="alpha",
        version="1.0.0",
        ecosystem=Ecosystem.PYPI,
        source_file="manifest.txt",
    )
    comp2 = DetectedComponent(
        name="beta",
        version="2.0.0",
        ecosystem=Ecosystem.PYPI,
        source_file="manifest.txt",
    )
    vuln_b = VulnerabilityRecord(canonical_id="CVE-2024-2222", severity="LOW")
    vuln_a = VulnerabilityRecord(canonical_id="CVE-2024-1111", severity="HIGH")

    m1 = MatchResult(
        component=comp2,
        vulnerability=vuln_b,
        match_type=MatchType.EXACT_NAME,
        match_confidence=1.0,
    )
    m2 = MatchResult(
        component=comp1,
        vulnerability=vuln_a,
        match_type=MatchType.EXACT_NAME,
        match_confidence=1.0,
    )
    m3 = MatchResult(
        component=comp2,
        vulnerability=vuln_a,
        match_type=MatchType.EXACT_NAME,
        match_confidence=1.0,
    )

    summary = _make_dummy_summary(matches=[m1, m2, m3])
    scan = ExportScan.from_scan_summary(summary)
    doc = export_sarif_dict(scan)

    rules = doc["runs"][0]["tool"]["driver"]["rules"]
    assert len(rules) == 2
    # Deterministic rule order: CVE-2024-1111 before CVE-2024-2222
    assert rules[0]["id"] == "CVE-2024-1111"
    assert rules[1]["id"] == "CVE-2024-2222"

    results = doc["runs"][0]["results"]
    assert len(results) == 3
    # 1 Rule, 2 Results for CVE-2024-1111
    assert results[0]["ruleId"] == "CVE-2024-1111"
    assert results[0]["properties"]["componentName"] == "alpha"
    assert results[1]["ruleId"] == "CVE-2024-1111"
    assert results[1]["properties"]["componentName"] == "beta"
    assert results[2]["ruleId"] == "CVE-2024-2222"


def test_sarif_validation_errors():
    """Verify validator flags invalid SARIF structure."""
    with pytest.raises(ExportValidationError, match="SARIF root must be a dictionary"):
        validate_sarif_dict(["not a dict"])  # type: ignore

    with pytest.raises(ExportValidationError, match="Expected SARIF version"):
        validate_sarif_dict({"version": "1.0.0", "$schema": SARIF_SCHEMA_URI, "runs": []})

    with pytest.raises(ExportValidationError, match="Expected SARIF \\$schema"):
        validate_sarif_dict({"version": "2.1.0", "$schema": "bad-schema", "runs": []})

    with pytest.raises(ExportValidationError, match="SARIF 'runs' field must be a list"):
        validate_sarif_dict({"version": "2.1.0", "$schema": SARIF_SCHEMA_URI, "runs": "bad"})

    with pytest.raises(ExportValidationError, match="Each SARIF run must be a dictionary"):
        validate_sarif_dict(
            {"version": "2.1.0", "$schema": SARIF_SCHEMA_URI, "runs": ["not-a-dict"]}
        )

    with pytest.raises(ExportValidationError, match=r"SARIF run must contain 'tool\.driver'"):
        validate_sarif_dict(
            {
                "version": "2.1.0",
                "$schema": SARIF_SCHEMA_URI,
                "runs": [{"tool": {}}],
            }
        )

    with pytest.raises(ExportValidationError, match=r"SARIF tool\.driver must have a 'name'"):
        validate_sarif_dict(
            {
                "version": "2.1.0",
                "$schema": SARIF_SCHEMA_URI,
                "runs": [{"tool": {"driver": {"version": "1.0"}}}],
            }
        )

    with pytest.raises(ExportValidationError, match=r"SARIF tool\.driver must have a 'version'"):
        validate_sarif_dict(
            {
                "version": "2.1.0",
                "$schema": SARIF_SCHEMA_URI,
                "runs": [{"tool": {"driver": {"name": "Tool"}}}],
            }
        )

    with pytest.raises(ExportValidationError, match="SARIF run 'results' must be a list"):
        validate_sarif_dict(
            {
                "version": "2.1.0",
                "$schema": SARIF_SCHEMA_URI,
                "runs": [
                    {"tool": {"driver": {"name": "Tool", "version": "1.0"}}, "results": "bad"}
                ],
            }
        )

    with pytest.raises(ExportValidationError, match="Each SARIF result must have a 'ruleId'"):
        validate_sarif_dict(
            {
                "version": "2.1.0",
                "$schema": SARIF_SCHEMA_URI,
                "runs": [
                    {"tool": {"driver": {"name": "Tool", "version": "1.0"}}, "results": [{}]}
                ],
            }
        )

    with pytest.raises(ExportValidationError, match="Invalid SARIF result level"):
        validate_sarif_dict(
            {
                "version": "2.1.0",
                "$schema": SARIF_SCHEMA_URI,
                "runs": [
                    {
                        "tool": {"driver": {"name": "Tool", "version": "1.0"}},
                        "results": [{"ruleId": "R1", "level": "invalid"}],
                    }
                ],
            }
        )

    with pytest.raises(ExportValidationError, match=r"SARIF result must contain message\.text"):
        validate_sarif_dict(
            {
                "version": "2.1.0",
                "$schema": SARIF_SCHEMA_URI,
                "runs": [
                    {
                        "tool": {"driver": {"name": "Tool", "version": "1.0"}},
                        "results": [{"ruleId": "R1", "level": "error", "message": {}}],
                    }
                ],
            }
        )


def test_export_sarif_json_valid_json_output():
    """Verify export_sarif_json produces parseable JSON string."""
    summary = _make_dummy_summary()
    scan = ExportScan.from_scan_summary(summary)
    json_text = export_sarif_json(scan)

    parsed = json.loads(json_text)
    assert parsed["version"] == "2.1.0"
