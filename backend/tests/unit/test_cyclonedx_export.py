"""Unit tests for CycloneDX 1.5 JSON SBOM exporter (Etapa 15 §45)."""

from __future__ import annotations

import json

import pytest

from vuln_ai.core.graph import (
    DependencyEdge,
    DependencyGraph,
    DependencyNode,
    DependencyScope,
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
from vuln_ai.export.cyclonedx import (
    CYCLONEDX_BOM_FORMAT,
    CYCLONEDX_SPEC_VERSION,
    export_cyclonedx_dict,
    export_cyclonedx_json,
    validate_cyclonedx_dict,
)
from vuln_ai.export.errors import ExportValidationError
from vuln_ai.export.models import ExportScan, generate_purl


def test_purl_generation():
    """Verify package-url generation across PyPI, npm (with and without scope), Cargo, and unknown."""
    # PyPI
    assert generate_purl("pypi", "urllib3", "2.31.0") == "pkg:pypi/urllib3@2.31.0"
    assert generate_purl("pypi", "Flask_RESTful", "0.3.9") == "pkg:pypi/flask-restful@0.3.9"

    # npm unscoped
    assert generate_purl("npm", "lodash", "4.17.21") == "pkg:npm/lodash@4.17.21"

    # npm scoped (%40 encoded)
    assert generate_purl("npm", "@types/node", "20.1.0") == "pkg:npm/%40types/node@20.1.0"

    # Cargo
    assert generate_purl("cargo", "serde", "1.0.104") == "pkg:cargo/serde@1.0.104"

    # Unsupported or missing version
    assert generate_purl("unknown_eco", "foo", "1.0.0") is None
    assert generate_purl("pypi", "requests", None) is None


def test_cyclonedx_minimum_valid_document_and_metadata():
    """Verify CycloneDX 1.5 root fields, tools, and application component."""
    summary = ScanResultSummary(
        project_name="sample-project",
        project_path="/app",
        scan_status=ScanStatus.COMPLETED,
    )
    scan = ExportScan.from_scan_summary(summary)
    doc = export_cyclonedx_dict(scan)

    assert doc["bomFormat"] == CYCLONEDX_BOM_FORMAT
    assert doc["specVersion"] == CYCLONEDX_SPEC_VERSION
    assert doc["serialNumber"].startswith("urn:uuid:")
    assert doc["version"] == 1

    meta = doc["metadata"]
    assert "timestamp" in meta
    assert meta["tools"][0]["name"] == "Local Vulnerability AI"
    assert meta["tools"][0]["version"] == "0.1.0"
    assert meta["component"]["name"] == "sample-project"
    assert meta["component"]["type"] == "application"

    assert doc["components"] == []
    # Root component has empty dependencies list
    assert doc["dependencies"] == [{"ref": "pkg:root/project", "dependsOn": []}]
    assert "vulnerabilities" not in doc


def test_cyclonedx_components_scopes_and_provenance():
    """Verify component details, scopes, purl, and provenance properties."""
    graph = DependencyGraph()
    node1 = DependencyNode.create(
        name="fastapi",
        version="0.100.0",
        ecosystem=Ecosystem.PYPI,
        source_file="poetry.lock",
        is_direct=True,
        scope=DependencyScope.RUNTIME,
        manifest_source="pyproject.toml",
        lockfile_source="poetry.lock",
    )
    node2 = DependencyNode.create(
        name="pytest",
        version="7.4.0",
        ecosystem=Ecosystem.PYPI,
        source_file="poetry.lock",
        is_direct=True,
        scope=DependencyScope.DEV,
        manifest_source="pyproject.toml",
        lockfile_source="poetry.lock",
    )
    graph.add_node(node1)
    graph.add_node(node2)

    summary = ScanResultSummary(
        project_name="api-service",
        project_path="/src",
        scan_status=ScanStatus.COMPLETED,
        dependency_graph=graph,
    )
    scan = ExportScan.from_scan_summary(summary)
    doc = export_cyclonedx_dict(scan)

    components = doc["components"]
    assert len(components) == 2

    # Deterministically ordered: fastapi then pytest
    c1, c2 = components[0], components[1]
    assert c1["name"] == "fastapi"
    assert c1["version"] == "0.100.0"
    assert c1["purl"] == "pkg:pypi/fastapi@0.100.0"
    assert c1["scope"] == "required"  # runtime scope

    assert c2["name"] == "pytest"
    assert c2["scope"] == "optional"  # dev scope

    props = {p["name"]: p["value"] for p in c1["properties"]}
    assert props["vuln_ai:dependency_type"] == "direct"
    assert props["vuln_ai:lockfile_source"] == "poetry.lock"
    assert props["vuln_ai:manifest_source"] == "pyproject.toml"


def test_cyclonedx_dependency_relationships_and_multi_version():
    """Verify representation of dependency topology and multi-version packages."""
    graph = DependencyGraph()
    # Direct parent
    root_dep = DependencyNode.create(
        name="fastapi",
        version="0.100.0",
        ecosystem=Ecosystem.PYPI,
        source_file="poetry.lock",
        is_direct=True,
    )
    # Transitive child
    starlette = DependencyNode.create(
        name="starlette",
        version="0.27.0",
        ecosystem=Ecosystem.PYPI,
        source_file="poetry.lock",
        is_direct=False,
        parent_name="fastapi",
    )
    # Multi-version: another package with version 1.0 and 2.0
    mv1 = DependencyNode.create(
        name="semver",
        version="2.13.0",
        ecosystem=Ecosystem.PYPI,
        source_file="poetry.lock",
        is_direct=False,
    )
    mv2 = DependencyNode.create(
        name="semver",
        version="3.0.0",
        ecosystem=Ecosystem.PYPI,
        source_file="poetry.lock",
        is_direct=False,
    )

    graph.add_node(root_dep)
    graph.add_node(starlette)
    graph.add_node(mv1)
    graph.add_node(mv2)

    edge = DependencyEdge(
        parent_name="fastapi",
        parent_version="0.100.0",
        child_name="starlette",
        child_version="0.27.0",
    )
    graph.add_edge(edge)

    summary = ScanResultSummary(
        project_name="api-service",
        project_path="/src",
        scan_status=ScanStatus.COMPLETED,
        dependency_graph=graph,
    )
    scan = ExportScan.from_scan_summary(summary)
    doc = export_cyclonedx_dict(scan)

    # 4 distinct components resolved
    assert len(doc["components"]) == 4

    deps = {d["ref"]: d["dependsOn"] for d in doc["dependencies"]}
    # Project root depends on direct dependency fastapi
    assert "pkg:pypi/fastapi@0.100.0" in deps["pkg:root/project"]
    # fastapi depends on starlette
    assert "pkg:pypi/starlette@0.27.0" in deps["pkg:pypi/fastapi@0.100.0"]


def test_cyclonedx_vulnerabilities_integration():
    """Verify CycloneDX 1.5 vulnerability findings with ratings and analysis."""
    comp = DetectedComponent(
        name="starlette",
        version="0.27.0",
        ecosystem=Ecosystem.PYPI,
        source_file="poetry.lock",
    )
    vuln = VulnerabilityRecord(
        canonical_id="CVE-2023-38034",
        summary="Denial of service via unbounded form parts in starlette",
        severity="HIGH",
        cvss_score=7.5,
        source_name="OSV",
        source_url="https://osv.dev/vulnerability/GHSA-v5gw-mw7f-84px",
    )
    match = MatchResult(
        component=comp,
        vulnerability=vuln,
        match_type=MatchType.EXACT_NAME,
        match_confidence=1.0,
        applicability=Applicability.LIKELY_AFFECTED,
    )

    summary = ScanResultSummary(
        project_name="demo",
        project_path="/demo",
        scan_status=ScanStatus.COMPLETED,
        matches=[match],
    )
    scan = ExportScan.from_scan_summary(summary)
    doc = export_cyclonedx_dict(scan)

    assert "vulnerabilities" in doc
    vulns = doc["vulnerabilities"]
    assert len(vulns) == 1

    v0 = vulns[0]
    assert v0["id"] == "CVE-2023-38034"
    assert v0["source"]["name"] == "OSV"
    assert v0["ratings"][0]["score"] == 7.5
    assert v0["ratings"][0]["severity"] == "high"
    assert v0["affects"][0]["ref"] == "pkg:pypi/starlette@0.27.0"
    assert v0["analysis"]["state"] == "exploitable"


def test_cyclonedx_validation_errors():
    """Verify schema integrity validations."""
    with pytest.raises(ExportValidationError, match="CycloneDX root must be a dictionary"):
        validate_cyclonedx_dict("invalid")  # type: ignore

    with pytest.raises(ExportValidationError, match="Expected bomFormat"):
        validate_cyclonedx_dict({"bomFormat": "bad", "specVersion": "1.5"})

    with pytest.raises(ExportValidationError, match="Expected specVersion"):
        validate_cyclonedx_dict({"bomFormat": CYCLONEDX_BOM_FORMAT, "specVersion": "1.4"})

    with pytest.raises(ExportValidationError, match="serialNumber must be a valid urn:uuid"):
        validate_cyclonedx_dict(
            {
                "bomFormat": CYCLONEDX_BOM_FORMAT,
                "specVersion": "1.5",
                "serialNumber": "not-a-uuid",
            }
        )

    base_doc = {
        "bomFormat": CYCLONEDX_BOM_FORMAT,
        "specVersion": "1.5",
        "serialNumber": "urn:uuid:6ba7b810-9dad-11d1-80b4-00c04fd430c8",
    }
    with pytest.raises(ExportValidationError, match="CycloneDX 'metadata' must be a dictionary"):
        validate_cyclonedx_dict({**base_doc, "metadata": "bad"})

    with pytest.raises(ExportValidationError, match="CycloneDX metadata must include a timestamp"):
        validate_cyclonedx_dict({**base_doc, "metadata": {}})

    with pytest.raises(
        ExportValidationError, match="CycloneDX metadata must include a tools list"
    ):
        validate_cyclonedx_dict({**base_doc, "metadata": {"timestamp": "2026-10-03T12:00:00Z"}})

    with pytest.raises(ExportValidationError, match="CycloneDX 'components' must be a list"):
        validate_cyclonedx_dict(
            {
                **base_doc,
                "metadata": {"timestamp": "2026-10-03T12:00:00Z", "tools": [{}]},
                "components": "bad",
            }
        )

    with pytest.raises(ExportValidationError, match="Each CycloneDX component must have a 'name'"):
        validate_cyclonedx_dict(
            {
                **base_doc,
                "metadata": {"timestamp": "2026-10-03T12:00:00Z", "tools": [{}]},
                "components": [{}],
            }
        )

    with pytest.raises(ExportValidationError, match="Each CycloneDX component must have a 'type'"):
        validate_cyclonedx_dict(
            {
                **base_doc,
                "metadata": {"timestamp": "2026-10-03T12:00:00Z", "tools": [{}]},
                "components": [{"name": "pkg"}],
            }
        )

    with pytest.raises(
        ExportValidationError, match="Each CycloneDX component must have a 'bom-ref'"
    ):
        validate_cyclonedx_dict(
            {
                **base_doc,
                "metadata": {"timestamp": "2026-10-03T12:00:00Z", "tools": [{}]},
                "components": [{"name": "pkg", "type": "library"}],
            }
        )

    with pytest.raises(ExportValidationError, match="CycloneDX 'dependencies' must be a list"):
        validate_cyclonedx_dict(
            {
                **base_doc,
                "metadata": {"timestamp": "2026-10-03T12:00:00Z", "tools": [{}]},
                "components": [{"name": "pkg", "type": "library", "bom-ref": "ref"}],
                "dependencies": "bad",
            }
        )

    with pytest.raises(
        ExportValidationError, match="CycloneDX dependency item must contain 'ref' and 'dependsOn'"
    ):
        validate_cyclonedx_dict(
            {
                **base_doc,
                "metadata": {"timestamp": "2026-10-03T12:00:00Z", "tools": [{}]},
                "components": [{"name": "pkg", "type": "library", "bom-ref": "ref"}],
                "dependencies": [{}],
            }
        )


def test_cyclonedx_mapping_helpers():
    """Verify mapping functions for applicability and severity."""
    from vuln_ai.export.cyclonedx import _map_applicability_to_cdx_state, _map_severity_to_cdx

    assert _map_applicability_to_cdx_state("LIKELY_NOT_AFFECTED") == "not_affected"
    assert _map_applicability_to_cdx_state("REQUIRES_REVIEW") == "in_triage"
    assert _map_applicability_to_cdx_state("NOT_APPLICABLE") == "false_positive"
    assert _map_applicability_to_cdx_state("UNKNOWN_STATE") == "in_triage"

    assert _map_severity_to_cdx("CUSTOM") == "unknown"
    assert _map_severity_to_cdx("CRITICAL") == "critical"


def test_export_cyclonedx_json():
    """Verify JSON export string."""
    summary = ScanResultSummary(
        project_name="demo",
        project_path="/demo",
        scan_status=ScanStatus.COMPLETED,
    )
    scan = ExportScan.from_scan_summary(summary)
    text = export_cyclonedx_json(scan)
    parsed = json.loads(text)
    assert parsed["bomFormat"] == "CycloneDX"
