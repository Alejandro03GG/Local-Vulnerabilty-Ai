"""Unit tests for SPDX 2.3 JSON SBOM exporter (Etapa 15 §46)."""

from __future__ import annotations

import json

import pytest

from vuln_ai.core.graph import (
    DependencyEdge,
    DependencyGraph,
    DependencyNode,
)
from vuln_ai.core.models import (
    Ecosystem,
    ScanResultSummary,
    ScanStatus,
)
from vuln_ai.export.errors import ExportValidationError
from vuln_ai.export.models import ExportScan, sanitize_spdx_id
from vuln_ai.export.spdx import (
    DATA_LICENSE,
    DOCUMENT_SPDXID,
    ROOT_PACKAGE_SPDXID,
    SPDX_VERSION,
    export_spdx_dict,
    export_spdx_json,
    validate_spdx_dict,
)


def test_sanitize_spdx_id():
    """Verify SPDXID sanitization complies with ^[a-zA-Z0-9.-]+$."""
    assert sanitize_spdx_id("pypi_requests_2.31.0") == "SPDXRef-pypi-requests-2.31.0"
    assert sanitize_spdx_id("@scope/pkg@1.0.0") == "SPDXRef-scope-pkg-1.0.0"
    assert sanitize_spdx_id("invalid!chars#here") == "SPDXRef-invalid-chars-here"
    assert sanitize_spdx_id("---") == "SPDXRef-unknown"


def test_spdx_minimum_valid_document():
    """Verify SPDX 2.3 mandatory document fields and root package creation."""
    summary = ScanResultSummary(
        project_name="spdx-demo",
        project_path="/spdx-demo",
        scan_status=ScanStatus.COMPLETED,
    )
    scan = ExportScan.from_scan_summary(summary)
    doc = export_spdx_dict(scan)

    assert doc["spdxVersion"] == SPDX_VERSION
    assert doc["dataLicense"] == DATA_LICENSE
    assert doc["SPDXID"] == DOCUMENT_SPDXID
    assert doc["name"] == "spdx-demo"
    assert "https://spdx.org/spdxdocs/" in doc["documentNamespace"]

    creation = doc["creationInfo"]
    assert "created" in creation
    assert any("Local Vulnerability AI" in c for c in creation["creators"])

    # Root package
    packages = doc["packages"]
    assert len(packages) == 1
    root = packages[0]
    assert root["SPDXID"] == ROOT_PACKAGE_SPDXID
    assert root["name"] == "spdx-demo"
    assert root["downloadLocation"] == "NOASSERTION"
    assert root["licenseConcluded"] == "NOASSERTION"
    assert root["filesAnalyzed"] is False

    # Root relationship
    assert doc["relationships"] == [
        {
            "spdxElementId": DOCUMENT_SPDXID,
            "relationshipType": "DESCRIBES",
            "relatedSpdxElement": ROOT_PACKAGE_SPDXID,
        }
    ]


def test_spdx_packages_purl_and_relationships():
    """Verify packages, PURL external refs, and DEPENDS_ON relationship topology."""
    graph = DependencyGraph()
    parent_node = DependencyNode.create(
        name="fastapi",
        version="0.100.0",
        ecosystem=Ecosystem.PYPI,
        source_file="poetry.lock",
        is_direct=True,
    )
    child_node = DependencyNode.create(
        name="pydantic",
        version="2.0.0",
        ecosystem=Ecosystem.PYPI,
        source_file="poetry.lock",
        is_direct=False,
    )
    graph.add_node(parent_node)
    graph.add_node(child_node)

    edge = DependencyEdge(
        parent_name="fastapi",
        parent_version="0.100.0",
        child_name="pydantic",
        child_version="2.0.0",
    )
    graph.add_edge(edge)

    summary = ScanResultSummary(
        project_name="app",
        project_path="/app",
        scan_status=ScanStatus.COMPLETED,
        dependency_graph=graph,
    )
    scan = ExportScan.from_scan_summary(summary)
    doc = export_spdx_dict(scan)

    packages = doc["packages"]
    assert len(packages) == 3  # Root + 2 packages

    fastapi_pkg = next(p for p in packages if p["name"] == "fastapi")
    assert fastapi_pkg["versionInfo"] == "0.100.0"
    assert fastapi_pkg["downloadLocation"] == "NOASSERTION"
    assert fastapi_pkg["licenseConcluded"] == "NOASSERTION"
    assert fastapi_pkg["externalRefs"][0]["referenceLocator"] == "pkg:pypi/fastapi@0.100.0"

    pydantic_pkg = next(p for p in packages if p["name"] == "pydantic")
    assert pydantic_pkg["versionInfo"] == "2.0.0"

    rels = doc["relationships"]
    rel_tuples = [
        (r["spdxElementId"], r["relationshipType"], r["relatedSpdxElement"]) for r in rels
    ]

    # Document DESCRIBES Root
    assert (DOCUMENT_SPDXID, "DESCRIBES", ROOT_PACKAGE_SPDXID) in rel_tuples
    # Root DEPENDS_ON fastapi (direct)
    assert (ROOT_PACKAGE_SPDXID, "DEPENDS_ON", fastapi_pkg["SPDXID"]) in rel_tuples
    # fastapi DEPENDS_ON pydantic
    assert (fastapi_pkg["SPDXID"], "DEPENDS_ON", pydantic_pkg["SPDXID"]) in rel_tuples


def test_spdx_validation_errors():
    """Verify validation of invalid SPDX structures."""
    with pytest.raises(ExportValidationError, match="SPDX root must be a dictionary"):
        validate_spdx_dict("bad")  # type: ignore

    with pytest.raises(ExportValidationError, match="Expected spdxVersion"):
        validate_spdx_dict({"spdxVersion": "SPDX-2.2"})

    with pytest.raises(ExportValidationError, match="Expected dataLicense"):
        validate_spdx_dict({"spdxVersion": SPDX_VERSION, "dataLicense": "MIT"})

    with pytest.raises(ExportValidationError, match="Expected SPDXID"):
        validate_spdx_dict(
            {
                "spdxVersion": SPDX_VERSION,
                "dataLicense": DATA_LICENSE,
                "SPDXID": "bad",
            }
        )

    base_doc = {
        "spdxVersion": SPDX_VERSION,
        "dataLicense": DATA_LICENSE,
        "SPDXID": DOCUMENT_SPDXID,
    }

    with pytest.raises(ExportValidationError, match="SPDX document must have a 'name'"):
        validate_spdx_dict({**base_doc})

    with pytest.raises(
        ExportValidationError, match="SPDX document must have a 'documentNamespace'"
    ):
        validate_spdx_dict({**base_doc, "name": "project"})

    with pytest.raises(ExportValidationError, match="SPDX 'creationInfo' must be a dictionary"):
        validate_spdx_dict(
            {
                **base_doc,
                "name": "project",
                "documentNamespace": "https://spdx.org/test",
                "creationInfo": "bad",
            }
        )

    with pytest.raises(
        ExportValidationError, match="SPDX creationInfo must have 'created' timestamp"
    ):
        validate_spdx_dict(
            {
                **base_doc,
                "name": "project",
                "documentNamespace": "https://spdx.org/test",
                "creationInfo": {},
            }
        )

    with pytest.raises(ExportValidationError, match="SPDX creationInfo must have 'creators' list"):
        validate_spdx_dict(
            {
                **base_doc,
                "name": "project",
                "documentNamespace": "https://spdx.org/test",
                "creationInfo": {"created": "2026-10-03T12:00:00Z"},
            }
        )

    with pytest.raises(ExportValidationError, match="SPDX 'packages' must be a list"):
        validate_spdx_dict(
            {
                **base_doc,
                "name": "project",
                "documentNamespace": "https://spdx.org/test",
                "creationInfo": {"created": "2026-10-03T12:00:00Z", "creators": ["Tool: vuln_ai"]},
                "packages": "bad",
            }
        )

    with pytest.raises(ExportValidationError, match="Each SPDX package must have a 'name'"):
        validate_spdx_dict(
            {
                **base_doc,
                "name": "project",
                "documentNamespace": "https://spdx.org/test",
                "creationInfo": {"created": "2026-10-03T12:00:00Z", "creators": ["Tool: vuln_ai"]},
                "packages": [{}],
            }
        )

    with pytest.raises(
        ExportValidationError, match="Each SPDX package must have a valid 'SPDXID'"
    ):
        validate_spdx_dict(
            {
                **base_doc,
                "name": "project",
                "documentNamespace": "https://spdx.org/test",
                "creationInfo": {"created": "2026-10-03T12:00:00Z", "creators": ["Tool: vuln_ai"]},
                "packages": [{"name": "pkg", "SPDXID": "invalid"}],
            }
        )

    with pytest.raises(
        ExportValidationError, match="Each SPDX package must have 'downloadLocation'"
    ):
        validate_spdx_dict(
            {
                **base_doc,
                "name": "project",
                "documentNamespace": "https://spdx.org/test",
                "creationInfo": {"created": "2026-10-03T12:00:00Z", "creators": ["Tool: vuln_ai"]},
                "packages": [{"name": "pkg", "SPDXID": "SPDXRef-pkg"}],
            }
        )

    with pytest.raises(
        ExportValidationError, match="Each SPDX package must specify 'filesAnalyzed'"
    ):
        validate_spdx_dict(
            {
                **base_doc,
                "name": "project",
                "documentNamespace": "https://spdx.org/test",
                "creationInfo": {"created": "2026-10-03T12:00:00Z", "creators": ["Tool: vuln_ai"]},
                "packages": [
                    {"name": "pkg", "SPDXID": "SPDXRef-pkg", "downloadLocation": "NOASSERTION"}
                ],
            }
        )

    with pytest.raises(ExportValidationError, match="SPDX 'relationships' must be a list"):
        validate_spdx_dict(
            {
                **base_doc,
                "name": "project",
                "documentNamespace": "https://spdx.org/test",
                "creationInfo": {"created": "2026-10-03T12:00:00Z", "creators": ["Tool: vuln_ai"]},
                "packages": [
                    {
                        "name": "pkg",
                        "SPDXID": "SPDXRef-pkg",
                        "downloadLocation": "NOASSERTION",
                        "filesAnalyzed": False,
                    }
                ],
                "relationships": "bad",
            }
        )

    with pytest.raises(
        ExportValidationError, match="Each SPDX relationship must specify spdxElementId"
    ):
        validate_spdx_dict(
            {
                **base_doc,
                "name": "project",
                "documentNamespace": "https://spdx.org/test",
                "creationInfo": {"created": "2026-10-03T12:00:00Z", "creators": ["Tool: vuln_ai"]},
                "packages": [
                    {
                        "name": "pkg",
                        "SPDXID": "SPDXRef-pkg",
                        "downloadLocation": "NOASSERTION",
                        "filesAnalyzed": False,
                    }
                ],
                "relationships": [{}],
            }
        )


def test_export_spdx_json():
    """Verify JSON export string."""
    summary = ScanResultSummary(
        project_name="app",
        project_path="/app",
        scan_status=ScanStatus.COMPLETED,
    )
    scan = ExportScan.from_scan_summary(summary)
    text = export_spdx_json(scan)
    parsed = json.loads(text)
    assert parsed["spdxVersion"] == "SPDX-2.3"
