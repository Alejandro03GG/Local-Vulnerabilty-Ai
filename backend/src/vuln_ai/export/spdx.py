"""SPDX 2.3 JSON SBOM exporter for Local Vulnerability AI.

Generates deterministic, compliant SPDX 2.3 SBOM documents with
Package Download Location, NOASSERTION licenses, PURL references,
and formal DEPENDS_ON relationship topology.
"""

from __future__ import annotations

import json
import uuid
from typing import Any

from vuln_ai.export.errors import ExportValidationError
from vuln_ai.export.models import ExportScan

SPDX_VERSION = "SPDX-2.3"
DATA_LICENSE = "CC0-1.0"
DOCUMENT_SPDXID = "SPDXRef-DOCUMENT"
ROOT_PACKAGE_SPDXID = "SPDXRef-RootPackage"


def validate_spdx_dict(doc: dict[str, Any]) -> None:
    """Validate that dictionary conforms to SPDX 2.3 JSON core structure."""
    if not isinstance(doc, dict):
        raise ExportValidationError("SPDX root must be a dictionary")
    if doc.get("spdxVersion") != SPDX_VERSION:
        raise ExportValidationError(
            f"Expected spdxVersion '{SPDX_VERSION}', got '{doc.get('spdxVersion')}'"
        )
    if doc.get("dataLicense") != DATA_LICENSE:
        raise ExportValidationError(
            f"Expected dataLicense '{DATA_LICENSE}', got '{doc.get('dataLicense')}'"
        )
    if doc.get("SPDXID") != DOCUMENT_SPDXID:
        raise ExportValidationError(
            f"Expected SPDXID '{DOCUMENT_SPDXID}', got '{doc.get('SPDXID')}'"
        )
    if not doc.get("name"):
        raise ExportValidationError("SPDX document must have a 'name'")
    if not doc.get("documentNamespace"):
        raise ExportValidationError("SPDX document must have a 'documentNamespace'")

    creation_info = doc.get("creationInfo")
    if not isinstance(creation_info, dict):
        raise ExportValidationError("SPDX 'creationInfo' must be a dictionary")
    if not creation_info.get("created"):
        raise ExportValidationError("SPDX creationInfo must have 'created' timestamp")
    if not creation_info.get("creators") or not isinstance(creation_info["creators"], list):
        raise ExportValidationError("SPDX creationInfo must have 'creators' list")

    packages = doc.get("packages")
    if not isinstance(packages, list):
        raise ExportValidationError("SPDX 'packages' must be a list")
    for pkg in packages:
        if not pkg.get("name"):
            raise ExportValidationError("Each SPDX package must have a 'name'")
        if not pkg.get("SPDXID") or not str(pkg["SPDXID"]).startswith("SPDXRef-"):
            raise ExportValidationError("Each SPDX package must have a valid 'SPDXID'")
        if "downloadLocation" not in pkg:
            raise ExportValidationError("Each SPDX package must have 'downloadLocation'")
        if "filesAnalyzed" not in pkg:
            raise ExportValidationError("Each SPDX package must specify 'filesAnalyzed'")

    relationships = doc.get("relationships")
    if not isinstance(relationships, list):
        raise ExportValidationError("SPDX 'relationships' must be a list")
    for rel in relationships:
        if (
            not rel.get("spdxElementId")
            or not rel.get("relationshipType")
            or not rel.get("relatedSpdxElement")
        ):
            raise ExportValidationError(
                "Each SPDX relationship must specify spdxElementId, relationshipType, and relatedSpdxElement"
            )


def export_spdx_dict(scan: ExportScan) -> dict[str, Any]:
    """Generate SPDX 2.3 dictionary representation from canonical ExportScan."""
    namespace_uuid = uuid.UUID("6ba7b810-9dad-11d1-80b4-00c04fd430c8")
    doc_uuid = uuid.uuid5(namespace_uuid, f"spdx:{scan.project_name}:{scan.scan_id}")
    doc_namespace = f"https://spdx.org/spdxdocs/{scan.project_name}-{doc_uuid}"

    # 1. Packages
    packages: list[dict[str, Any]] = []

    # Root application/container package
    is_container = bool(scan.metadata.get("container_image"))
    root_pkg: dict[str, Any] = {
        "name": scan.project_name.removeprefix("container:"),
        "SPDXID": ROOT_PACKAGE_SPDXID,
        "downloadLocation": "NOASSERTION",
        "filesAnalyzed": False,
        "licenseConcluded": "NOASSERTION",
        "licenseDeclared": "NOASSERTION",
        "copyrightText": "NOASSERTION",
        "primaryPackagePurpose": "CONTAINER" if is_container else "APPLICATION",
    }
    if scan.metadata.get("container_digest"):
        root_pkg["versionInfo"] = scan.metadata["container_digest"]
    packages.append(root_pkg)

    # Component packages
    comp_by_ref = {c.bom_ref: c for c in scan.components}
    for c in sorted(
        scan.components,
        key=lambda x: (x.ecosystem.lower(), x.name.lower(), x.version or ""),
    ):
        pkg_item: dict[str, Any] = {
            "name": c.name,
            "SPDXID": c.spdx_id,
            "versionInfo": c.version or "NOASSERTION",
            "downloadLocation": "NOASSERTION",
            "filesAnalyzed": False,
            "licenseConcluded": c.license_concluded,
            "licenseDeclared": c.license_declared,
            "copyrightText": "NOASSERTION",
            "primaryPackagePurpose": "LIBRARY",
        }
        if c.purl:
            pkg_item["externalRefs"] = [
                {
                    "referenceCategory": "PACKAGE-MANAGER",
                    "referenceType": "purl",
                    "referenceLocator": c.purl,
                }
            ]

        packages.append(pkg_item)

    # 2. Relationships
    relationships: set[tuple[str, str, str]] = set()

    # Document describes Root
    relationships.add((DOCUMENT_SPDXID, "DESCRIBES", ROOT_PACKAGE_SPDXID))

    # Root depends on all direct dependencies
    for c in scan.components:
        if c.is_direct:
            relationships.add((ROOT_PACKAGE_SPDXID, "DEPENDS_ON", c.spdx_id))

    # Graph edge dependencies
    for d in scan.dependencies:
        p_comp = comp_by_ref.get(d.parent_ref)
        c_comp = comp_by_ref.get(d.child_ref)
        if p_comp and c_comp:
            relationships.add((p_comp.spdx_id, "DEPENDS_ON", c_comp.spdx_id))

    sorted_relationships: list[dict[str, str]] = [
        {
            "spdxElementId": rel[0],
            "relationshipType": rel[1],
            "relatedSpdxElement": rel[2],
        }
        for rel in sorted(relationships, key=lambda r: (r[0], r[1], r[2]))
    ]

    doc: dict[str, Any] = {
        "spdxVersion": SPDX_VERSION,
        "dataLicense": DATA_LICENSE,
        "SPDXID": DOCUMENT_SPDXID,
        "name": scan.project_name,
        "documentNamespace": doc_namespace,
        "creationInfo": {
            "created": scan.generated_at,
            "creators": [f"Tool: {scan.tool_name}-{scan.tool_version}"],
        },
        "packages": packages,
        "relationships": sorted_relationships,
    }

    validate_spdx_dict(doc)
    return doc


def export_spdx_json(scan: ExportScan, indent: int = 2) -> str:
    """Generate pretty-printed SPDX 2.3 JSON text."""
    doc = export_spdx_dict(scan)
    return json.dumps(doc, indent=indent, ensure_ascii=False)
