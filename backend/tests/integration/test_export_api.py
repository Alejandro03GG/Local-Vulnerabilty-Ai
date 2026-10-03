"""Integration tests for Scan export API endpoints (Etapa 15 §36, §37)."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from vuln_ai.core.models import VulnerabilityRecord
from vuln_ai.db.repositories import SourceRepository, VulnerabilityRepository


@pytest.mark.asyncio
async def test_scan_export_api_endpoints(
    api_client: AsyncClient,
    db_session: AsyncSession,
    sample_project_dir: Path,
):
    """Test SARIF, CycloneDX, and SPDX export REST API endpoints."""
    # Seed vulnerabilities
    source_repo = SourceRepository(db_session)
    vuln_repo = VulnerabilityRepository(db_session)
    source, _ = await source_repo.get_or_create(name="CISA KEV", source_type="cisa_kev")

    await vuln_repo.upsert_vulnerabilities(
        source.id,
        [
            VulnerabilityRecord(
                cve_id="CVE-2024-2000",
                source_name="CISA KEV",
                vendor_project="requests",
                product="requests",
                vulnerability_name="Requests header leak",
                short_description="Header leak vulnerability",
            )
        ],
    )

    # Register project
    proj_res = await api_client.post(
        "/api/v1/projects",
        json={"name": "export-target", "path": str(sample_project_dir)},
    )
    proj_id = proj_res.json()["id"]

    # Trigger scan
    scan_res = await api_client.post(
        f"/api/v1/projects/{proj_id}/scans",
        json={"run_ai": False},
    )
    assert scan_res.status_code == 201
    scan_id = scan_res.json()["id"]

    # 1. Export SARIF
    sarif_res = await api_client.get(f"/api/v1/scans/{scan_id}/export/sarif")
    assert sarif_res.status_code == 200
    assert "application/sarif+json" in sarif_res.headers["content-type"]
    assert "attachment" in sarif_res.headers["content-disposition"]
    sarif_doc = json.loads(sarif_res.text)
    assert sarif_doc["version"] == "2.1.0"
    assert sarif_doc["runs"][0]["tool"]["driver"]["name"] == "Local Vulnerability AI"

    # 2. Export CycloneDX
    cdx_res = await api_client.get(f"/api/v1/scans/{scan_id}/export/cyclonedx")
    assert cdx_res.status_code == 200
    assert "application/vnd.cyclonedx+json" in cdx_res.headers["content-type"]
    assert "attachment" in cdx_res.headers["content-disposition"]
    cdx_doc = json.loads(cdx_res.text)
    assert cdx_doc["bomFormat"] == "CycloneDX"
    assert cdx_doc["specVersion"] == "1.5"

    # 3. Export SPDX
    spdx_res = await api_client.get(f"/api/v1/scans/{scan_id}/export/spdx")
    assert spdx_res.status_code == 200
    assert "application/spdx+json" in spdx_res.headers["content-type"]
    assert "attachment" in spdx_res.headers["content-disposition"]
    spdx_doc = json.loads(spdx_res.text)
    assert spdx_doc["spdxVersion"] == "SPDX-2.3"
    assert spdx_doc["dataLicense"] == "CC0-1.0"

    # 4. Non-existent scan ID
    bad_res = await api_client.get("/api/v1/scans/non-existent-scan/export/sarif")
    assert bad_res.status_code == 404
