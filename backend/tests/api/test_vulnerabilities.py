"""Tests for vulnerabilities API endpoints."""

from __future__ import annotations

from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from vuln_ai.core.models import VulnerabilityRecord
from vuln_ai.db.repositories import SourceRepository, VulnerabilityRepository


async def test_list_and_filter_vulnerabilities(
    api_client: AsyncClient,
    db_session: AsyncSession,
):
    """GET /api/v1/vulnerabilities lists and filters catalog entries."""
    source_repo = SourceRepository(db_session)
    vuln_repo = VulnerabilityRepository(db_session)

    source, _ = await source_repo.get_or_create(name="CISA KEV", source_type="cisa_kev")

    vulns = [
        VulnerabilityRecord(
            cve_id="CVE-2023-1111",
            source_name="CISA KEV",
            vendor_project="Apache",
            product="Tomcat",
            vulnerability_name="Tomcat RCE",
            short_description="Remote code execution in Tomcat",
            required_action="Upgrade to latest version",
            cwes=["CWE-94"],
        ),
        VulnerabilityRecord(
            cve_id="CVE-2024-2222",
            source_name="CISA KEV",
            vendor_project="Microsoft",
            product="Exchange",
            vulnerability_name="Exchange SSRF",
            short_description="Server-side request forgery",
            required_action="Apply security patch",
            cwes=["CWE-918"],
        ),
        VulnerabilityRecord(
            cve_id="CVE-2024-3333",
            source_name="CISA KEV",
            vendor_project="Apache",
            product="HTTP Server",
            vulnerability_name="Apache Path Traversal",
            short_description="Path traversal flaw",
            required_action="Patch immediately",
            cwes=["CWE-22"],
        ),
    ]
    await vuln_repo.upsert_vulnerabilities(source.id, vulns)

    # 1. List all
    res_all = await api_client.get("/api/v1/vulnerabilities?page=1&page_size=10")
    assert res_all.status_code == 200
    assert res_all.json()["total"] == 3

    # 2. Filter by cve
    res_cve = await api_client.get("/api/v1/vulnerabilities?cve=2023-1111")
    assert res_cve.status_code == 200
    assert res_cve.json()["total"] == 1
    assert res_cve.json()["items"][0]["cve_id"] == "CVE-2023-1111"

    # 3. Filter by vendor
    res_vendor = await api_client.get("/api/v1/vulnerabilities?vendor=Apache")
    assert res_vendor.status_code == 200
    assert res_vendor.json()["total"] == 2

    # 4. Filter by product
    res_product = await api_client.get("/api/v1/vulnerabilities?product=Exchange")
    assert res_product.status_code == 200
    assert res_product.json()["total"] == 1
    assert res_product.json()["items"][0]["product"] == "Exchange"

    # 5. Filter by source name
    res_source = await api_client.get("/api/v1/vulnerabilities?source=CISA")
    assert res_source.status_code == 200
    assert res_source.json()["total"] == 3


async def test_get_vulnerability_by_id(
    api_client: AsyncClient,
    db_session: AsyncSession,
):
    """GET /api/v1/vulnerabilities/{id} returns vulnerability details."""
    source_repo = SourceRepository(db_session)
    vuln_repo = VulnerabilityRepository(db_session)

    source, _ = await source_repo.get_or_create(name="CISA KEV", source_type="cisa_kev")
    record = VulnerabilityRecord(
        cve_id="CVE-2024-9876",
        source_name="CISA KEV",
        vendor_project="Linux",
        product="Kernel",
        vulnerability_name="Linux Kernel Privilege Escalation",
        short_description="Privilege escalation via use-after-free",
        required_action="Apply distribution updates",
        cwes=["CWE-416"],
    )
    await vuln_repo.upsert_vulnerabilities(source.id, [record])
    db_vulns = await vuln_repo.get_by_cve("CVE-2024-9876")
    vuln_id = db_vulns[0].id

    response = await api_client.get(f"/api/v1/vulnerabilities/{vuln_id}")
    assert response.status_code == 200
    data = response.json()
    assert data["id"] == vuln_id
    assert data["cve_id"] == "CVE-2024-9876"
    assert data["vendor_project"] == "Linux"
    assert data["product"] == "Kernel"
    assert data["cwes"] == ["CWE-416"]


async def test_get_vulnerability_not_found(api_client: AsyncClient):
    """GET /api/v1/vulnerabilities/{missing} returns 404."""
    response = await api_client.get("/api/v1/vulnerabilities/missing-uuid")
    assert response.status_code == 404
    assert response.json()["error"]["code"] == "VULNERABILITY_NOT_FOUND"
