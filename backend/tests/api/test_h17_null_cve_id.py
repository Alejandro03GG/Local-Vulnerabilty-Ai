"""H17 regression: advisories without CVE must serialize through API without HTTP 500."""

from __future__ import annotations

from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from vuln_ai.core.models import (
    Applicability,
    DetectedComponent,
    Ecosystem,
    EvidenceType,
    MatchEvidence,
    MatchResult,
    MatchType,
    VulnerabilityIdentifier,
    VulnerabilityRecord,
    VulnerabilitySourceRecord,
)
from vuln_ai.db.repositories import (
    ComponentRepository,
    MatchRepository,
    ProjectRepository,
    ScanRepository,
    SourceRepository,
    VulnerabilityRepository,
)


async def _seed_advisory_with_match(
    db_session: AsyncSession,
    *,
    canonical_id: str,
    cve_id: str | None,
    identifier_type: str,
) -> tuple[str, str, str]:
    """Insert vulnerability + match. Returns (vuln_id, match_id, scan_id)."""
    source_repo = SourceRepository(db_session)
    vuln_repo = VulnerabilityRepository(db_session)
    project_repo = ProjectRepository(db_session)
    scan_repo = ScanRepository(db_session)
    component_repo = ComponentRepository(db_session)
    match_repo = MatchRepository(db_session)

    source, _ = await source_repo.get_or_create(name="OSV", source_type="osv")
    record = VulnerabilityRecord(
        canonical_id=canonical_id,
        cve_id=cve_id,
        source_name="OSV",
        vendor_project="example",
        product="pkg",
        vulnerability_name=f"Advisory {canonical_id}",
        short_description="Advisory without mandatory CVE",
        required_action="Upgrade",
        identifiers=[
            VulnerabilityIdentifier(identifier_type=identifier_type, identifier=canonical_id)
        ],
        source_records=[
            VulnerabilitySourceRecord(
                source_name="OSV",
                source_identifier=canonical_id,
                raw_payload={"id": canonical_id},
            )
        ],
    )
    await vuln_repo.upsert_vulnerabilities(source.id, [record])
    db_vuln = await vuln_repo.get_by_identifier(canonical_id)
    assert db_vuln is not None
    vuln_id = db_vuln.id

    project = await project_repo.create(
        name=f"h17-{canonical_id}",
        path=f"/tmp/h17/{canonical_id}",
    )
    scan = await scan_repo.create(project.id)
    await scan_repo.complete(scan.id, components_found=1, vulnerabilities_found=1)

    component = DetectedComponent(
        name="pkg",
        version="1.0.0",
        ecosystem=Ecosystem.PYPI,
        source_file="requirements.txt",
    )
    comps_db = await component_repo.save_components(project.id, [component])

    evidence = MatchEvidence(
        source_name="OSV",
        identifier=canonical_id,
        package_name="pkg",
        ecosystem=Ecosystem.PYPI,
        installed_version="1.0.0",
        status=Applicability.LIKELY_AFFECTED,
        evidence_type=EvidenceType.RANGE_CONFIRMED,
        details="Range match",
    )
    match_res = MatchResult(
        component=component,
        vulnerability=record,
        match_type=MatchType.EXACT_NAME,
        match_confidence=0.9,
        applicability=Applicability.LIKELY_AFFECTED,
        structured_evidences=[evidence],
    )
    saved = await match_repo.save_matches(
        scan_id=scan.id,
        matches=[match_res],
        component_id_map={"pkg": comps_db[0].id},
        vulnerability_id_map={canonical_id: vuln_id},
    )
    assert len(saved) == 1
    return vuln_id, saved[0].id, scan.id


async def test_h17_list_and_get_ghsa_only_vulnerability(
    api_client: AsyncClient,
    db_session: AsyncSession,
) -> None:
    """GHSA-only advisory: cve_id null must return 200 with canonical_id."""
    vuln_id, _match_id, _scan_id = await _seed_advisory_with_match(
        db_session,
        canonical_id="GHSA-xxxx-yyyy-zzzz",
        cve_id=None,
        identifier_type="GHSA",
    )

    list_res = await api_client.get("/api/v1/vulnerabilities?page=1&page_size=50")
    assert list_res.status_code == 200, list_res.text
    items = list_res.json()["items"]
    found = next(i for i in items if i["id"] == vuln_id)
    assert found["cve_id"] is None
    assert found["canonical_id"] == "GHSA-xxxx-yyyy-zzzz"

    detail = await api_client.get(f"/api/v1/vulnerabilities/{vuln_id}")
    assert detail.status_code == 200, detail.text
    body = detail.json()
    assert body["cve_id"] is None
    assert body["canonical_id"] == "GHSA-xxxx-yyyy-zzzz"


async def test_h17_match_list_and_detail_with_null_cve(
    api_client: AsyncClient,
    db_session: AsyncSession,
) -> None:
    """Matches embedding null-CVE vulns must not 500 (Scan Detail / Matches UI path)."""
    vuln_id, match_id, scan_id = await _seed_advisory_with_match(
        db_session,
        canonical_id="GHSA-abcd-efgh-ijkl",
        cve_id=None,
        identifier_type="GHSA",
    )

    scan_res = await api_client.get(f"/api/v1/scans/{scan_id}")
    assert scan_res.status_code == 200, scan_res.text

    matches_res = await api_client.get(f"/api/v1/matches?scan_id={scan_id}")
    assert matches_res.status_code == 200, matches_res.text
    payload = matches_res.json()
    assert payload["total"] >= 1
    embedded = payload["items"][0]["vulnerability"]
    assert embedded is not None
    assert embedded["cve_id"] is None
    assert embedded["canonical_id"] == "GHSA-abcd-efgh-ijkl"
    assert embedded["id"] == vuln_id

    match_detail = await api_client.get(f"/api/v1/matches/{match_id}")
    assert match_detail.status_code == 200, match_detail.text
    assert match_detail.json()["vulnerability"]["cve_id"] is None


async def test_h17_rustsec_only_and_cve_present(
    api_client: AsyncClient,
    db_session: AsyncSession,
) -> None:
    """RUSTSEC-only and CVE-present advisories both serialize cleanly in one catalog batch."""
    source_repo = SourceRepository(db_session)
    vuln_repo = VulnerabilityRepository(db_session)
    source, _ = await source_repo.get_or_create(name="OSV", source_type="osv")
    records = [
        VulnerabilityRecord(
            canonical_id="RUSTSEC-2024-0001",
            cve_id=None,
            source_name="OSV",
            product="pkg-a",
            vulnerability_name="RUSTSEC only",
            identifiers=[
                VulnerabilityIdentifier(identifier_type="OTHER", identifier="RUSTSEC-2024-0001")
            ],
            source_records=[
                VulnerabilitySourceRecord(
                    source_name="OSV",
                    source_identifier="RUSTSEC-2024-0001",
                    raw_payload={"id": "RUSTSEC-2024-0001"},
                )
            ],
        ),
        VulnerabilityRecord(
            canonical_id="CVE-2024-9999",
            cve_id="CVE-2024-9999",
            source_name="OSV",
            product="pkg-b",
            vulnerability_name="CVE present",
            identifiers=[
                VulnerabilityIdentifier(identifier_type="CVE", identifier="CVE-2024-9999")
            ],
            source_records=[
                VulnerabilitySourceRecord(
                    source_name="OSV",
                    source_identifier="CVE-2024-9999",
                    raw_payload={"id": "CVE-2024-9999"},
                )
            ],
        ),
    ]
    await vuln_repo.upsert_vulnerabilities(source.id, records)
    rustsec_db = await vuln_repo.get_by_identifier("RUSTSEC-2024-0001")
    cve_db = await vuln_repo.get_by_identifier("CVE-2024-9999")
    assert rustsec_db is not None and cve_db is not None

    rustsec = (await api_client.get(f"/api/v1/vulnerabilities/{rustsec_db.id}")).json()
    assert rustsec.get("cve_id") is None
    assert rustsec["canonical_id"] == "RUSTSEC-2024-0001"

    cve = (await api_client.get(f"/api/v1/vulnerabilities/{cve_db.id}")).json()
    assert cve.get("cve_id") == "CVE-2024-9999"
    assert cve["canonical_id"] == "CVE-2024-9999"
