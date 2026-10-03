"""Tests for multi-source intelligence models and repository methods."""

from __future__ import annotations

import pytest
from sqlalchemy.ext.asyncio import AsyncSession

from vuln_ai.core.models import (
    AffectedVersionRange,
    Applicability,
    DetectedComponent,
    Ecosystem,
    EvidenceType,
    IdentifierType,
    MatchEvidence,
    MatchResult,
    MatchType,
    VulnerabilityIdentifier,
    VulnerabilityRecord,
)
from vuln_ai.db.repositories import (
    MatchRepository,
    ProjectRepository,
    ScanRepository,
    SourceRepository,
    VulnerabilityRepository,
)


def test_vulnerability_record_canonical_and_cve_coherence():
    """Verify that canonical_id and cve_id work seamlessly together."""
    # 1. Backwards compatible initialization with cve_id
    rec_cve = VulnerabilityRecord(
        cve_id="CVE-2024-1234",
        source_name="CISA KEV",
        vendor_project="Apache",
        product="Tomcat",
    )
    assert rec_cve.canonical_id == "CVE-2024-1234"
    assert rec_cve.cve_id == "CVE-2024-1234"
    assert len(rec_cve.identifiers) == 1
    assert rec_cve.identifiers[0].identifier == "CVE-2024-1234"
    assert rec_cve.identifiers[0].identifier_type == IdentifierType.CVE

    # 2. Modern non-CVE initialization with GHSA canonical_id
    rec_ghsa = VulnerabilityRecord(
        canonical_id="GHSA-1234-5678-90ab",
        source_name="OSV",
        vendor_project="pallets",
        product="flask",
    )
    assert rec_ghsa.canonical_id == "GHSA-1234-5678-90ab"
    assert rec_ghsa.cve_id is None
    assert len(rec_ghsa.identifiers) == 1
    assert rec_ghsa.identifiers[0].identifier == "GHSA-1234-5678-90ab"
    assert rec_ghsa.identifiers[0].identifier_type == IdentifierType.GHSA

    # 3. Both canonical_id and secondary identifiers provided
    rec_multi = VulnerabilityRecord(
        canonical_id="CVE-2024-5555",
        identifiers=[
            VulnerabilityIdentifier(
                identifier="CVE-2024-5555", identifier_type=IdentifierType.CVE, source="NVD"
            ),
            VulnerabilityIdentifier(
                identifier="GHSA-9999-xxxx", identifier_type=IdentifierType.GHSA, source="OSV"
            ),
        ],
        affected_ranges=[
            AffectedVersionRange(
                ecosystem=Ecosystem.PYPI,
                package_name="requests",
                introduced="2.0.0",
                fixed="2.32.0",
                raw_range=">= 2.0.0, < 2.32.0",
                source_name="OSV",
            )
        ],
    )
    assert rec_multi.canonical_id == "CVE-2024-5555"
    assert rec_multi.cve_id == "CVE-2024-5555"
    assert len(rec_multi.identifiers) == 2
    assert len(rec_multi.affected_ranges) == 1
    assert rec_multi.affected_ranges[0].package_name == "requests"


def test_match_evidence_structured_model():
    """Verify MatchEvidence structure and MatchResult integration."""
    ev = MatchEvidence(
        source_name="OSV",
        identifier="CVE-2024-1234",
        package_name="requests",
        ecosystem=Ecosystem.PYPI,
        installed_version="2.31.0",
        affected_range="< 2.32.0",
        fixed_version="2.32.0",
        status=Applicability.LIKELY_AFFECTED,
        evidence_type=EvidenceType.RANGE_CONFIRMED,
        details="Installed 2.31.0 is less than fixed 2.32.0",
    )
    assert ev.source_name == "OSV"
    assert ev.installed_version == "2.31.0"
    assert ev.status == Applicability.LIKELY_AFFECTED

    comp = DetectedComponent(
        name="requests",
        version="2.31.0",
        ecosystem=Ecosystem.PYPI,
        source_file="requirements.txt",
    )
    vuln = VulnerabilityRecord(
        canonical_id="CVE-2024-1234",
        product="requests",
        vendor_project="psf",
    )
    match = MatchResult(
        component=comp,
        vulnerability=vuln,
        match_type=MatchType.EXACT_NAME,
        match_confidence=1.0,
        applicability=Applicability.LIKELY_AFFECTED,
        structured_evidences=[ev],
    )
    # Check that legacy string evidence is auto-rendered
    assert len(match.evidence) == 1
    assert "[OSV] CVE-2024-1234 for requests" in match.evidence[0]


@pytest.mark.asyncio
async def test_vulnerability_repository_multi_source(db_session: AsyncSession):
    """Test VulnerabilityRepository multi-source queries, identifiers, and ranges."""
    src_repo = SourceRepository(db_session)
    source, _ = await src_repo.get_or_create("OSV Source", "osv", "http://example.com")

    vuln_repo = VulnerabilityRepository(db_session)

    records = [
        VulnerabilityRecord(
            canonical_id="GHSA-test-1234",
            source_name="OSV",
            vendor_project="psf",
            product="requests",
            vulnerability_name="Test Request Flaw",
            severity="HIGH",
            cvss_score=8.5,
            identifiers=[
                VulnerabilityIdentifier(
                    identifier="GHSA-test-1234", identifier_type=IdentifierType.GHSA, source="OSV"
                ),
                VulnerabilityIdentifier(
                    identifier="CVE-2024-7777", identifier_type=IdentifierType.CVE, source="NVD"
                ),
            ],
            affected_ranges=[
                AffectedVersionRange(
                    ecosystem="pypi",
                    package_name="requests",
                    introduced="2.0.0",
                    fixed="2.32.0",
                    raw_range=">= 2.0.0, < 2.32.0",
                    source_name="OSV",
                )
            ],
        )
    ]

    count = await vuln_repo.upsert_vulnerabilities(source.id, records)
    assert count == 1

    # 1. Search by canonical_id
    by_canonical = await vuln_repo.get_by_canonical_id("GHSA-test-1234")
    assert by_canonical is not None
    assert by_canonical.canonical_id == "GHSA-test-1234"
    assert by_canonical.severity == "HIGH"
    assert by_canonical.cvss_score == 8.5

    # 2. Search by alias identifier (CVE-2024-7777)
    by_ident = await vuln_repo.get_by_identifier("CVE-2024-7777")
    assert by_ident is not None
    assert by_ident.id == by_canonical.id

    # 3. Query identifiers
    idents = await vuln_repo.get_identifiers(by_canonical.id)
    assert len(idents) == 2
    ident_values = {i.identifier for i in idents}
    assert "GHSA-test-1234" in ident_values
    assert "CVE-2024-7777" in ident_values

    # 4. Query affected ranges
    ranges = await vuln_repo.get_affected_ranges(by_canonical.id)
    assert len(ranges) == 1
    assert ranges[0].package_name == "requests"
    assert ranges[0].fixed == "2.32.0"

    # 5. Query source records
    s_records = await vuln_repo.get_source_records(by_canonical.id)
    assert len(s_records) == 1
    assert s_records[0].source_name == "OSV"

    # 6. Search by package
    pkg_vulns = await vuln_repo.find_by_package("pypi", "requests")
    assert len(pkg_vulns) == 1
    assert pkg_vulns[0].id == by_canonical.id

    pkg_empty = await vuln_repo.find_by_package("npm", "requests")
    assert len(pkg_empty) == 0

    # 7. Domain conversion
    domain_rec = vuln_repo.to_domain(by_canonical)
    assert domain_rec.canonical_id == "GHSA-test-1234"
    assert domain_rec.severity == "HIGH"
    assert domain_rec.cvss_score == 8.5


@pytest.mark.asyncio
async def test_match_repository_structured_evidences(db_session: AsyncSession):
    """Test MatchRepository saving and retrieving structured evidences."""
    proj_repo = ProjectRepository(db_session)
    project = await proj_repo.create("Test Proj", "/tmp/test-proj")

    scan_repo = ScanRepository(db_session)
    scan = await scan_repo.create(project.id)

    src_repo = SourceRepository(db_session)
    source, _ = await src_repo.get_or_create("CISA KEV", "kev")

    vuln_repo = VulnerabilityRepository(db_session)
    await vuln_repo.upsert_vulnerabilities(
        source.id,
        [
            VulnerabilityRecord(
                canonical_id="CVE-2024-8888",
                product="flask",
                vendor_project="pallets",
            )
        ],
    )
    vuln_db = await vuln_repo.get_by_canonical_id("CVE-2024-8888")
    assert vuln_db is not None

    comp = DetectedComponent(
        name="flask",
        version="3.0.0",
        ecosystem=Ecosystem.PYPI,
        source_file="pyproject.toml",
    )
    from vuln_ai.db.repositories import ComponentRepository

    comp_repo = ComponentRepository(db_session)
    comps_db = await comp_repo.save_components(project.id, [comp])

    ev = MatchEvidence(
        source_name="CISA KEV",
        identifier="CVE-2024-8888",
        package_name="flask",
        ecosystem=Ecosystem.PYPI,
        installed_version="3.0.0",
        status=Applicability.DETECTED,
        evidence_type=EvidenceType.PRODUCT_NAME_ONLY,
        details="Product match without version ranges",
    )

    match_res = MatchResult(
        component=comp,
        vulnerability=VulnerabilityRecord(canonical_id="CVE-2024-8888", product="flask"),
        match_type=MatchType.EXACT_NAME,
        match_confidence=0.7,
        applicability=Applicability.DETECTED,
        structured_evidences=[ev],
    )

    match_repo = MatchRepository(db_session)
    saved = await match_repo.save_matches(
        scan_id=scan.id,
        matches=[match_res],
        component_id_map={"flask": comps_db[0].id},
        vulnerability_id_map={"CVE-2024-8888": vuln_db.id},
    )
    assert len(saved) == 1

    evidences_db = await match_repo.get_match_evidences(saved[0].id)
    assert len(evidences_db) == 1
    assert evidences_db[0].identifier == "CVE-2024-8888"
    assert evidences_db[0].source_name == "CISA KEV"
    assert evidences_db[0].evidence_type == EvidenceType.PRODUCT_NAME_ONLY
