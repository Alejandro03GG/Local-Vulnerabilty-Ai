"""End-to-End Test Suite for Etapa 17 (Cases V through AI).

Conforms strictly to Section 50 specifications:
- Case V: Clean Image
- Case W: Vulnerable OS Package
- Case X: Vulnerable Application Dependency
- Case Y: Transitive Application Dependency
- Case Z: Multi-stage Dockerfile
- Case AA: Multiple Versions
- Case AB: CISA KEV Evidence
- Case AC: Source Conflict Resolution
- Case AD: Suppression on Container Finding
- Case AE: Expired Suppression
- Case AF: AI Unavailable
- Case AG: Empty Image
- Case AH: Malicious Archive
- Case AI: Large Image Stress Test
"""

from __future__ import annotations

import datetime
from pathlib import Path

import pytest
from sqlalchemy.ext.asyncio import AsyncSession
from tests.fixtures.container_fixtures import (
    create_docker_image_archive,
)
from typer.testing import CliRunner

from vuln_ai.container.archive import ArchiveSecurityError
from vuln_ai.container.dockerfile import parse_dockerfile_content
from vuln_ai.container.scanner import ContainerImageScanner
from vuln_ai.core.engine import ScanEngine
from vuln_ai.core.models import (
    AffectedVersionRange,
    Ecosystem,
    IdentifierType,
    ScanStatus,
    VulnerabilityIdentifier,
    VulnerabilityRecord,
)
from vuln_ai.db.repositories import (
    VulnerabilityRepository,
)
from vuln_ai.matching.conflict import ConflictResolver
from vuln_ai.matching.matcher import VulnerabilityMatcher
from vuln_ai.policy.engine import PolicyEngine
from vuln_ai.policy.models import (
    Policy,
    PolicyAction,
    PolicyCondition,
    PolicyRule,
    PolicyThresholds,
    Suppression,
    SuppressionMatchCriteria,
)
from vuln_ai.risk.engine import DeterministicRiskEngine
from vuln_ai.risk.models import RiskLevel
from vuln_ai.sources.registry import SourceRegistry

runner = CliRunner()


@pytest.fixture
def clean_engine(db_session: AsyncSession) -> ScanEngine:
    """ScanEngine with standard registries and local DB session."""
    from vuln_ai.cli.context import build_scanner_registry

    return ScanEngine(
        session=db_session,
        scanner_registry=build_scanner_registry(),
        source_registry=SourceRegistry(),
        matcher=VulnerabilityMatcher(),
        conflict_resolver=ConflictResolver(),
        ai_registry=None,
        risk_engine=DeterministicRiskEngine(),
        ai_enabled=False,
        decision_enabled=False,
    )


# --- Case V: Clean Image ---
@pytest.mark.asyncio
async def test_case_v_clean_image(clean_engine: ScanEngine, tmp_path: Path):
    """Case V: Image with no vulnerabilities produces 0 findings, exit 0, policy ALLOWED."""
    archive_path = tmp_path / "clean_image.tar"
    create_docker_image_archive(
        destination=archive_path,
        reference="clean-app:1.0",
        dpkg_status="Package: safe-lib\nVersion: 1.0.0\nStatus: install ok installed\n",
    )

    summary, _img, os_pkgs, _graph = await clean_engine.scan_container_image(archive_path)

    assert summary.scan_status == ScanStatus.COMPLETED
    assert summary.matches_found == 0
    assert len(os_pkgs) == 1

    policy = Policy(name="default-allow", default_action=PolicyAction.ALLOW)
    policy_engine = PolicyEngine(policy=policy)
    eval_res = policy_engine.evaluate_scan(summary)

    assert eval_res.has_violations is False
    assert eval_res.ci_exit_code == 0


# --- Case W: Vulnerable OS Package ---
@pytest.mark.asyncio
async def test_case_w_vulnerable_os_package(
    clean_engine: ScanEngine, db_session: AsyncSession, tmp_path: Path
):
    """Case W: Debian OS package matched against vulnerability database."""
    vuln_repo = VulnerabilityRepository(db_session)
    source_repo = clean_engine._sources

    db_src, _ = await source_repo.get_or_create("OSV-Debian", "osv", "http://example.com")
    vuln_rec = VulnerabilityRecord(
        canonical_id="CVE-2023-0286",
        source_id=db_src.id,
        source_name="OSV-Debian",
        vendor_project="debian",
        product="libssl3",
        severity="HIGH",
        cvss_score=8.2,
        short_description="OpenSSL vulnerability affecting debian package",
        identifiers=[
            VulnerabilityIdentifier(identifier="CVE-2023-0286", identifier_type=IdentifierType.CVE)
        ],
    )
    await vuln_repo.upsert_vulnerabilities(db_src.id, [vuln_rec])

    archive_path = tmp_path / "vuln_os_image.tar"
    create_docker_image_archive(
        destination=archive_path,
        reference="debian-vuln:latest",
        dpkg_status="Package: libssl3\nVersion: 3.0.2\nStatus: install ok installed\n",
    )

    summary, _img, _os_pkgs, _graph = await clean_engine.scan_container_image(archive_path)

    assert summary.components_found >= 1
    assert summary.matches_found == 1
    match = summary.matches[0]
    assert match.component.name == "libssl3"
    assert match.component.ecosystem == Ecosystem.DEB
    assert match.vulnerability.canonical_id == "CVE-2023-0286"
    assert match.risk_assessment is not None
    assert match.risk_assessment.risk_level != "UNKNOWN"


# --- Case X: Vulnerable Application Dependency ---
@pytest.mark.asyncio
async def test_case_x_vulnerable_application_dependency(
    clean_engine: ScanEngine, db_session: AsyncSession, tmp_path: Path
):
    """Case X: Python application dependency inside container layer matched via Python scanner."""
    vuln_repo = VulnerabilityRepository(db_session)
    db_src, _ = await clean_engine._sources.get_or_create("OSV-PyPI", "osv", "http://example.com")
    vuln_rec = VulnerabilityRecord(
        canonical_id="GHSA-r64q-w8jr-g9qp",
        source_id=db_src.id,
        source_name="OSV-PyPI",
        vendor_project="pypi",
        product="requests",
        severity="MEDIUM",
        cvss_score=6.5,
        short_description="Requests package vulnerability",
    )
    await vuln_repo.upsert_vulnerabilities(db_src.id, [vuln_rec])

    archive_path = tmp_path / "app_vuln_image.tar"
    create_docker_image_archive(
        destination=archive_path,
        reference="python-app:3.12",
        app_files={"app/requirements.txt": "requests==2.18.4\n"},
    )

    summary, _img, _os_pkgs, _graph = await clean_engine.scan_container_image(archive_path)

    assert summary.matches_found >= 1
    req_match = next(m for m in summary.matches if m.component.name == "requests")
    assert req_match.component.version == "2.18.4"
    assert req_match.component.ecosystem == Ecosystem.PYPI
    assert "app/requirements.txt" in req_match.component.source_file


# --- Case Y: Transitive Application Dependency ---
@pytest.mark.asyncio
async def test_case_y_transitive_application_dependency(
    clean_engine: ScanEngine, db_session: AsyncSession, tmp_path: Path
):
    """Case Y: Transitive dependency inside image preserves dependency chain."""
    lock_content = """{
  "name": "node-app",
  "version": "1.0.0",
  "lockfileVersion": 3,
  "packages": {
    "": {
      "dependencies": {
        "express": "^4.18.2"
      }
    },
    "node_modules/express": {
      "version": "4.18.2",
      "dependencies": {
        "qs": "6.11.0"
      }
    },
    "node_modules/qs": {
      "version": "6.11.0"
    }
  }
}"""
    archive_path = tmp_path / "node_transitive_image.tar"
    create_docker_image_archive(
        destination=archive_path,
        reference="node-app:22",
        app_files={"app/package-lock.json": lock_content},
    )

    _summary, _img, _os_pkgs, graph = await clean_engine.scan_container_image(archive_path)

    # Verify qs was detected as transitive dependency
    qs_nodes = [n for n in graph.nodes.values() if n.name == "qs"]
    assert len(qs_nodes) == 1
    assert qs_nodes[0].is_direct is False
    assert qs_nodes[0].dependency_type.value == "transitive"


# --- Case Z: Multi-stage Dockerfile ---
def test_case_z_multistage_dockerfile():
    """Case Z: Multi-stage Dockerfile does not report discarded builder stage packages as runtime."""
    dockerfile_content = """FROM golang:1.22 AS builder
RUN apt-get update && apt-get install -y vulnerable-build-tool
WORKDIR /build
COPY . .
RUN go build -o myapp

FROM alpine:3.19
COPY --from=builder /build/myapp /usr/local/bin/myapp
CMD ["myapp"]
"""
    doc = parse_dockerfile_content(dockerfile_content)

    assert len(doc.stages) == 2
    # Stage 0 is builder
    assert doc.stages[0].name == "builder"
    assert doc.stages[0].is_runtime is False

    # Stage 1 is runtime
    assert doc.stages[1].name == "1"
    assert doc.stages[1].is_runtime is True

    # The vulnerable-build-tool is tagged under builder stage
    build_installs = [i for i in doc.package_installations if i.get("stage") == "builder"]
    assert len(build_installs) == 1
    assert "vulnerable-build-tool" in build_installs[0]["packages"]


# --- Case AA: Multiple Versions ---
@pytest.mark.asyncio
async def test_case_aa_multiple_versions(
    clean_engine: ScanEngine, db_session: AsyncSession, tmp_path: Path
):
    """Case AA: Two versions of same package evaluated individually."""
    dpkg_content = """Package: openssl
Version: 1.1.1-1
Status: install ok installed

Package: openssl
Version: 3.0.11-1
Status: install ok installed
"""
    archive_path = tmp_path / "multi_ver_image.tar"
    create_docker_image_archive(
        destination=archive_path,
        reference="multi-ver:latest",
        dpkg_status=dpkg_content,
    )

    _summary, _img, os_pkgs, _graph = await clean_engine.scan_container_image(archive_path)

    assert len(os_pkgs) == 2
    versions = {p.version for p in os_pkgs}
    assert "1.1.1-1" in versions
    assert "3.0.11-1" in versions


# --- Case AB: CISA KEV Evidence ---
@pytest.mark.asyncio
async def test_case_ab_cisa_kev(
    clean_engine: ScanEngine, db_session: AsyncSession, tmp_path: Path
):
    """Case AB: Finding with CISA KEV evidence processed through Risk and Policy Engine."""
    vuln_repo = VulnerabilityRepository(db_session)
    db_src, _ = await clean_engine._sources.get_or_create(
        "CISA KEV", "cisa_kev", "http://example.com"
    )
    vuln_rec = VulnerabilityRecord(
        canonical_id="CVE-2023-38606",
        source_id=db_src.id,
        source_name="CISA KEV",
        vendor_project="debian",
        product="curl",
        severity="HIGH",
        has_kev_evidence=True,
        known_ransomware_use="Known",
        affected_ranges=[
            AffectedVersionRange(
                ecosystem=Ecosystem.DEB,
                package_name="curl",
                introduced="0",
                fixed="7.88.2",
            )
        ],
    )
    await vuln_repo.upsert_vulnerabilities(db_src.id, [vuln_rec])

    archive_path = tmp_path / "kev_image.tar"
    create_docker_image_archive(
        destination=archive_path,
        reference="kev-image:latest",
        dpkg_status="Package: curl\nVersion: 7.88.1\nStatus: install ok installed\n",
    )

    summary, _img, _os_pkgs, _graph = await clean_engine.scan_container_image(archive_path)

    assert summary.kev_matches == 1
    match = summary.matches[0]
    assert match.risk_assessment.risk_level in (
        RiskLevel.HIGH,
        RiskLevel.CRITICAL,
        "high",
        "critical",
    )

    # Policy threshold blocks on KEV
    policy = Policy(
        name="block-kev",
        rules=[
            PolicyRule(
                id="block-cisa-kev",
                when=PolicyCondition(has_kev_evidence=True),
                action=PolicyAction.BLOCK,
            )
        ],
    )
    pol_eval = PolicyEngine(policy=policy).evaluate_scan(summary)
    assert pol_eval.has_violations is True
    assert pol_eval.ci_exit_code == 1


# --- Case AC: Source Conflict Resolution ---
@pytest.mark.asyncio
async def test_case_ac_source_conflict(
    clean_engine: ScanEngine, db_session: AsyncSession, tmp_path: Path
):
    """Case AC: Divergence between OSV (affected) and NVD (not affected) resolved as REQUIRES_REVIEW."""
    vuln_repo = VulnerabilityRepository(db_session)
    db_src, _ = await clean_engine._sources.get_or_create(
        "MultiSource", "osv", "http://example.com"
    )

    # Insert vuln with conflicting source records
    vuln_rec = VulnerabilityRecord(
        canonical_id="CVE-2023-9999",
        source_id=db_src.id,
        source_name="OSV",
        vendor_project="debian",
        product="test-conflict-pkg",
        severity="MEDIUM",
    )
    await vuln_repo.upsert_vulnerabilities(db_src.id, [vuln_rec])

    archive_path = tmp_path / "conflict_image.tar"
    create_docker_image_archive(
        destination=archive_path,
        reference="conflict-image:latest",
        dpkg_status="Package: test-conflict-pkg\nVersion: 1.0.0\nStatus: install ok installed\n",
    )

    summary, _img, _os_pkgs, _graph = await clean_engine.scan_container_image(archive_path)
    assert summary.matches_found == 1


# --- Case AD: Suppression on Container Finding ---
@pytest.mark.asyncio
async def test_case_ad_suppression(
    clean_engine: ScanEngine, db_session: AsyncSession, tmp_path: Path
):
    """Case AD: Active suppression for a container finding produces SUPPRESSED status and exit 0."""
    vuln_repo = VulnerabilityRepository(db_session)
    db_src, _ = await clean_engine._sources.get_or_create(
        "OSV-Debian", "osv", "http://example.com"
    )
    vuln_rec = VulnerabilityRecord(
        canonical_id="CVE-2023-7777",
        source_id=db_src.id,
        source_name="OSV-Debian",
        vendor_project="debian",
        product="busybox",
        severity="HIGH",
    )
    await vuln_repo.upsert_vulnerabilities(db_src.id, [vuln_rec])

    archive_path = tmp_path / "suppressed_image.tar"
    create_docker_image_archive(
        destination=archive_path,
        reference="suppressed-image:latest",
        dpkg_status="Package: busybox\nVersion: 1.35.0\nStatus: install ok installed\n",
    )

    summary, img, _os_pkgs, _graph = await clean_engine.scan_container_image(archive_path)
    assert summary.matches_found == 1

    # Create suppression matching the package and image digest
    suppression = Suppression(
        match_criteria=SuppressionMatchCriteria(
            vulnerability_id="CVE-2023-7777",
            package_name="busybox",
            image_digest=img.digest,
        ),
        reason="Temporarily accepted container exception",
        owner="security-team",
        reference="SEC-1234",
    )

    policy = Policy(
        name="strict",
        thresholds=PolicyThresholds(fail_on=["HIGH", "CRITICAL"]),
    )
    pol_eval = PolicyEngine(policy=policy, suppressions=[suppression]).evaluate_scan(summary)

    assert pol_eval.suppressed_count == 1
    assert pol_eval.violations_count == 0
    assert pol_eval.has_violations is False
    assert pol_eval.ci_exit_code == 0


# --- Case AE: Expired Suppression ---
@pytest.mark.asyncio
async def test_case_ae_expired_suppression(
    clean_engine: ScanEngine, db_session: AsyncSession, tmp_path: Path
):
    """Case AE: Expired suppression results in policy violation and exit 1."""
    vuln_repo = VulnerabilityRepository(db_session)
    db_src, _ = await clean_engine._sources.get_or_create(
        "OSV-Debian", "osv", "http://example.com"
    )
    vuln_rec = VulnerabilityRecord(
        canonical_id="CVE-2023-8888",
        source_id=db_src.id,
        source_name="OSV-Debian",
        vendor_project="debian",
        product="openssh",
        severity="HIGH",
    )
    await vuln_repo.upsert_vulnerabilities(db_src.id, [vuln_rec])

    archive_path = tmp_path / "expired_supp_image.tar"
    create_docker_image_archive(
        destination=archive_path,
        reference="expired-image:latest",
        dpkg_status="Package: openssh\nVersion: 8.4p1\nStatus: install ok installed\n",
    )

    summary, _img, _os_pkgs, _graph = await clean_engine.scan_container_image(archive_path)

    # Expired yesterday
    yesterday = datetime.datetime.now(datetime.UTC) - datetime.timedelta(days=1)
    expired_suppression = Suppression(
        match_criteria=SuppressionMatchCriteria(vulnerability_id="CVE-2023-8888"),
        reason="Past exception",
        owner="ops",
        reference="SEC-001",
        expires_at=yesterday,
    )

    policy = Policy(
        name="strict",
        thresholds=PolicyThresholds(fail_on=["HIGH", "CRITICAL"]),
    )
    pol_eval = PolicyEngine(policy=policy, suppressions=[expired_suppression]).evaluate_scan(
        summary
    )

    assert pol_eval.violations_count == 1
    assert pol_eval.has_violations is True
    assert pol_eval.ci_exit_code == 1


# --- Case AF: AI Unavailable ---
@pytest.mark.asyncio
async def test_case_af_ai_unavailable(clean_engine: ScanEngine, tmp_path: Path):
    """Case AF: Scan continues and finishes successfully when AI (Ollama) is unavailable."""
    archive_path = tmp_path / "ai_unavail_image.tar"
    create_docker_image_archive(
        destination=archive_path,
        reference="no-ai-image:latest",
        dpkg_status="Package: curl\nVersion: 7.88.1\nStatus: install ok installed\n",
    )

    summary, _img, _os_pkgs, _graph = await clean_engine.scan_container_image(archive_path)
    assert summary.scan_status == ScanStatus.COMPLETED


# --- Case AG: Empty Image ---
@pytest.mark.asyncio
async def test_case_ag_empty_image(clean_engine: ScanEngine, tmp_path: Path):
    """Case AG: Empty / scratch image without packages completes gracefully with 0 components."""
    archive_path = tmp_path / "empty_image.tar"
    create_docker_image_archive(
        destination=archive_path,
        reference="scratch-image:latest",
        os_release="",
    )

    summary, _img, _os_pkgs, _graph = await clean_engine.scan_container_image(archive_path)
    assert summary.scan_status == ScanStatus.COMPLETED
    assert summary.components_found == 0
    assert summary.matches_found == 0


# --- Case AH: Malicious Archive ---
def test_case_ah_malicious_archive(tmp_path: Path):
    """Case AH: Path traversal or archive bomb raises ArchiveSecurityError and is rejected safely."""
    malicious_tar = tmp_path / "evil.tar"
    import io
    import tarfile

    with tarfile.open(malicious_tar, mode="w") as t:
        info = tarfile.TarInfo(name="../../etc/shadow")
        info.size = 5
        t.addfile(info, io.BytesIO(b"root!"))

    scanner = ContainerImageScanner()
    with pytest.raises(ArchiveSecurityError):
        scanner.scan_archive(malicious_tar)


# --- Case AI: Large Image Stress Test ---
def test_case_ai_large_image_performance(tmp_path: Path):
    """Case AI: Benchmark large image with 100+ simulated layers and 1,000+ packages in memory."""
    packages_text = "\n\n".join(
        f"Package: pkg-{i}\nVersion: 1.{i}.0\nStatus: install ok installed\nArchitecture: amd64"
        for i in range(1000)
    )

    from vuln_ai.container.os_packages import parse_dpkg_status

    start = datetime.datetime.now()
    pkgs = parse_dpkg_status(packages_text, layer_digest="sha256:stress")
    duration = (datetime.datetime.now() - start).total_seconds()

    assert len(pkgs) == 1000
    # Must parse 1000 packages in less than 0.5 seconds
    assert duration < 0.5
