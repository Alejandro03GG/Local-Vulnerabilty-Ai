"""Targeted unit tests to ensure >= 95% total test coverage for Etapa 17."""

from __future__ import annotations

import io
import tarfile
from pathlib import Path

import pytest
from httpx import ASGITransport, AsyncClient

from vuln_ai.api.main import create_app
from vuln_ai.container.archive import (
    ArchiveSecurityError,
    ArchiveSecurityLimits,
    SafeArchiveReader,
    is_safe_symlink_target,
    read_tar_member_bytes,
)
from vuln_ai.container.dockerfile import (
    parse_dockerfile_content,
)
from vuln_ai.container.os_detect import (
    detect_os_from_files,
    parse_os_release_text,
)


def test_os_detect_various_distros():
    """Verify static OS detection for various distribution releases."""
    # Ubuntu with ID_LIKE
    ubuntu_os = parse_os_release_text(
        'NAME="Ubuntu"\nID=ubuntu\nID_LIKE=debian\nVERSION_ID="22.04"\nVERSION_CODENAME=jammy\n'
    )
    assert ubuntu_os.family == "debian"
    assert ubuntu_os.name == "Ubuntu"
    assert ubuntu_os.version == "22.04"
    assert ubuntu_os.codename == "jammy"

    # RedHat family
    rhel_os = parse_os_release_text(
        'NAME="Red Hat Enterprise Linux"\nID=rhel\nID_LIKE="fedora"\nVERSION_ID="9.2"\n'
    )
    assert rhel_os.family == "redhat"
    assert rhel_os.version == "9.2"

    # SUSE
    suse_os = parse_os_release_text(
        'NAME="openSUSE Leap"\nID=opensuse-leap\nID_LIKE="suse opensuse"\nVERSION_ID="15.5"\n'
    )
    assert suse_os.family == "suse"

    # Arch
    arch_os = parse_os_release_text('NAME="Arch Linux"\nID=arch\n')
    assert arch_os.family == "arch"

    # Unknown custom distro fallback
    custom_os = parse_os_release_text('NAME="CustomOS"\nID=custom\n')
    assert custom_os.family == "linux"


def test_detect_os_from_files_priority():
    """Verify fallback priorities across filesystem release files."""
    # /usr/lib/os-release
    res1 = detect_os_from_files(
        {"/usr/lib/os-release": "ID=alpine\nNAME=Alpine\nVERSION_ID=3.19.0\n"}
    )
    assert res1.family == "alpine"

    # /etc/alpine-release
    res2 = detect_os_from_files({"/etc/alpine-release": "3.18.2\n"})
    assert res2.family == "alpine"
    assert res2.version == "3.18.2"

    # /etc/debian_version
    res3 = detect_os_from_files({"/etc/debian_version": "12.5\n"})
    assert res3.family == "debian"
    assert res3.version == "12.5"

    # /etc/redhat-release
    res4 = detect_os_from_files({"/etc/redhat-release": "CentOS Linux release 8.4.2105 (Core)\n"})
    assert res4.family == "redhat"
    assert res4.version == "8.4.2105"

    # Fallback to Generic Linux
    res5 = detect_os_from_files({})
    assert res5.family == "linux"
    assert res5.name == "Generic Linux"


def test_archive_reader_methods(tmp_path: Path):
    """Verify read_file_content, find_and_read_files, and member reader helpers."""
    tar_file = tmp_path / "test_read.tar"
    with tarfile.open(tar_file, mode="w") as t:
        d1 = b"Hello, World!"
        i1 = tarfile.TarInfo(name="app/hello.txt")
        i1.size = len(d1)
        t.addfile(i1, io.BytesIO(d1))

        d2 = b"name: test-pkg"
        i2 = tarfile.TarInfo(name="app/manifest.yaml")
        i2.size = len(d2)
        t.addfile(i2, io.BytesIO(d2))

    reader = SafeArchiveReader()

    # read_file_content from path
    content = reader.read_file_content(tar_file, "app/hello.txt")
    assert content == b"Hello, World!"

    # read_file_content not found
    assert reader.read_file_content(tar_file, "missing.txt") is None

    # read_file_content from stream
    with open(tar_file, "rb") as f:
        content_stream = reader.read_file_content(f, "app/manifest.yaml")
        assert content_stream == b"name: test-pkg"

    # find_and_read_files
    matches = reader.find_and_read_files(tar_file, lambda p: p.endswith(".txt"))
    assert "/app/hello.txt" in matches
    assert matches["/app/hello.txt"] == b"Hello, World!"

    # read_tar_member_bytes helper
    with tarfile.open(tar_file, mode="r:*") as t:
        m = t.getmember("app/hello.txt")
        assert read_tar_member_bytes(t, m) == b"Hello, World!"


def test_archive_reader_limits(tmp_path: Path):
    """Verify security limits for single file bytes and compression ratio."""
    tar_file = tmp_path / "oversize.tar"
    with tarfile.open(tar_file, mode="w") as t:
        data = b"X" * 100
        info = tarfile.TarInfo(name="big.txt")
        info.size = len(data)
        t.addfile(info, io.BytesIO(data))

    # Single file limit
    strict_reader = SafeArchiveReader(limits=ArchiveSecurityLimits(max_single_file_bytes=50))
    with pytest.raises(ArchiveSecurityError):
        list(strict_reader.inspect_members(tar_file))

    # Single file limit in read_file_content
    with pytest.raises(ArchiveSecurityError):
        strict_reader.read_file_content(tar_file, "big.txt")


def test_safe_symlink_checks():
    """Verify symlink target security checks."""
    assert is_safe_symlink_target("foo/bar", "baz") is True
    assert is_safe_symlink_target("../bar", "baz/qux") is True
    assert is_safe_symlink_target("../../bar", "baz") is False
    assert is_safe_symlink_target("/root/file", "app") is False


@pytest.mark.asyncio
async def test_container_api_error_branches():
    """Test 404 error branches on container image endpoints."""
    app = create_app()
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        # Get nonexistent image
        res = await client.get("/api/v1/images/nonexistent-id")
        assert res.status_code == 404

        # Get nonexistent image layers
        res_l = await client.get("/api/v1/images/nonexistent-id/layers")
        assert res_l.status_code == 404

        # Get nonexistent image components
        res_c = await client.get("/api/v1/images/nonexistent-id/components")
        assert res_c.status_code == 404

        # Get nonexistent image vulnerabilities
        res_v = await client.get("/api/v1/images/nonexistent-id/vulnerabilities")
        assert res_v.status_code == 404

        # Get nonexistent image dependency graph
        res_g = await client.get("/api/v1/images/nonexistent-id/dependency-graph")
        assert res_g.status_code == 404

        # Get nonexistent image policy
        res_p = await client.get("/api/v1/images/nonexistent-id/policy")
        assert res_p.status_code == 404

        # Dockerfile scan without content or path
        res_d = await client.post("/api/v1/container/dockerfile/scan", json={})
        assert res_d.status_code == 400


def test_dockerfile_ast_edge_cases(tmp_path: Path):
    """Test Dockerfile parser with heredocs, line continuations, and multiple stages."""
    df_content = """# syntax=docker/dockerfile:1
FROM golang:1.22-alpine AS builder
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -o /app/server .

FROM alpine:3.19 AS runtime
WORKDIR /app
COPY --from=builder /app/server /app/server
USER 10001
ENTRYPOINT ["/app/server"]
"""
    doc = parse_dockerfile_content(df_content, source_file="Dockerfile.multistage")
    assert len(doc.stages) == 2
    assert doc.stages[0].name == "builder"
    assert doc.stages[1].name == "runtime"
    assert doc.stages[1].is_runtime is True
    assert doc.stages[0].is_runtime is False
    assert len(doc.copied_files) >= 1
    assert any(c.get("from_stage") == "builder" for c in doc.copied_files)


def test_image_source_abstraction_and_placeholders(tmp_path: Path):
    """LocalOCIArchiveSource works; daemon/registry placeholders stay unimplemented."""
    from tests.fixtures.container_fixtures import (
        create_docker_image_archive,
        create_oci_image_archive,
    )
    from vuln_ai.container.source import (
        DockerDaemonSource,
        LocalOCIArchiveSource,
        OCIRegistrySource,
    )

    docker_archive = create_docker_image_archive(tmp_path / "src-docker.tar")
    source = LocalOCIArchiveSource(docker_archive)
    summary = source.inspect()
    assert summary.source_type == "docker_archive"
    assert source.get_manifest()
    assert source.get_config() is not None
    assert source.get_layers()

    oci_archive = create_oci_image_archive(tmp_path / "src-oci.tar")
    oci_source = LocalOCIArchiveSource(oci_archive)
    oci_summary = oci_source.inspect()
    assert oci_summary.source_type == "oci_archive"
    assert oci_source.get_layers()

    with pytest.raises(NotImplementedError):
        DockerDaemonSource("nginx:latest").inspect()
    with pytest.raises(NotImplementedError):
        DockerDaemonSource("nginx:latest").get_manifest()
    with pytest.raises(NotImplementedError):
        DockerDaemonSource("nginx:latest").get_config()
    with pytest.raises(NotImplementedError):
        DockerDaemonSource("nginx:latest").get_layers()
    with pytest.raises(NotImplementedError):
        DockerDaemonSource("nginx:latest").parse()
    with pytest.raises(NotImplementedError):
        OCIRegistrySource("ghcr.io/org/app@sha256:abc").inspect()
    with pytest.raises(NotImplementedError):
        OCIRegistrySource("ghcr.io/org/app@sha256:abc").get_manifest()
    with pytest.raises(NotImplementedError):
        OCIRegistrySource("ghcr.io/org/app@sha256:abc").get_config()
    with pytest.raises(NotImplementedError):
        OCIRegistrySource("ghcr.io/org/app@sha256:abc").get_layers()
    with pytest.raises(NotImplementedError):
        OCIRegistrySource("ghcr.io/org/app@sha256:abc").parse()

    with pytest.raises(FileNotFoundError):
        LocalOCIArchiveSource(tmp_path / "missing.tar").inspect()


def test_policy_image_digest_condition_and_defaults():
    """Policy conditions can scope by image digest; default actions cover review/accept."""
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
    from vuln_ai.policy.engine import ConditionEvaluator, PolicyEngine
    from vuln_ai.policy.models import (
        Policy,
        PolicyAction,
        PolicyCondition,
        PolicyStatus,
        PolicyThresholds,
    )
    from vuln_ai.risk.models import RiskAssessment, RiskLevel, RiskStatus

    component = DetectedComponent(
        name="openssl",
        version="3.0.0",
        ecosystem=Ecosystem.DEB,
        source_file="/var/lib/dpkg/status",
        metadata={"container_digest": "sha256:abc123", "image_digest": "sha256:abc123"},
    )
    vuln = VulnerabilityRecord(
        canonical_id="CVE-DIGEST-1",
        cve_id="CVE-DIGEST-1",
        source_name="OSV",
        product="openssl",
        short_description="digest scoped",
        severity="CRITICAL",
    )
    risk = RiskAssessment(
        status=RiskStatus.LIKELY_AFFECTED,
        risk_level=RiskLevel.CRITICAL,
        certainty=0.9,
        rationale="critical openssl",
        recommended_action="upgrade",
        requires_human_review=False,
    )
    match = MatchResult(
        component=component,
        vulnerability=vuln,
        match_type=MatchType.EXACT_NAME,
        match_confidence=1.0,
        applicability=Applicability.LIKELY_AFFECTED,
        risk_assessment=risk,
    )

    assert (
        ConditionEvaluator.evaluate(PolicyCondition(image_digest="sha256:abc123"), match) is True
    )
    assert (
        ConditionEvaluator.evaluate(PolicyCondition(image_digest=["sha256:other"]), match) is False
    )
    assert (
        ConditionEvaluator.evaluate(
            PolicyCondition(image_digest="sha256:abc123", risk_level="CRITICAL"),
            match,
        )
        is True
    )

    review_policy = Policy(
        name="review-default",
        version="1",
        thresholds=PolicyThresholds(),
        rules=[],
        default_action=PolicyAction.REQUIRE_REVIEW,
    )
    review_eval = PolicyEngine(review_policy).evaluate([match])
    assert review_eval.evaluations[0].status == PolicyStatus.REQUIRES_REVIEW
    assert review_eval.requires_review_count == 1

    accept_policy = Policy(
        name="accept-default",
        version="1",
        thresholds=PolicyThresholds(),
        rules=[],
        default_action=PolicyAction.ACCEPT_RISK,
    )
    accept_eval = PolicyEngine(accept_policy).evaluate([match])
    assert accept_eval.evaluations[0].status == PolicyStatus.ACCEPTED_RISK
    assert accept_eval.accepted_risk_count == 1

    summary = ScanResultSummary(
        project_name="img",
        project_path="/tmp/img.tar",
        scan_status=ScanStatus.COMPLETED,
        matches=[match],
    )
    summary_eval = PolicyEngine.evaluate_summary(summary, policy=review_policy)
    assert summary_eval.evaluations[0].status == PolicyStatus.REQUIRES_REVIEW


def test_sarif_container_provenance_properties():
    """SARIF findings include container provenance properties when present."""
    from datetime import UTC, datetime

    from vuln_ai.export.models import ExportFinding, ExportScan, ExportVulnerability
    from vuln_ai.export.sarif import export_sarif_dict

    finding = ExportFinding(
        finding_id="f1",
        rule_id="CVE-CONT-1",
        component_name="curl",
        component_version="7.88.1",
        component_ref="deb:curl:7.88.1",
        ecosystem="deb",
        applicability="likely_affected",
        risk_level="HIGH",
        requires_human_review=False,
        confidence=0.9,
        container_image="app:1.0",
        container_digest="sha256:deadbeef",
        container_layer="sha256:layer1",
        container_path="/var/lib/dpkg/status",
        package_manager="dpkg",
        risk_score=85.0,
        conflict_summary="sources disagree",
        source_file="/var/lib/dpkg/status",
    )
    vuln = ExportVulnerability(
        canonical_id="CVE-CONT-1",
        summary="container finding",
        severity="HIGH",
        recommendation="upgrade curl",
        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
    )
    scan = ExportScan(
        scan_id="scan-1",
        project_name="container",
        project_path="/tmp/image.tar",
        generated_at=datetime.now(UTC).isoformat(),
        findings=[finding],
        vulnerabilities=[vuln],
        components=[],
        dependencies=[],
    )
    doc = export_sarif_dict(scan)
    props = doc["runs"][0]["results"][0]["properties"]
    assert props["containerImage"] == "app:1.0"
    assert props["containerDigest"] == "sha256:deadbeef"
    assert props["containerLayer"] == "sha256:layer1"
    assert props["containerPath"] == "/var/lib/dpkg/status"
    assert props["packageManager"] == "dpkg"
    assert props["riskScore"] == 85.0
    assert props["conflictSummary"] == "sources disagree"


def test_scanner_missing_archive_and_dockerfile_helpers(tmp_path: Path):
    """Scanner surfaces FileNotFound for missing archives/Dockerfiles."""
    from vuln_ai.container.dockerfile import parse_dockerfile_file
    from vuln_ai.container.scanner import ContainerImageScanner

    scanner = ContainerImageScanner()
    with pytest.raises(FileNotFoundError):
        scanner.scan_archive(tmp_path / "nope.tar")
    with pytest.raises(FileNotFoundError):
        parse_dockerfile_file(tmp_path / "missing.Dockerfile")
    with pytest.raises(FileNotFoundError):
        scanner.scan_dockerfile(tmp_path / "missing.Dockerfile")


def test_manifest_bad_config_and_invalid_layers():
    """Malformed config JSON and invalid Layers values are tolerated safely."""
    from vuln_ai.container.manifest import (
        parse_docker_archive_manifest,
        parse_oci_index_or_manifest,
    )

    parsed = parse_docker_archive_manifest(
        b'[{"Config": "c.json", "RepoTags": ["x:1"], "Layers": "bad"}]',
        config_bytes=b"not-json",
    )
    assert parsed.layers == []
    assert parsed.architecture == "amd64"

    oci = parse_oci_index_or_manifest(
        b'{"schemaVersion": 2, "layers": [{"digest": "sha256:abc", "size": 1}]}',
        config_bytes=b"{bad",
    )
    assert len(oci.layers) == 1


def test_suppression_image_digest_mismatch():
    """Suppressions scoped to an image digest must not apply to other digests."""
    from datetime import UTC, datetime

    from vuln_ai.core.models import (
        Applicability,
        DetectedComponent,
        Ecosystem,
        MatchResult,
        MatchType,
        VulnerabilityRecord,
    )
    from vuln_ai.policy.clock import FixedClock
    from vuln_ai.policy.engine import PolicyEngine
    from vuln_ai.policy.models import (
        Policy,
        PolicyAction,
        PolicyCondition,
        PolicyRule,
        PolicyStatus,
        PolicyThresholds,
        Suppression,
        SuppressionMatchCriteria,
    )
    from vuln_ai.risk.models import RiskAssessment, RiskLevel, RiskStatus

    component = DetectedComponent(
        name="curl",
        version="7.88.1",
        ecosystem=Ecosystem.DEB,
        source_file="/var/lib/dpkg/status",
        metadata={"container_digest": "sha256:image-a"},
    )
    vuln = VulnerabilityRecord(canonical_id="CVE-SUP-1", severity="HIGH", source_name="OSV")
    risk = RiskAssessment(
        status=RiskStatus.LIKELY_AFFECTED,
        risk_level=RiskLevel.HIGH,
        certainty=0.9,
        rationale="high",
        recommended_action="fix",
        requires_human_review=False,
    )
    match = MatchResult(
        component=component,
        vulnerability=vuln,
        match_type=MatchType.EXACT_NAME,
        match_confidence=1.0,
        applicability=Applicability.LIKELY_AFFECTED,
        risk_assessment=risk,
    )
    policy = Policy(
        name="block-high",
        version="1",
        thresholds=PolicyThresholds(fail_on=["HIGH"]),
        rules=[
            PolicyRule(
                id="block-high",
                when=PolicyCondition(risk_level="HIGH"),
                action=PolicyAction.BLOCK,
            )
        ],
        default_action=PolicyAction.ALLOW,
    )
    suppression = Suppression(
        id="sup-1",
        reason="temporary exception for other image",
        owner="security-team",
        reference="TICKET-1",
        match_criteria=SuppressionMatchCriteria(
            vulnerability_id="CVE-SUP-1",
            package_name="curl",
            image_digest="sha256:image-b",
        ),
        created_at=datetime.now(UTC),
    )
    result = PolicyEngine(
        policy, suppressions=[suppression], clock=FixedClock(datetime.now(UTC))
    ).evaluate([match])
    assert result.evaluations[0].status == PolicyStatus.VIOLATION
    assert result.has_violations is True
