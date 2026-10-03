"""Unit tests verifying container components reuse the existing matcher."""

from __future__ import annotations

from pathlib import Path

from tests.fixtures.container_fixtures import create_docker_image_archive
from vuln_ai.container.models import OSPackage
from vuln_ai.container.scanner import ContainerImageScanner
from vuln_ai.core.models import (
    AffectedVersionRange,
    Applicability,
    DetectedComponent,
    Ecosystem,
    MatchResult,
    VulnerabilityRecord,
)
from vuln_ai.matching.matcher import VulnerabilityMatcher


def test_os_package_converts_to_detected_component_with_provenance() -> None:
    """OS packages must feed the shared DetectedComponent contract."""
    pkg = OSPackage(
        name="openssl",
        version="3.0.11-1",
        architecture="amd64",
        ecosystem=Ecosystem.DEB,
        manager="dpkg",
        source_file="/var/lib/dpkg/status",
        layer_digest="sha256:deadbeef",
    )
    component = pkg.to_detected_component()
    assert component.name == "openssl"
    assert component.version == "3.0.11-1"
    assert component.ecosystem == Ecosystem.DEB
    assert component.metadata["container_layer"] == "sha256:deadbeef"
    assert component.metadata["container_path"] == "/var/lib/dpkg/status"
    assert component.metadata["package_manager"] == "dpkg"
    assert component.metadata["architecture"] == "amd64"


def test_version_aware_matcher_on_container_os_component() -> None:
    """Container OS components must use the existing version-aware matcher."""
    component = DetectedComponent(
        name="curl",
        version="7.88.1",
        ecosystem=Ecosystem.DEB,
        source_file="/var/lib/dpkg/status",
        metadata={
            "container_layer": "sha256:layer1",
            "container_path": "/var/lib/dpkg/status",
            "container_digest": "sha256:imagedigest",
            "package_manager": "dpkg",
        },
    )
    vuln = VulnerabilityRecord(
        canonical_id="CVE-2023-CONTAINER-1",
        cve_id="CVE-2023-CONTAINER-1",
        source_name="OSV",
        product="curl",
        short_description="Test curl vulnerability",
        affected_ranges=[
            AffectedVersionRange(
                ecosystem="deb",
                package_name="curl",
                introduced="0",
                fixed="8.0.0",
                source_name="OSV",
            )
        ],
    )
    matcher = VulnerabilityMatcher()
    matches = matcher.match([component], [vuln])
    assert len(matches) == 1
    match = matches[0]
    assert isinstance(match, MatchResult)
    assert match.vulnerability.canonical_id == "CVE-2023-CONTAINER-1"
    assert match.component.metadata["container_layer"] == "sha256:layer1"
    assert match.applicability == Applicability.LIKELY_AFFECTED
    # Canonical vocabulary: never invent a VULNERABLE status.
    assert "VULNERABLE" not in {a.value for a in Applicability}


def test_multi_version_os_packages_match_independently() -> None:
    """Same package name with different versions must be evaluated separately."""
    c1 = DetectedComponent(
        name="openssl",
        version="1.1.1",
        ecosystem=Ecosystem.DEB,
        source_file="/var/lib/dpkg/status",
        metadata={"architecture": "amd64", "container_layer": "sha256:l1"},
    )
    c2 = DetectedComponent(
        name="openssl",
        version="3.0.12",
        ecosystem=Ecosystem.DEB,
        source_file="/var/lib/dpkg/status",
        metadata={"architecture": "amd64", "container_layer": "sha256:l2"},
    )
    vuln = VulnerabilityRecord(
        canonical_id="CVE-OPENSSL-OLD",
        cve_id="CVE-OPENSSL-OLD",
        source_name="NVD",
        product="openssl",
        short_description="Old openssl branch",
        affected_ranges=[
            AffectedVersionRange(
                ecosystem="deb",
                package_name="openssl",
                introduced="1.1.0",
                fixed="1.1.2",
                source_name="NVD",
            )
        ],
    )
    matcher = VulnerabilityMatcher()
    matches = matcher.match([c1, c2], [vuln])
    match_by_ver = {m.component.version: m for m in matches}
    assert match_by_ver["1.1.1"].applicability == Applicability.LIKELY_AFFECTED
    assert match_by_ver["3.0.12"].applicability == Applicability.LIKELY_NOT_AFFECTED


def test_scanner_app_dependency_keeps_provenance(tmp_path: Path) -> None:
    """Application dependencies discovered in images keep layer/path provenance."""
    archive = create_docker_image_archive(
        tmp_path / "appimg.tar",
        app_files={"app/requirements.txt": "urllib3==1.26.18\n"},
    )
    _image, _os_pkgs, components, graph = ContainerImageScanner().scan_archive(archive)
    urllib_comps = [c for c in components if c.name == "urllib3"]
    assert urllib_comps
    assert urllib_comps[0].metadata.get("container_layer")
    assert urllib_comps[0].metadata.get("container_path", "").endswith("requirements.txt")
    assert graph.nodes
