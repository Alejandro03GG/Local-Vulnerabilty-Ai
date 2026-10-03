"""Unit tests for container component models and conversion."""

from __future__ import annotations

from vuln_ai.container.models import OSPackage
from vuln_ai.core.models import ComponentType, Ecosystem, VersionType


def test_os_package_to_detected_component():
    """Verify OSPackage converts properly to standard DetectedComponent."""
    pkg = OSPackage(
        name="openssl",
        version="3.0.11",
        architecture="amd64",
        ecosystem=Ecosystem.DEB,
        manager="dpkg",
        source_file="/var/lib/dpkg/status",
        layer_digest="sha256:abcd1234",
        description="Secure Sockets Layer toolkit",
        dependencies=["libc6", "debconf"],
        metadata={"priority": "required"},
    )

    comp = pkg.to_detected_component()

    assert comp.name == "openssl"
    assert comp.version == "3.0.11"
    assert comp.version_type == VersionType.EXACT
    assert comp.ecosystem == Ecosystem.DEB
    assert comp.component_type == ComponentType.OS_PACKAGE
    assert comp.is_direct is True
    assert comp.source_file == "/var/lib/dpkg/status"

    # Metadata
    assert comp.metadata["container_layer"] == "sha256:abcd1234"
    assert comp.metadata["architecture"] == "amd64"
    assert comp.metadata["package_manager"] == "dpkg"
    assert comp.metadata["container_path"] == "/var/lib/dpkg/status"
    assert comp.metadata["priority"] == "required"


def test_os_package_apk_and_rpm():
    """Verify APK and RPM packages map to correct ecosystems."""
    apk_pkg = OSPackage(
        name="musl",
        version="1.2.4-r2",
        ecosystem=Ecosystem.APK,
        manager="apk",
        source_file="/lib/apk/db/installed",
    )
    c_apk = apk_pkg.to_detected_component()
    assert c_apk.ecosystem == Ecosystem.APK
    assert c_apk.metadata["package_manager"] == "apk"

    rpm_pkg = OSPackage(
        name="systemd",
        version="239-78.el8",
        ecosystem=Ecosystem.RPM,
        manager="rpm",
        source_file="/var/lib/rpm/manifest",
    )
    c_rpm = rpm_pkg.to_detected_component()
    assert c_rpm.ecosystem == Ecosystem.RPM
    assert c_rpm.metadata["package_manager"] == "rpm"
