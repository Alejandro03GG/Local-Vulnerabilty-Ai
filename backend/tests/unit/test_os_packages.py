"""Unit tests for OS package parsers (dpkg, apk, rpm)."""

from __future__ import annotations

from vuln_ai.container.os_packages import (
    extract_os_packages_from_files,
    parse_apk_installed,
    parse_dpkg_status,
    parse_rpm_manifest_text,
)
from vuln_ai.core.models import Ecosystem


def test_parse_dpkg_status():
    """Verify Debian/Ubuntu dpkg status parsing with continuation lines."""
    dpkg_text = """Package: libssl3
Status: install ok installed
Priority: optional
Section: libs
Installed-Size: 5200
Maintainer: Debian OpenSSL Team <pkg-openssl-devel@lists.alioth.debian.org>
Architecture: amd64
Version: 3.0.13-1~deb12u1
Depends: libc6 (>= 2.34)
Description: Secure Sockets Layer toolkit - shared libraries
 This package contains the dynamic libraries needed by applications that
 use the SSL and TLS encryption protocols.

Package: curl
Status: install ok installed
Priority: optional
Section: web
Architecture: amd64
Version: 7.88.1-10+deb12u5
Depends: libc6 (>= 2.34), libcurl4 (= 7.88.1-10+deb12u5), zlib1g (>= 1:1.1.4)
Description: command line tool for transferring data with URL syntax

Package: removed-pkg
Status: deinstall ok config-files
Version: 1.0.0
Description: Should be ignored because not installed
"""
    pkgs = parse_dpkg_status(dpkg_text, layer_digest="sha256:layer1")
    assert len(pkgs) == 2

    ssl_pkg = next(p for p in pkgs if p.name == "libssl3")
    assert ssl_pkg.version == "3.0.13-1~deb12u1"
    assert ssl_pkg.architecture == "amd64"
    assert ssl_pkg.ecosystem == Ecosystem.DEB
    assert ssl_pkg.manager == "dpkg"
    assert ssl_pkg.layer_digest == "sha256:layer1"
    assert "libc6" in ssl_pkg.dependencies

    # Convert to DetectedComponent
    comp = ssl_pkg.to_detected_component()
    assert comp.name == "libssl3"
    assert comp.version == "3.0.13-1~deb12u1"
    assert comp.ecosystem == Ecosystem.DEB
    assert comp.metadata["container_layer"] == "sha256:layer1"
    assert comp.metadata["architecture"] == "amd64"


def test_parse_apk_installed():
    """Verify Alpine Linux apk installed database parsing."""
    apk_text = """C:Q1abc123
P:ssl_client
V:1.36.1-r29
A:x86_64
S:15234
I:36864
T:Client for SSL/TLS connections
U:https://busybox.net/
L:GPL-2.0-only
o:busybox
m:Soren Tempel <soeren@soeren-tempel.net>
t:1707328900
c:64c67675e46358485a73e51f868ad93d3962b8aa
D:so:libc.musl-x86_64.so.1 so:libtls-standalone.so.1
p:cmd:ssl_client

C:Q1def456
P:zlib
V:1.3.1-r0
A:x86_64
S:52341
T:Compression library
L:Zlib
D:so:libc.musl-x86_64.so.1
"""
    pkgs = parse_apk_installed(apk_text, layer_digest="sha256:apk_layer")
    assert len(pkgs) == 2

    ssl_pkg = next(p for p in pkgs if p.name == "ssl_client")
    assert ssl_pkg.version == "1.36.1-r29"
    assert ssl_pkg.ecosystem == Ecosystem.APK
    assert ssl_pkg.manager == "apk"
    assert ssl_pkg.architecture == "x86_64"
    assert ssl_pkg.description == "Client for SSL/TLS connections"


def test_parse_rpm_manifest_text():
    """Verify RPM manifest package list parsing."""
    rpm_text = """# RPM package manifest
glibc 2.28-225.el8 x86_64
curl-7.61.1-30.el8_8.2.x86_64
openssl-libs 1.1.1k-9.el8_7 x86_64
"""
    pkgs = parse_rpm_manifest_text(rpm_text, layer_digest="sha256:rpm_layer")
    assert len(pkgs) == 3

    curl_pkg = next(p for p in pkgs if p.name == "curl")
    assert curl_pkg.ecosystem == Ecosystem.RPM
    assert curl_pkg.manager == "rpm"


def test_extract_os_packages_from_files():
    """Verify multi-manager extraction from file dictionary."""
    files = {
        "/var/lib/dpkg/status": "Package: bash\nVersion: 5.2.15-2+b2\nStatus: install ok installed\n",
        "/etc/unused": "ignored",
    }
    extracted = extract_os_packages_from_files(files, layer_digest="sha256:root")
    assert len(extracted) == 1
    assert extracted[0].name == "bash"
    assert extracted[0].version == "5.2.15-2+b2"
