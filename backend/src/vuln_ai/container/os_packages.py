"""Parsers for OS-level installed package databases (dpkg, apk, rpm).

Extracts installed packages directly from database files without invoking
package managers or shell commands.
"""

from __future__ import annotations

import logging
import re
from collections.abc import Mapping

from vuln_ai.container.models import OSPackage
from vuln_ai.core.models import Ecosystem

logger = logging.getLogger(__name__)


def parse_dpkg_status(
    status_content: str,
    source_file: str = "/var/lib/dpkg/status",
    layer_digest: str | None = None,
) -> list[OSPackage]:
    """Parse Debian/Ubuntu /var/lib/dpkg/status database file."""
    packages: list[OSPackage] = []
    # Blocks are separated by double newlines
    raw_blocks = status_content.split("\n\n")

    for block in raw_blocks:
        if not block.strip():
            continue

        fields: dict[str, str] = {}
        current_field: str | None = None

        for line in block.splitlines():
            if line.startswith((" ", "\t")):
                # Continuation line
                if current_field:
                    fields[current_field] += " " + line.strip()
            elif ":" in line:
                key, val = line.split(":", 1)
                key = key.strip()
                val = val.strip()
                fields[key] = val
                current_field = key

        pkg_name = fields.get("Package")
        version = fields.get("Version")
        status = fields.get("Status", "install ok installed")

        if not pkg_name or not version:
            continue

        # Only include installed packages
        if "installed" not in status:
            continue

        arch = fields.get("Architecture")
        desc = fields.get("Description")
        raw_deps = fields.get("Depends", "")
        # Parse simple dependencies
        deps = [d.split()[0].strip() for d in raw_deps.split(",") if d.strip()]

        packages.append(
            OSPackage(
                name=pkg_name,
                version=version,
                architecture=arch,
                ecosystem=Ecosystem.DEB,
                manager="dpkg",
                source_file=source_file,
                layer_digest=layer_digest,
                description=desc,
                dependencies=deps,
                metadata={
                    "section": fields.get("Section", ""),
                    "priority": fields.get("Priority", ""),
                    "maintainer": fields.get("Maintainer", ""),
                },
            )
        )

    return packages


def parse_apk_installed(
    installed_content: str,
    source_file: str = "/lib/apk/db/installed",
    layer_digest: str | None = None,
) -> list[OSPackage]:
    """Parse Alpine Linux /lib/apk/db/installed database file."""
    packages: list[OSPackage] = []
    raw_blocks = installed_content.split("\n\n")

    for block in raw_blocks:
        if not block.strip():
            continue

        fields: dict[str, str] = {}
        for line in block.splitlines():
            line = line.strip()
            if not line or len(line) < 3 or line[1] != ":":
                continue
            prefix = line[0]
            val = line[2:].strip()
            fields[prefix] = val

        pkg_name = fields.get("P")
        version = fields.get("V")

        if not pkg_name or not version:
            continue

        arch = fields.get("A")
        desc = fields.get("T")
        raw_deps = fields.get("D", "")
        deps = [d.strip() for d in raw_deps.split() if d.strip()]

        packages.append(
            OSPackage(
                name=pkg_name,
                version=version,
                architecture=arch,
                ecosystem=Ecosystem.APK,
                manager="apk",
                source_file=source_file,
                layer_digest=layer_digest,
                description=desc,
                dependencies=deps,
                metadata={
                    "origin": fields.get("o", ""),
                    "maintainer": fields.get("m", ""),
                    "commit": fields.get("c", ""),
                },
            )
        )

    return packages


def parse_rpm_manifest_text(
    manifest_content: str,
    source_file: str = "/var/lib/rpm/manifest",
    layer_digest: str | None = None,
) -> list[OSPackage]:
    """Parse text-based RPM package listings (e.g. from manifests or package lists)."""
    packages: list[OSPackage] = []

    # Format often: <name> <version>-<release> <arch> OR <name>-<version>-<release>.<arch>
    for line in manifest_content.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue

        parts = line.split()
        if len(parts) >= 2:
            pkg_name = parts[0]
            version = parts[1]
            arch = parts[2] if len(parts) > 2 else None
        else:
            # Try parsing NEVRA: e.g. curl-7.61.1-30.el8_8.2.x86_64
            match = re.match(r"^(.+?)-([0-9][^-]*)-(.*?)\.([a-zA-Z0-9_]+)$", line)
            if match:
                pkg_name = match.group(1)
                version = f"{match.group(2)}-{match.group(3)}"
                arch = match.group(4)
            else:
                continue

        packages.append(
            OSPackage(
                name=pkg_name,
                version=version,
                architecture=arch,
                ecosystem=Ecosystem.RPM,
                manager="rpm",
                source_file=source_file,
                layer_digest=layer_digest,
            )
        )

    return packages


def extract_os_packages_from_files(
    files_map: Mapping[str, bytes | str],
    layer_digest: str | None = None,
) -> list[OSPackage]:
    """Scan container file dictionary for known OS package databases."""
    all_packages: list[OSPackage] = []

    for path_key, content in files_map.items():
        clean_path = "/" + path_key.lstrip("./")
        text = (
            content.decode("utf-8", errors="replace")
            if isinstance(content, bytes)
            else str(content)
        )

        # DPKG
        if clean_path in ("/var/lib/dpkg/status", "/var/lib/dpkg/status-old"):
            all_packages.extend(
                parse_dpkg_status(text, source_file=clean_path, layer_digest=layer_digest)
            )

        # APK
        elif clean_path in ("/lib/apk/db/installed", "/etc/apk/installed"):
            all_packages.extend(
                parse_apk_installed(text, source_file=clean_path, layer_digest=layer_digest)
            )

        # RPM manifest / installed-pkgs
        elif "rpm" in clean_path and (
            clean_path.endswith("manifest") or clean_path.endswith("installed-pkgs")
        ):
            all_packages.extend(
                parse_rpm_manifest_text(text, source_file=clean_path, layer_digest=layer_digest)
            )

    return all_packages
