"""Static Operating System detection for container filesystems.

Extracts distribution identity from standard files (/etc/os-release, etc.)
strictly without executing any system utilities.
"""

from __future__ import annotations

import re
from collections.abc import Mapping

from vuln_ai.container.models import OperatingSystem

_DISTRO_FAMILY_MAP = {
    "debian": "debian",
    "ubuntu": "debian",
    "kali": "debian",
    "linuxmint": "debian",
    "alpine": "alpine",
    "rhel": "redhat",
    "centos": "redhat",
    "rocky": "redhat",
    "almalinux": "redhat",
    "fedora": "redhat",
    "amzn": "redhat",
    "amazonlinux": "redhat",
    "ol": "redhat",  # Oracle Linux
    "sles": "suse",
    "opensuse": "suse",
    "arch": "arch",
}


def parse_os_release_text(content: str, source_path: str = "/etc/os-release") -> OperatingSystem:
    """Parse standard KEY=VALUE /etc/os-release content."""
    fields: dict[str, str] = {}
    for line in content.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if "=" in line:
            key, val = line.split("=", 1)
            key = key.strip()
            val = val.strip().strip('"').strip("'")
            fields[key] = val

    os_id = fields.get("ID", "").lower()
    name = fields.get("PRETTY_NAME") or fields.get("NAME") or os_id.capitalize() or "Linux"
    version_id = fields.get("VERSION_ID")
    codename = fields.get("VERSION_CODENAME")

    # Detect family
    id_like = fields.get("ID_LIKE", "").lower().split()
    family = _DISTRO_FAMILY_MAP.get(os_id)
    if not family:
        for like in id_like:
            if like in _DISTRO_FAMILY_MAP:
                family = _DISTRO_FAMILY_MAP[like]
                break
    if not family:
        family = "linux"

    return OperatingSystem(
        family=family,
        name=name,
        version=version_id,
        codename=codename,
        source=source_path,
    )


def detect_os_from_files(files_map: Mapping[str, bytes | str]) -> OperatingSystem:
    """Detect OS distribution by inspecting known filesystem release files.

    files_map keys can be paths like '/etc/os-release', 'etc/os-release', etc.
    """
    normalized_map: dict[str, str] = {}
    for k, v in files_map.items():
        clean_path = "/" + k.lstrip("./")
        text_val = v.decode("utf-8", errors="replace") if isinstance(v, bytes) else str(v)
        normalized_map[clean_path] = text_val

    # Priority 1: /etc/os-release
    if "/etc/os-release" in normalized_map:
        return parse_os_release_text(normalized_map["/etc/os-release"], "/etc/os-release")

    # Priority 2: /usr/lib/os-release
    if "/usr/lib/os-release" in normalized_map:
        return parse_os_release_text(normalized_map["/usr/lib/os-release"], "/usr/lib/os-release")

    # Priority 3: Alpine release
    if "/etc/alpine-release" in normalized_map:
        ver = normalized_map[
            "etc/alpine-release"
            if "etc/alpine-release" in normalized_map
            else "/etc/alpine-release"
        ].strip()
        return OperatingSystem(
            family="alpine",
            name="Alpine Linux",
            version=ver or None,
            source="/etc/alpine-release",
        )

    # Priority 4: Debian version
    if "/etc/debian_version" in normalized_map:
        ver = normalized_map["/etc/debian_version"].strip()
        return OperatingSystem(
            family="debian",
            name="Debian GNU/Linux",
            version=ver or None,
            source="/etc/debian_version",
        )

    # Priority 5: RedHat / CentOS / Fedora / Amazon Linux
    for rh_path in (
        "/etc/redhat-release",
        "/etc/centos-release",
        "/etc/fedora-release",
        "/etc/system-release",
    ):
        if rh_path in normalized_map:
            content = normalized_map[rh_path].strip()
            name = content.split("release")[0].strip() or "Red Hat Enterprise Linux"
            ver_match = re.search(r"release\s+([\d\.]+)", content, re.IGNORECASE)
            version = ver_match.group(1) if ver_match else None
            return OperatingSystem(
                family="redhat",
                name=name,
                version=version,
                source=rh_path,
            )

    # Fallback generic linux
    return OperatingSystem(
        family="linux",
        name="Generic Linux",
        version=None,
        codename=None,
        source="unknown",
    )
