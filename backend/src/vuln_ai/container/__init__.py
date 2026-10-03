"""Container & Image Scanning module for Local Vulnerability AI."""

from vuln_ai.container.archive import (
    ArchiveSecurityError,
    ArchiveSecurityLimits,
    SafeArchiveReader,
)
from vuln_ai.container.dockerfile import (
    parse_dockerfile_content,
    parse_dockerfile_file,
)
from vuln_ai.container.graph import build_container_dependency_graph
from vuln_ai.container.manifest import (
    parse_docker_archive_manifest,
    parse_oci_index_or_manifest,
)
from vuln_ai.container.models import (
    BaseImageReference,
    ContainerImage,
    DockerfileDocument,
    DockerfileInstruction,
    DockerfileStage,
    ImageLayer,
    OperatingSystem,
    OSPackage,
)
from vuln_ai.container.os_detect import detect_os_from_files, parse_os_release_text
from vuln_ai.container.os_packages import (
    extract_os_packages_from_files,
    parse_apk_installed,
    parse_dpkg_status,
    parse_rpm_manifest_text,
)
from vuln_ai.container.scanner import ContainerImageScanner
from vuln_ai.container.source import (
    DockerDaemonSource,
    ImageInspectionSummary,
    ImageSource,
    LocalOCIArchiveSource,
    OCIRegistrySource,
)

__all__ = [
    "ArchiveSecurityError",
    "ArchiveSecurityLimits",
    "BaseImageReference",
    "ContainerImage",
    "ContainerImageScanner",
    "DockerDaemonSource",
    "DockerfileDocument",
    "DockerfileInstruction",
    "DockerfileStage",
    "ImageInspectionSummary",
    "ImageLayer",
    "ImageSource",
    "LocalOCIArchiveSource",
    "OCIRegistrySource",
    "OSPackage",
    "OperatingSystem",
    "SafeArchiveReader",
    "build_container_dependency_graph",
    "detect_os_from_files",
    "extract_os_packages_from_files",
    "parse_apk_installed",
    "parse_docker_archive_manifest",
    "parse_dockerfile_content",
    "parse_dockerfile_file",
    "parse_dpkg_status",
    "parse_oci_index_or_manifest",
    "parse_os_release_text",
    "parse_rpm_manifest_text",
]
