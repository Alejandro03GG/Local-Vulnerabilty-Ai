"""Domain models for Container & Image Scanning.

These Pydantic models represent container images, layers, operating systems,
OS packages, Dockerfile AST structures, and container scan outputs.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from pydantic import BaseModel, Field

from vuln_ai.core.models import ComponentType, DetectedComponent, Ecosystem, VersionType


class OperatingSystem(BaseModel):
    """Detected operating system within an image filesystem."""

    family: str = Field(default="linux", description="OS family (e.g. debian, alpine, redhat)")
    name: str = Field(description="OS distribution name (e.g. Debian GNU/Linux, Alpine Linux)")
    version: str | None = Field(
        default=None, description="Distribution version (e.g. 12.5, 3.19.1)"
    )
    codename: str | None = Field(default=None, description="Distribution codename (e.g. bookworm)")
    source: str = Field(default="/etc/os-release", description="Source file proving OS detection")


class ImageLayer(BaseModel):
    """Metadata for an individual container filesystem layer."""

    digest: str = Field(description="Layer content digest (sha256:...)")
    index: int = Field(description="0-based layer index preserving execution order")
    size_bytes: int = Field(
        default=0, description="Uncompressed or compressed layer size in bytes"
    )
    media_type: str = Field(default="application/vnd.docker.image.rootfs.diff.tar.gzip")
    command: str | None = Field(
        default=None, description="Dockerfile instruction creating this layer"
    )
    source: str = Field(default="layer_archive", description="Provenance of layer tarball")
    metadata: dict[str, Any] = Field(default_factory=dict, description="Arbitrary layer metadata")


class ContainerImage(BaseModel):
    """A container image artifact subject to static inspection."""

    id: str = Field(description="Unique internal ID or UUID")
    reference: str = Field(description="Image repository:tag or human-readable reference")
    digest: str | None = Field(
        default=None, description="Immutable cryptographic digest (sha256:...)"
    )
    architecture: str = Field(
        default="amd64", description="Target CPU architecture (e.g. amd64, arm64)"
    )
    os: str = Field(default="linux", description="Target OS (e.g. linux)")
    operating_system: OperatingSystem | None = Field(
        default=None, description="Detailed resolved OS"
    )
    created_at: datetime = Field(
        default_factory=lambda: datetime.now(UTC), description="Image creation timestamp"
    )
    source_type: str = Field(
        default="oci_archive", description="Source format: oci_archive, docker_archive, etc."
    )
    source_path: str = Field(default="", description="Path or location of the image archive")
    layers: list[ImageLayer] = Field(default_factory=list, description="Ordered layer stack")
    metadata: dict[str, Any] = Field(default_factory=dict, description="Arbitrary image metadata")


class OSPackage(BaseModel):
    """A system-level package installed in the container OS."""

    name: str = Field(description="Package name (e.g. libssl3, curl, apk-tools)")
    version: str = Field(description="Installed version string")
    architecture: str | None = Field(default=None, description="Architecture (e.g. amd64, x86_64)")
    ecosystem: Ecosystem = Field(default=Ecosystem.DEB, description="deb, apk, or rpm")
    manager: str = Field(default="dpkg", description="dpkg, apk, or rpm")
    source_file: str = Field(description="Path in image (e.g. /var/lib/dpkg/status)")
    layer_digest: str | None = Field(
        default=None, description="Digest of layer containing this package"
    )
    description: str | None = Field(default=None, description="Package description if available")
    dependencies: list[str] = Field(
        default_factory=list, description="Direct package dependencies"
    )
    metadata: dict[str, Any] = Field(default_factory=dict, description="Package metadata")

    def to_detected_component(self) -> DetectedComponent:
        """Convert this OS package into the standard DetectedComponent for the Security Engine."""
        meta = dict(self.metadata)
        if self.layer_digest:
            meta["container_layer"] = self.layer_digest
        if self.architecture:
            meta["architecture"] = self.architecture
        meta["package_manager"] = self.manager
        meta["container_path"] = self.source_file

        return DetectedComponent(
            name=self.name,
            version=self.version,
            version_type=VersionType.EXACT,
            ecosystem=self.ecosystem,
            source_file=self.source_file,
            component_type=ComponentType.OS_PACKAGE,
            is_direct=True,
            metadata=meta,
        )


class BaseImageReference(BaseModel):
    """Reference to a base image in a Dockerfile."""

    name: str = Field(description="Base image repository or name (e.g. python, node, ubuntu)")
    tag: str = Field(default="latest", description="Tag specified (e.g. 3.12-slim, 22-alpine)")
    digest: str | None = Field(
        default=None, description="Cryptographic digest if pinned (sha256:...)"
    )
    stage: str | None = Field(default=None, description="Stage alias if defined (AS builder)")
    source_location: str = Field(default="", description="Source file and line number")


class DockerfileInstruction(BaseModel):
    """An individual structured instruction in a Dockerfile AST."""

    line_number: int = Field(description="1-indexed line number in Dockerfile")
    instruction: str = Field(description="Uppercase instruction name (FROM, RUN, COPY, ADD, etc.)")
    arguments: str = Field(description="Arguments string after the instruction verb")
    stage: str = Field(default="default", description="Stage name or index")
    raw: str = Field(description="Exact raw text line from Dockerfile")


class DockerfileStage(BaseModel):
    """A build stage in a multi-stage Dockerfile."""

    index: int = Field(description="0-indexed stage sequence")
    name: str = Field(description="Stage name or index")
    base_image: BaseImageReference = Field(description="Base image referenced in FROM")
    instructions: list[DockerfileInstruction] = Field(default_factory=list)
    is_runtime: bool = Field(
        default=True, description="Whether this stage forms the final runtime image"
    )


class DockerfileDocument(BaseModel):
    """Structured AST representation of a Dockerfile."""

    source_file: str = Field(default="Dockerfile")
    stages: list[DockerfileStage] = Field(default_factory=list)
    instructions: list[DockerfileInstruction] = Field(default_factory=list)
    base_images: list[BaseImageReference] = Field(default_factory=list)
    package_installations: list[dict[str, Any]] = Field(
        default_factory=list,
        description="Detected package installations from RUN commands (apt-get, apk, pip, etc.)",
    )
    copied_files: list[dict[str, Any]] = Field(
        default_factory=list,
        description="Files copied into the image via COPY or ADD",
    )
    dependency_manifests: list[str] = Field(
        default_factory=list,
        description="Application dependency manifests identified (e.g. requirements.txt, package.json)",
    )
