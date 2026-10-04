"""Pydantic schemas for Container and Image API endpoints."""

from __future__ import annotations

from datetime import datetime
from typing import Any

from pydantic import BaseModel, Field


class ContainerScanRequest(BaseModel):
    """Request payload to initiate a container image scan."""

    archive_path: str = Field(description="Local filesystem path to container tarball (.tar)")
    reference: str | None = Field(default=None, description="Optional custom image tag/reference")
    policy_id: str | None = Field(
        default=None, description="Optional policy ID or name to evaluate"
    )
    no_ai: bool = Field(default=False, description="Disable AI-assisted analysis")


class ContainerLayerResponse(BaseModel):
    """Container filesystem layer response item."""

    id: str
    layer_index: int
    digest: str
    size_bytes: int
    media_type: str
    command: str | None = None


class ContainerImageResponse(BaseModel):
    """Container image metadata response."""

    id: str
    scan_id: str
    reference: str
    digest: str | None = None
    architecture: str
    os: str
    os_family: str | None = None
    os_version: str | None = None
    os_codename: str | None = None
    source_type: str
    source_path: str
    created_at: datetime
    layer_count: int = 0
    layers: list[ContainerLayerResponse] = Field(default_factory=list)
    metadata: dict[str, Any] = Field(default_factory=dict)
    dockerfile_ast: dict[str, Any] | None = Field(
        default=None, description="Persisted Dockerfile AST when source_type=dockerfile"
    )


class ContainerComponentResponse(BaseModel):
    """Component detected inside container OS or application runtime."""

    id: str
    name: str
    version: str | None = None
    ecosystem: str
    component_type: str
    layer_digest: str | None = None
    container_path: str = ""
    stage: str = "runtime"
    package_manager: str | None = None
    is_direct: bool = True


class DockerfileScanRequest(BaseModel):
    """Request payload to analyze a Dockerfile statically."""

    content: str | None = Field(default=None, description="Raw Dockerfile content string")
    path: str | None = Field(default=None, description="Filesystem path to Dockerfile")
    persist: bool = Field(
        default=True,
        description="Persist Dockerfile AST as a container image record (H9)",
    )


class DockerfileScanResponse(BaseModel):
    """Structured AST response for Dockerfile static inspection."""

    source_file: str
    stages: list[dict[str, Any]]
    base_images: list[dict[str, Any]]
    package_installations: list[dict[str, Any]]
    copied_files: list[dict[str, Any]]
    dependency_manifests: list[str]
    image_id: str | None = Field(
        default=None, description="Persisted container image ID when persist=true"
    )
    scan_id: str | None = Field(default=None, description="Associated scan ID when persisted")
