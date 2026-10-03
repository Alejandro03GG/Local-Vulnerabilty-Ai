"""Component schemas for the REST API."""

from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel, Field


class ComponentResponse(BaseModel):
    """Component representation returned by the API."""

    id: str = Field(description="Unique component identifier (UUID)")
    project_id: str = Field(description="Associated project ID")
    name: str = Field(description="Package or library name")
    version: str | None = Field(default=None, description="Installed or declared version")
    version_type: str = Field(
        description="Version certainty: exact, semantic, constraint, unknown"
    )
    version_constraint: str | None = Field(
        default=None, description="Original version constraint expression"
    )
    source_file: str = Field(
        description="Manifest or lockfile file where component was discovered"
    )
    ecosystem: str = Field(description="Ecosystem: python, javascript, cargo, etc.")
    component_type: str = Field(description="Component classification: library, framework, etc.")
    is_direct: bool = Field(default=True, description="Whether component is a direct dependency")
    dependency_type: str = Field(
        default="direct", description="Classification: direct or transitive"
    )
    scope: str = Field(default="runtime", description="Scope: runtime, dev, optional, peer")
    manifest_source: str | None = Field(
        default=None, description="Declaring manifest if available"
    )
    lockfile_source: str | None = Field(
        default=None, description="Resolving lockfile if available"
    )
    parent_name: str | None = Field(default=None, description="Direct parent package name")
    dependency_path: list[str] = Field(
        default_factory=list, description="Chain of parent packages from project root"
    )
    detected_at: datetime = Field(description="Timestamp when component was detected")


class DependencyEdgeResponse(BaseModel):
    """Directed dependency relation in project dependency graph."""

    parent_name: str = Field(description="Parent package name")
    parent_version: str | None = Field(default=None, description="Parent version if known")
    child_name: str = Field(description="Child package name")
    child_version: str | None = Field(default=None, description="Child version if known")
    scope: str = Field(default="runtime", description="Dependency scope")
    requirement: str | None = Field(default=None, description="Declared requirement expression")


class DependencyGraphResponse(BaseModel):
    """Project dependency graph summary and relations."""

    project_id: str = Field(description="Project ID")
    direct_count: int = Field(default=0, description="Total direct dependencies")
    transitive_count: int = Field(default=0, description="Total transitive dependencies")
    edges_count: int = Field(default=0, description="Total relation edges")
    lockfiles_detected: list[str] = Field(default_factory=list, description="Detected lockfiles")
    manifests_detected: list[str] = Field(default_factory=list, description="Detected manifests")
    components: list[ComponentResponse] = Field(
        default_factory=list, description="Resolved components"
    )
    edges: list[DependencyEdgeResponse] = Field(
        default_factory=list, description="Dependency edges"
    )
