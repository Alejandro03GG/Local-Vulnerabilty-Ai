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
    source_file: str = Field(description="Manifest file where component was discovered")
    ecosystem: str = Field(description="Ecosystem: python, javascript, etc.")
    component_type: str = Field(description="Component classification: library, framework, etc.")
    detected_at: datetime = Field(description="Timestamp when component was detected")
