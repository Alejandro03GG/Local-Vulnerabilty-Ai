"""Project schemas for the REST API."""

from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel, Field


class ProjectCreate(BaseModel):
    """Payload to register a new project."""

    name: str = Field(min_length=1, max_length=255, description="Project display name")
    path: str = Field(min_length=1, description="Absolute or relative filesystem path")
    description: str = Field(default="", description="Optional project description")


class ProjectUpdate(BaseModel):
    """Payload to update an existing project."""

    name: str | None = Field(default=None, min_length=1, max_length=255)
    path: str | None = Field(default=None, min_length=1)
    description: str | None = None


class ProjectResponse(BaseModel):
    """Project representation returned by the API."""

    id: str = Field(description="Unique project identifier (UUID)")
    name: str = Field(description="Project name")
    path: str = Field(description="Filesystem path")
    description: str = Field(description="Project description")
    created_at: datetime = Field(description="Creation timestamp")
    updated_at: datetime = Field(description="Last update timestamp")
