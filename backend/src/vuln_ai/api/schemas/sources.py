"""Vulnerability source schemas for the REST API."""

from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel, Field


class SourceResponse(BaseModel):
    """Vulnerability source representation."""

    id: str = Field(description="Unique source identifier (UUID)")
    name: str = Field(description="Source display name, e.g. CISA KEV")
    source_type: str = Field(description="Source classification, e.g. cisa_kev")
    url: str = Field(description="Remote feed or API URL")
    status: str = Field(description="Current status: active, syncing, error, never_synced")
    last_sync: datetime | None = Field(
        default=None, description="Timestamp of last successful sync"
    )
    record_count: int = Field(
        default=0, description="Number of vulnerabilities loaded from source"
    )
    last_error: str | None = Field(default=None, description="Last error message if failed")


class SourceSyncResponse(BaseModel):
    """Result of triggering a source synchronization."""

    source: str = Field(description="Source name")
    success: bool = Field(description="Whether synchronization completed successfully")
    records: int = Field(description="Number of records imported or updated")
    error: str | None = Field(default=None, description="Error details if sync failed")
    duration: float = Field(description="Duration in seconds")
