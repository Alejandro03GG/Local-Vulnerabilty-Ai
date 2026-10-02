"""Common schemas for the REST API."""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, Field


class ErrorDetail(BaseModel):
    """Structured error detail."""

    code: str = Field(description="Machine-readable error code")
    message: str = Field(description="Human-readable error description")
    details: dict[str, Any] = Field(
        default_factory=dict,
        description="Additional context or validation details",
    )


class ErrorResponse(BaseModel):
    """Consistent API error response envelope."""

    error: ErrorDetail


class PaginatedResponse[T](BaseModel):
    """Generic paginated response envelope."""

    items: list[T] = Field(description="Page items")
    page: int = Field(ge=1, description="Current page number (1-based)")
    page_size: int = Field(ge=1, description="Page size limit")
    total: int = Field(ge=0, description="Total number of items matching query")
