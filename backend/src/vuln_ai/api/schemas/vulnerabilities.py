"""Vulnerability schemas for the REST API."""

from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel, Field


class VulnerabilityResponse(BaseModel):
    """Vulnerability record representation returned by the API."""

    id: str = Field(description="Unique vulnerability identifier (UUID)")
    cve_id: str = Field(description="CVE identifier, e.g. CVE-2021-44228")
    source_id: str = Field(description="Source identifier (UUID)")
    vendor_project: str = Field(description="Vendor or organization")
    product: str = Field(description="Affected product or software component name")
    vulnerability_name: str = Field(description="Short human-readable title")
    short_description: str = Field(description="Description of the vulnerability")
    required_action: str = Field(description="Action required to remediate")
    date_added: str | None = Field(default=None, description="Date added to catalog (YYYY-MM-DD)")
    due_date: str | None = Field(default=None, description="Due date for remediation (YYYY-MM-DD)")
    known_ransomware_use: str = Field(description="Known ransomware campaign association")
    cwes: list[str] = Field(default_factory=list, description="Associated CWE identifiers")
    notes: str = Field(default="", description="Additional notes or references")
    synced_at: datetime = Field(description="Timestamp when vulnerability was synced locally")
