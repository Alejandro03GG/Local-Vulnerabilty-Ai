"""CISA Known Exploited Vulnerabilities (KEV) source implementation.

Downloads and parses the CISA KEV catalog from the official JSON feed.
Reference: https://www.cisa.gov/known-exploited-vulnerabilities-catalog
"""

from __future__ import annotations

import logging
import time
from datetime import UTC, datetime

import httpx

from vuln_ai.config import KEVSourceSettings
from vuln_ai.core.exceptions import SourceParseError, SourceSyncError
from vuln_ai.core.models import (
    SyncResult,
    VulnerabilityRecord,
    normalize_component_name,
)

logger = logging.getLogger(__name__)


class CISAKEVSource:
    """CISA Known Exploited Vulnerabilities catalog source.

    Downloads the full KEV catalog as JSON and parses it into
    VulnerabilityRecord objects for storage and matching.

    Note: KEV does NOT include version ranges. It only provides
    vendorProject and product names. Version-based matching
    requires additional sources (NVD, OSV) in future phases.
    """

    def __init__(self, settings: KEVSourceSettings | None = None) -> None:
        self._settings = settings or KEVSourceSettings()
        self._records: list[VulnerabilityRecord] = []

    @property
    def name(self) -> str:
        return "CISA KEV"

    @property
    def source_type(self) -> str:
        return "kev"

    @property
    def url(self) -> str:
        return self._settings.url

    async def sync(self) -> SyncResult:
        """Download and parse the KEV catalog.

        Tries the primary URL first, then falls back to the GitHub mirror.
        """
        start_time = time.monotonic()

        for attempt, feed_url in enumerate(
            [self._settings.url, self._settings.mirror_url], start=1
        ):
            try:
                raw_data = await self._download(feed_url)
                records = self._parse(raw_data)
                self._records = records
                duration = time.monotonic() - start_time

                logger.info(
                    "KEV sync completed: %d records in %.2fs from %s",
                    len(records),
                    duration,
                    feed_url,
                )

                return SyncResult(
                    source_name=self.name,
                    success=True,
                    records_synced=len(records),
                    records_total=len(records),
                    duration_seconds=duration,
                )

            except (SourceSyncError, SourceParseError) as exc:
                logger.warning(
                    "KEV sync attempt %d failed (%s): %s",
                    attempt,
                    feed_url,
                    exc,
                )
                if attempt >= 2:
                    duration = time.monotonic() - start_time
                    return SyncResult(
                        source_name=self.name,
                        success=False,
                        error=str(exc),
                        duration_seconds=duration,
                    )

        # Should not reach here, but just in case
        duration = time.monotonic() - start_time
        return SyncResult(
            source_name=self.name,
            success=False,
            error="All sync attempts exhausted",
            duration_seconds=duration,
        )

    async def search(
        self,
        component: str,
        vendor: str | None = None,
        product: str | None = None,
    ) -> list[VulnerabilityRecord]:
        """Search cached KEV records by component, vendor, or product.

        Uses normalized name matching.
        """
        normalized = normalize_component_name(component)
        results = []

        for record in self._records:
            if self._matches(normalized, record, vendor, product):
                results.append(record)

        return results

    @property
    def records(self) -> list[VulnerabilityRecord]:
        """Access the currently loaded records."""
        return self._records

    async def _download(self, url: str) -> dict:
        """Download the KEV JSON feed."""
        try:
            async with httpx.AsyncClient(
                timeout=self._settings.timeout_seconds,
                follow_redirects=True,
            ) as client:
                response = await client.get(
                    url,
                    headers={"User-Agent": self._settings.user_agent},
                )
                response.raise_for_status()
                return response.json()

        except httpx.TimeoutException as exc:
            raise SourceSyncError(f"Timeout downloading KEV catalog from {url}") from exc
        except httpx.HTTPStatusError as exc:
            raise SourceSyncError(
                f"HTTP {exc.response.status_code} downloading KEV catalog from {url}"
            ) from exc
        except httpx.RequestError as exc:
            raise SourceSyncError(
                f"Network error downloading KEV catalog from {url}: {exc}"
            ) from exc
        except Exception as exc:
            raise SourceSyncError(
                f"Unexpected error downloading KEV catalog from {url}: {exc}"
            ) from exc

    def _parse(self, data: dict) -> list[VulnerabilityRecord]:
        """Parse the KEV JSON into VulnerabilityRecord objects.

        Validates the expected structure and handles missing fields gracefully.
        """
        if not isinstance(data, dict):
            raise SourceParseError("KEV data is not a JSON object")

        vulnerabilities = data.get("vulnerabilities")
        if vulnerabilities is None:
            raise SourceParseError("KEV data missing 'vulnerabilities' key")

        if not isinstance(vulnerabilities, list):
            raise SourceParseError("KEV 'vulnerabilities' is not an array")

        records: list[VulnerabilityRecord] = []
        parse_errors = 0

        for i, entry in enumerate(vulnerabilities):
            try:
                record = self._parse_entry(entry)
                records.append(record)
            except (KeyError, ValueError, TypeError) as exc:
                parse_errors += 1
                logger.debug("Failed to parse KEV entry %d: %s", i, exc)
                if parse_errors > 100:
                    raise SourceParseError(
                        f"Too many parse errors ({parse_errors}), aborting"
                    ) from exc

        if not records and vulnerabilities:
            raise SourceParseError(f"No records parsed from {len(vulnerabilities)} entries")

        if parse_errors > 0:
            logger.warning(
                "KEV parse completed with %d errors out of %d entries",
                parse_errors,
                len(vulnerabilities),
            )

        return records

    def _parse_entry(self, entry: dict) -> VulnerabilityRecord:
        """Parse a single KEV vulnerability entry."""
        cve_id = entry.get("cveID", "")
        if not cve_id:
            raise ValueError("Missing cveID")

        vendor_project = entry.get("vendorProject", "")
        product = entry.get("product", "")
        if not vendor_project or not product:
            raise ValueError(f"Missing vendor/product for {cve_id}")

        # Parse dates
        date_added = self._parse_date(entry.get("dateAdded"))
        due_date = self._parse_date(entry.get("dueDate"))

        # Parse CWEs (may be a list or absent)
        cwes = entry.get("cwes", [])
        if not isinstance(cwes, list):
            cwes = []

        return VulnerabilityRecord(
            cve_id=cve_id,
            source_name=self.name,
            vendor_project=vendor_project,
            product=product,
            vulnerability_name=entry.get("vulnerabilityName", ""),
            short_description=entry.get("shortDescription", ""),
            required_action=entry.get("requiredAction", ""),
            date_added=date_added,
            due_date=due_date,
            known_ransomware_use=entry.get("knownRansomwareCampaignUse", "Unknown"),
            cwes=cwes,
            notes=entry.get("notes", ""),
        )

    @staticmethod
    def _parse_date(date_str: str | None) -> datetime | None:
        """Parse a date string from KEV (format: YYYY-MM-DD)."""
        if not date_str:
            return None
        try:
            parts = date_str.split("-")
            return datetime(
                int(parts[0]),
                int(parts[1]),
                int(parts[2]),
                tzinfo=UTC,
            )
        except (ValueError, IndexError):
            return None

    @staticmethod
    def _matches(
        normalized_name: str,
        record: VulnerabilityRecord,
        vendor: str | None,
        product: str | None,
    ) -> bool:
        """Check if a record matches search criteria."""
        norm_vendor = record.normalized_vendor()
        norm_product = record.normalized_product()

        # If explicit vendor/product filters are given, use them
        if vendor is not None:
            norm_search_vendor = normalize_component_name(vendor)
            if norm_search_vendor != norm_vendor:
                return False

        if product is not None:
            norm_search_product = normalize_component_name(product)
            if norm_search_product != norm_product:
                return False

        # Match component name against vendor or product
        if normalized_name == norm_product:
            return True
        if normalized_name == norm_vendor:
            return True

        # Check if the component name appears in the product name
        # (conservative: only exact substring of normalized form)
        return bool(normalized_name and normalized_name in norm_product)
