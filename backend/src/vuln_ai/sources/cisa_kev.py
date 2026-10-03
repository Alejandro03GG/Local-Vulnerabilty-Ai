"""CISA Known Exploited Vulnerabilities (KEV) source implementation.

Downloads and parses the CISA KEV catalog from the official JSON feed.
Reference: https://www.cisa.gov/known-exploited-vulnerabilities-catalog
"""

from __future__ import annotations

import contextlib
import logging
import time
from datetime import UTC, datetime
from typing import Any

import httpx

from vuln_ai.config import KEVSourceSettings
from vuln_ai.core.exceptions import SourceParseError, SourceSyncError
from vuln_ai.core.models import (
    AffectedVersionRange,
    IdentifierType,
    SyncResult,
    VulnerabilityIdentifier,
    VulnerabilityRecord,
    VulnerabilitySourceRecord,
    normalize_component_name,
)

logger = logging.getLogger(__name__)


class CISAKEVSource:
    """CISA Known Exploited Vulnerabilities catalog source.

    Downloads the full KEV catalog as JSON and normalizes it into canonical
    VulnerabilityRecord instances with structured identifiers, source records
    indicating KEV exploitation evidence, and zero synthetic package ranges.

    CRITICAL ARCHITECTURAL CONSTRAINTS:
    - KEV represents evidence that a CVE is actively exploited in the wild.
    - KEV does NOT provide package ecosystem version ranges (introduced/fixed).
    - NEVER convert vendorProject/product into PyPI/npm/Cargo package ranges.
    - Canonical ID and primary identifier are deterministically set to cveID.
    """

    def __init__(
        self,
        settings: KEVSourceSettings | None = None,
        http_client: httpx.AsyncClient | None = None,
    ) -> None:
        self._settings = settings or KEVSourceSettings()
        self._client = http_client
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

    @property
    def records(self) -> list[VulnerabilityRecord]:
        """Access the currently loaded records."""
        return self._records

    async def _get_client(self) -> tuple[httpx.AsyncClient, bool]:
        """Return the async client and whether it should be closed by the caller."""
        if self._client is not None:
            return self._client, False
        return (
            httpx.AsyncClient(
                timeout=self._settings.timeout_seconds,
                follow_redirects=True,
            ),
            True,
        )

    async def _download(self, url: str) -> dict[str, Any]:
        """Download the KEV JSON feed."""
        client, should_close = await self._get_client()
        try:
            response = await client.get(
                url,
                headers={"User-Agent": self._settings.user_agent},
            )
            response.raise_for_status()
            try:
                data = response.json()
            except Exception as json_err:
                raise SourceParseError(
                    f"Invalid JSON in KEV feed from {url}: {json_err}"
                ) from json_err

            if not isinstance(data, dict):
                raise SourceParseError(f"KEV response from {url} is not a JSON object")
            return data

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
        except SourceParseError:
            raise
        except Exception as exc:
            raise SourceSyncError(
                f"Unexpected error downloading KEV catalog from {url}: {exc}"
            ) from exc
        finally:
            if should_close:
                await client.aclose()

    def normalize(self, raw_data: dict[str, Any]) -> VulnerabilityRecord:
        """Transform raw CISA KEV catalog entry into canonical VulnerabilityRecord.

        Extracts:
        - canonical_id & cve_id (CVE-YYYY-NNNN)
        - Structured identifier with type CVE and source CISA KEV
        - Source record with has_kev_evidence=True, has_affected_range=False,
          and complete raw_payload preservation
        - Evidence metadata: dateAdded, dueDate, requiredAction,
          knownRansomwareCampaignUse, cwes, notes
        - Sets affected_ranges = [] (CISA KEV does not provide package version ranges)
        """
        if not isinstance(raw_data, dict):
            raise SourceParseError("KEV entry must be a dictionary")

        raw_cve = raw_data.get("cveID")
        if not raw_cve or not isinstance(raw_cve, str) or not raw_cve.strip():
            raise SourceParseError("Missing cveID in KEV entry")

        cve_id = raw_cve.strip().upper()
        if not cve_id.startswith("CVE-"):
            raise SourceParseError(f"Invalid cveID '{cve_id}', expected format CVE-YYYY-NNNN")

        vendor_project = str(raw_data.get("vendorProject") or "").strip()
        product = str(raw_data.get("product") or "").strip()
        if not vendor_project or not product:
            raise SourceParseError(f"Missing vendorProject or product for {cve_id}")

        vulnerability_name = str(raw_data.get("vulnerabilityName") or "").strip()
        short_description = str(raw_data.get("shortDescription") or "").strip()
        required_action = str(raw_data.get("requiredAction") or "").strip()
        notes = str(raw_data.get("notes") or "").strip()

        # Parse dates
        date_added = self._parse_date(raw_data.get("dateAdded"))
        due_date = self._parse_date(raw_data.get("dueDate"))

        # Parse ransomware campaign use safely (never infer RiskLevel/VULNERABLE here)
        raw_ransomware = raw_data.get("knownRansomwareCampaignUse")
        if isinstance(raw_ransomware, bool):
            known_ransomware = "Known" if raw_ransomware else "Unknown"
        elif isinstance(raw_ransomware, str):
            val = raw_ransomware.strip()
            if val.lower() in ("known", "yes", "true"):
                known_ransomware = "Known"
            elif val.lower() in ("unknown", "no", "false"):
                known_ransomware = "Unknown"
            else:
                known_ransomware = val
        else:
            known_ransomware = "Unknown"

        # Parse CWEs
        cwes: list[str] = []
        raw_cwes = raw_data.get("cwes")
        if isinstance(raw_cwes, list):
            for c in raw_cwes:
                if isinstance(c, str) and c.strip():
                    cwes.append(c.strip())
        elif isinstance(raw_cwes, str) and raw_cwes.strip():
            cwes = [c.strip() for c in raw_cwes.split(",") if c.strip()]

        # Structured Identifiers: exactly one CVE identifier for CISA KEV
        identifiers = [
            VulnerabilityIdentifier(
                identifier=cve_id,
                identifier_type=IdentifierType.CVE,
                source=self.name,
            )
        ]

        # Structured Source Record: KEV evidence preserving raw_payload
        source_records = [
            VulnerabilitySourceRecord(
                source_name=self.name,
                source_identifier=cve_id,
                has_kev_evidence=True,
                has_affected_range=False,
                raw_payload=raw_data,
                synced_at=datetime.now(UTC),
            )
        ]

        # CRITICAL RULE: CISA KEV does NOT provide package ecosystem version ranges.
        # NEVER invent package ranges from vendorProject/product.
        affected_ranges: list[AffectedVersionRange] = []

        return VulnerabilityRecord(
            canonical_id=cve_id,
            cve_id=cve_id,
            source_name=self.name,
            vendor_project=vendor_project,
            product=product,
            vulnerability_name=vulnerability_name,
            short_description=short_description,
            required_action=required_action,
            date_added=date_added,
            due_date=due_date,
            known_ransomware_use=known_ransomware,
            cwes=cwes,
            notes=notes,
            identifiers=identifiers,
            source_records=source_records,
            affected_ranges=affected_ranges,
        )

    def _parse_entry(self, entry: dict[str, Any]) -> VulnerabilityRecord:
        """Parse a single KEV vulnerability entry (backward compatibility wrapper for normalize)."""
        return self.normalize(entry)

    def _parse(self, data: dict[str, Any]) -> list[VulnerabilityRecord]:
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
            except (KeyError, ValueError, TypeError, SourceParseError) as exc:
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

    def get_cve(self, cve_id: str) -> VulnerabilityRecord | None:
        """Find a cached vulnerability record by CVE ID."""
        target = cve_id.strip().upper()
        for rec in self._records:
            if rec.canonical_id == target or rec.cve_id == target:
                return rec
        return None

    @staticmethod
    def _parse_date(date_val: Any) -> datetime | None:
        """Parse a date value from KEV (format: YYYY-MM-DD or ISO timestamp)."""
        if not date_val:
            return None
        if isinstance(date_val, datetime):
            return date_val if date_val.tzinfo else date_val.replace(tzinfo=UTC)
        if not isinstance(date_val, str):
            return None

        date_str = date_val.strip()
        if not date_str:
            return None

        dt: datetime | None = None
        # 1. Try ISO format
        with contextlib.suppress(ValueError):
            dt = datetime.fromisoformat(date_str.replace("Z", "+00:00"))

        if dt is None:
            # 2. Try YYYY-MM-DD format
            with contextlib.suppress(ValueError, IndexError):
                parts = date_str.split("-")
                if len(parts) >= 3:
                    dt = datetime(
                        int(parts[0]),
                        int(parts[1]),
                        int(parts[2][:2]),
                    )

        if dt is not None:
            return dt if dt.tzinfo else dt.replace(tzinfo=UTC)
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
