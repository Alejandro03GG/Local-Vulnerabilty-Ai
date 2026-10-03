"""OSV (Open Source Vulnerabilities) source adapter implementation.

Queries the distributed OSV database API (https://api.osv.dev/v1) and normalizes
records into canonical VulnerabilityRecord instances with structured identifiers,
affected version ranges, and source provenance.
Reference: https://ossf.github.io/osv-schema/
"""

from __future__ import annotations

import contextlib
import logging
from datetime import UTC, datetime
from typing import Any

import httpx

from vuln_ai.config import OSVSourceSettings
from vuln_ai.core.exceptions import SourceParseError, SourceSyncError
from vuln_ai.core.models import (
    AffectedVersionRange,
    Ecosystem,
    IdentifierType,
    SyncResult,
    VulnerabilityIdentifier,
    VulnerabilityRecord,
    VulnerabilitySourceRecord,
    normalize_component_name,
)

logger = logging.getLogger(__name__)


def map_osv_ecosystem(ecosystem_str: str) -> str:
    """Map OSV ecosystem naming to internal Ecosystem enum string.

    Examples:
        >>> map_osv_ecosystem("PyPI")
        'pypi'
        >>> map_osv_ecosystem("npm")
        'npm'
        >>> map_osv_ecosystem("Go")
        'go'
        >>> map_osv_ecosystem("crates.io")
        'cargo'
    """
    cleaned = ecosystem_str.strip().lower()
    mapping = {
        "pypi": "pypi",
        "npm": "npm",
        "go": "go",
        "cargo": "cargo",
        "crates.io": "cargo",
        "maven": "maven",
        "nuget": "nuget",
        "rubygems": "rubygems",
        "packagist": "packagist",
        "hex": "hex",
        "pub": "pub",
    }
    return mapping.get(cleaned, cleaned)


def map_to_osv_ecosystem(internal_ecosystem: str | Ecosystem) -> str:
    """Map internal ecosystem string to official OSV ecosystem name."""
    val = (
        internal_ecosystem.value
        if isinstance(internal_ecosystem, Ecosystem)
        else str(internal_ecosystem).lower()
    )
    mapping = {
        "pypi": "PyPI",
        "npm": "npm",
        "go": "Go",
        "cargo": "crates.io",
        "maven": "Maven",
        "nuget": "NuGet",
        "rubygems": "RubyGems",
    }
    return mapping.get(val, val)


def determine_canonical_id(osv_id: str, aliases: list[str]) -> tuple[str, str | None]:
    """Deterministically select canonical_id and cve_id from OSV id and aliases.

    Priority:
    1. First CVE (e.g. CVE-2024-1234)
    2. First GHSA (e.g. GHSA-xxxx-yyyy-zzzz)
    3. OSV native ID (e.g. PYSEC-xxx, GO-xxx, OSV-xxx)
    4. Any other alias

    Returns:
        tuple[canonical_id, cve_id]
    """
    all_ids = [osv_id] + [a for a in aliases if a != osv_id]

    cves = sorted([i for i in all_ids if i.upper().startswith("CVE-")])
    if cves:
        return cves[0], cves[0]

    ghsas = sorted([i for i in all_ids if i.upper().startswith("GHSA-")])
    if ghsas:
        return ghsas[0], None

    return osv_id, None


def determine_identifier_type(ident: str) -> IdentifierType:
    """Categorize an identifier string into an IdentifierType."""
    ident_up = ident.upper()
    if ident_up.startswith("CVE-"):
        return IdentifierType.CVE
    if ident_up.startswith("GHSA-"):
        return IdentifierType.GHSA
    if ident_up.startswith("OSV-"):
        return IdentifierType.OSV
    if ident_up.startswith("PYSEC-"):
        return IdentifierType.PYSEC
    return IdentifierType.ALIAS


class OSVSource:
    """OSV (Open Source Vulnerabilities) source adapter.

    Queries package-level vulnerabilities via OSV REST API v1 and normalizes
    them into canonical domain representations.
    """

    def __init__(
        self,
        settings: OSVSourceSettings | None = None,
        http_client: httpx.AsyncClient | None = None,
    ) -> None:
        self._settings = settings or OSVSourceSettings()
        self._client = http_client
        self._cached_records: list[VulnerabilityRecord] = []

    @property
    def records(self) -> list[VulnerabilityRecord]:
        return self._cached_records

    @property
    def name(self) -> str:
        return "OSV"

    @property
    def source_type(self) -> str:
        return "osv"

    @property
    def url(self) -> str:
        return self._settings.base_url

    async def _get_client(self) -> httpx.AsyncClient:
        if self._client is not None:
            return self._client
        return httpx.AsyncClient(
            timeout=self._settings.timeout_seconds,
            headers={"User-Agent": self._settings.user_agent},
        )

    async def query_package(
        self,
        package_name: str,
        ecosystem: str | Ecosystem = Ecosystem.PYPI,
    ) -> list[VulnerabilityRecord]:
        """Query OSV API for vulnerabilities affecting a specific package.

        Args:
            package_name: Name of package (e.g. 'requests', 'lodash').
            ecosystem: Target ecosystem (e.g. 'pypi', 'npm').

        Returns:
            List of normalized canonical VulnerabilityRecords.
        """
        osv_ecosystem = map_to_osv_ecosystem(ecosystem)
        endpoint = f"{self._settings.base_url.rstrip('/')}/query"
        payload = {
            "package": {
                "name": package_name,
                "ecosystem": osv_ecosystem,
            }
        }

        raw_json = await self._post_json(endpoint, payload)
        vulns_data = raw_json.get("vulns", [])
        if not isinstance(vulns_data, list):
            raise SourceParseError(f"Expected 'vulns' list from OSV, got {type(vulns_data)}")

        records = [self.normalize(v) for v in vulns_data]
        self._cached_records.extend(records)
        return records

    async def query_batch(
        self,
        queries: list[tuple[str, str | Ecosystem]],
    ) -> list[VulnerabilityRecord]:
        """Query OSV API for multiple packages in batch.

        Args:
            queries: List of (package_name, ecosystem) tuples.

        Returns:
            Combined list of normalized canonical VulnerabilityRecords.
        """
        if not queries:
            return []

        endpoint = f"{self._settings.base_url.rstrip('/')}/querybatch"
        payload = {
            "queries": [
                {
                    "package": {
                        "name": pkg,
                        "ecosystem": map_to_osv_ecosystem(eco),
                    }
                }
                for pkg, eco in queries
            ]
        }

        raw_json = await self._post_json(endpoint, payload)
        results = raw_json.get("results", [])
        if not isinstance(results, list):
            raise SourceParseError("Expected 'results' list from OSV querybatch")

        all_records: list[VulnerabilityRecord] = []
        for batch_item in results:
            vulns_data = batch_item.get("vulns", [])
            if isinstance(vulns_data, list):
                for v in vulns_data:
                    all_records.append(self.normalize(v))

        self._cached_records.extend(all_records)
        return all_records

    async def get_by_id(self, osv_id: str) -> VulnerabilityRecord | None:
        """Fetch full vulnerability details by OSV ID (e.g. GHSA-xxx, CVE-xxx)."""
        endpoint = f"{self._settings.base_url.rstrip('/')}/vulns/{osv_id}"
        client = await self._get_client()
        should_close = self._client is None

        try:
            resp = await client.get(endpoint)
            if resp.status_code == 404:
                return None
            resp.raise_for_status()
            return self.normalize(resp.json())
        except httpx.TimeoutException as exc:
            raise SourceSyncError(f"Timeout fetching OSV vulnerability '{osv_id}': {exc}") from exc
        except httpx.HTTPStatusError as exc:
            raise SourceSyncError(
                f"HTTP error {exc.response.status_code} fetching OSV '{osv_id}': {exc}"
            ) from exc
        except httpx.RequestError as exc:
            raise SourceSyncError(f"Connection error fetching OSV '{osv_id}': {exc}") from exc
        except Exception as exc:
            raise SourceParseError(f"Failed to parse OSV vulnerability '{osv_id}': {exc}") from exc
        finally:
            if should_close:
                await client.aclose()

    async def sync(self) -> SyncResult:
        """Execute a synchronization check against OSV.

        Since OSV contains millions of records, sync validates connectivity and
        reports available status. Direct package scans query OSV on demand.
        """
        start = datetime.now(UTC)
        try:
            # Probe OSV with a lightweight query to verify operational availability
            probe = await self.query_package("requests", Ecosystem.PYPI)
            duration = (datetime.now(UTC) - start).total_seconds()
            return SyncResult(
                source_name=self.name,
                success=True,
                records_synced=len(probe),
                records_total=len(self._cached_records),
                duration_seconds=duration,
            )
        except Exception as exc:
            duration = (datetime.now(UTC) - start).total_seconds()
            return SyncResult(
                source_name=self.name,
                success=False,
                error=str(exc),
                duration_seconds=duration,
            )

    async def search(
        self,
        component: str,
        vendor: str | None = None,
        product: str | None = None,
    ) -> list[VulnerabilityRecord]:
        """Search local in-memory records matching component name."""
        norm = normalize_component_name(component)
        matches = []
        for r in self._cached_records:
            if norm in r.normalized_product() or any(
                norm == normalize_component_name(ar.package_name) for ar in r.affected_ranges
            ):
                matches.append(r)
        return matches

    def normalize(self, raw_data: dict[str, Any]) -> VulnerabilityRecord:
        """Transform raw OSV schema payload into canonical VulnerabilityRecord.

        Extracts:
        - canonical_id & cve_id deterministically
        - All identifiers / aliases without loss
        - Structured affected version ranges (introduced, fixed, last_affected, raw_range)
        - Severity / CVSS metadata
        - Auditable source record with raw payload
        """
        if not isinstance(raw_data, dict) or "id" not in raw_data:
            raise SourceParseError("OSV record must be a dict containing an 'id' field")

        osv_id = str(raw_data["id"]).strip()
        raw_aliases = raw_data.get("aliases", [])
        aliases = [str(a).strip() for a in raw_aliases if isinstance(a, str)]

        canonical_id, cve_id = determine_canonical_id(osv_id, aliases)

        # 1. Build Identifiers list
        identifiers: list[VulnerabilityIdentifier] = []
        seen_idents: set[str] = set()

        all_ids = [osv_id] + [a for a in aliases if a != osv_id]
        for ident in all_ids:
            if ident not in seen_idents:
                seen_idents.add(ident)
                identifiers.append(
                    VulnerabilityIdentifier(
                        identifier=ident,
                        identifier_type=determine_identifier_type(ident),
                        source="OSV",
                    )
                )

        # 2. Parse affected ranges
        affected_ranges: list[AffectedVersionRange] = []
        primary_package = ""
        vendor_project = ""

        raw_affected = raw_data.get("affected", [])
        if isinstance(raw_affected, list):
            for aff_item in raw_affected:
                if not isinstance(aff_item, dict):
                    continue
                pkg_info = aff_item.get("package", {})
                pkg_name = pkg_info.get("name", "")
                raw_eco = pkg_info.get("ecosystem", "unknown")
                internal_eco = map_osv_ecosystem(raw_eco)

                if not primary_package and pkg_name:
                    primary_package = pkg_name

                # Parse ranges inside affected item
                ranges_data = aff_item.get("ranges", [])
                if isinstance(ranges_data, list):
                    for r_entry in ranges_data:
                        if not isinstance(r_entry, dict):
                            continue
                        r_type = r_entry.get("type", "ECOSYSTEM").lower()
                        events = r_entry.get("events", [])
                        if not isinstance(events, list):
                            continue

                        current_introduced: str | None = None
                        for ev in events:
                            if not isinstance(ev, dict):
                                continue
                            if "introduced" in ev:
                                current_introduced = str(ev["introduced"]).strip()
                            elif "fixed" in ev:
                                fixed_val = str(ev["fixed"]).strip()
                                raw_expr = (
                                    f">= {current_introduced}, < {fixed_val}"
                                    if current_introduced and current_introduced != "0"
                                    else f"< {fixed_val}"
                                )
                                affected_ranges.append(
                                    AffectedVersionRange(
                                        ecosystem=internal_eco,
                                        package_name=pkg_name,
                                        range_type=r_type,
                                        introduced=current_introduced,
                                        fixed=fixed_val,
                                        last_affected=None,
                                        raw_range=raw_expr,
                                        source_name="OSV",
                                    )
                                )
                                current_introduced = None
                            elif "last_affected" in ev:
                                last_val = str(ev["last_affected"]).strip()
                                raw_expr = (
                                    f">= {current_introduced}, <= {last_val}"
                                    if current_introduced and current_introduced != "0"
                                    else f"<= {last_val}"
                                )
                                affected_ranges.append(
                                    AffectedVersionRange(
                                        ecosystem=internal_eco,
                                        package_name=pkg_name,
                                        range_type=r_type,
                                        introduced=current_introduced,
                                        fixed=None,
                                        last_affected=last_val,
                                        raw_range=raw_expr,
                                        source_name="OSV",
                                    )
                                )
                                current_introduced = None
                            elif "limit" in ev:
                                limit_val = str(ev["limit"]).strip()
                                raw_expr = (
                                    f">= {current_introduced}, < {limit_val}"
                                    if current_introduced and current_introduced != "0"
                                    else f"< {limit_val}"
                                )
                                affected_ranges.append(
                                    AffectedVersionRange(
                                        ecosystem=internal_eco,
                                        package_name=pkg_name,
                                        range_type=r_type,
                                        introduced=current_introduced,
                                        fixed=None,
                                        last_affected=None,
                                        limit=limit_val,
                                        raw_range=raw_expr,
                                        source_name="OSV",
                                    )
                                )
                                current_introduced = None

                        if current_introduced:
                            affected_ranges.append(
                                AffectedVersionRange(
                                    ecosystem=internal_eco,
                                    package_name=pkg_name,
                                    range_type=r_type,
                                    introduced=current_introduced,
                                    fixed=None,
                                    last_affected=None,
                                    raw_range=f">= {current_introduced}",
                                    source_name="OSV",
                                )
                            )

        # 3. Parse severity & CVSS
        severity_val: str | None = None
        cvss_score: float | None = None

        db_specific = raw_data.get("database_specific", {})
        if isinstance(db_specific, dict) and "severity" in db_specific:
            severity_val = str(db_specific["severity"]).upper()

        severities = raw_data.get("severity", [])
        if isinstance(severities, list):
            for s in severities:
                if isinstance(s, dict) and "score" in s:
                    score_str = str(s["score"])
                    try:
                        cvss_score = float(score_str)
                    except ValueError:
                        # Handle CVSS vector string if base score not explicitly numeric
                        if not severity_val and "CVSS" in s.get("type", ""):
                            severity_val = "CVSS_RATED"

        # 4. Dates
        published_dt = None
        if "published" in raw_data and isinstance(raw_data["published"], str):
            with contextlib.suppress(ValueError):
                published_dt = datetime.fromisoformat(raw_data["published"].replace("Z", "+00:00"))

        # 5. Build Source Record for provenance
        source_record = VulnerabilitySourceRecord(
            source_name="OSV",
            source_identifier=osv_id,
            has_kev_evidence=False,
            has_affected_range=bool(affected_ranges),
            raw_payload=raw_data,
            synced_at=datetime.now(UTC),
        )

        summary = raw_data.get("summary", "")
        details = raw_data.get("details", "")

        return VulnerabilityRecord(
            canonical_id=canonical_id,
            cve_id=cve_id,
            source_name="OSV",
            vendor_project=vendor_project,
            product=primary_package,
            vulnerability_name=summary or osv_id,
            short_description=details or summary or "",
            date_added=published_dt,
            severity=severity_val,
            cvss_score=cvss_score,
            identifiers=identifiers,
            source_records=[source_record],
            affected_ranges=affected_ranges,
        )

    async def _post_json(self, url: str, payload: dict[str, Any]) -> dict[str, Any]:
        """Execute an asynchronous POST request to OSV API."""
        client = await self._get_client()
        should_close = self._client is None

        try:
            resp = await client.post(url, json=payload)
            resp.raise_for_status()
            return resp.json()
        except httpx.TimeoutException as exc:
            raise SourceSyncError(f"Timeout querying OSV API: {exc}") from exc
        except httpx.HTTPStatusError as exc:
            raise SourceSyncError(
                f"HTTP error {exc.response.status_code} querying OSV API: {exc}"
            ) from exc
        except httpx.RequestError as exc:
            raise SourceSyncError(f"Connection failed querying OSV API: {exc}") from exc
        except Exception as exc:
            raise SourceParseError(f"Failed to parse OSV API JSON response: {exc}") from exc
        finally:
            if should_close:
                await client.aclose()
