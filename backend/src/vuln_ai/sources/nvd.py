"""NVD (National Vulnerability Database) source adapter implementation.

Queries the NIST NVD CVE API 2.0 (https://services.nvd.nist.gov/rest/json/cves/2.0)
and normalizes records into canonical VulnerabilityRecord instances with structured
identifiers, CVSS ratings, CWEs, source provenance, and verifiable affected version ranges.
Reference: https://nvd.nist.gov/developers/vulnerabilities
"""

from __future__ import annotations

import contextlib
import logging
from datetime import UTC, datetime
from typing import Any

import httpx

from vuln_ai.config import NVDSourceSettings
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

# Ecosystem mapping from target_sw in CPE 2.3
_TARGET_SW_ECOSYSTEM_MAP: dict[str, tuple[str, str]] = {
    "python": ("pypi", "pep440"),
    "pypi": ("pypi", "pep440"),
    "node.js": ("npm", "semver"),
    "nodejs": ("npm", "semver"),
    "npm": ("npm", "semver"),
    "javascript": ("npm", "semver"),
    "go": ("go", "semver"),
    "golang": ("go", "semver"),
    "rust": ("cargo", "semver"),
    "cargo": ("cargo", "semver"),
    "crates.io": ("cargo", "semver"),
    "ruby": ("rubygems", "semver"),
    "rubygems": ("rubygems", "semver"),
    "java": ("maven", "maven"),
    "maven": ("maven", "maven"),
    "nuget": ("nuget", "semver"),
    "dotnet": ("nuget", "semver"),
}


def parse_cpe_23(cpe_str: str) -> dict[str, str] | None:
    """Parse a CPE 2.3 formatted string into component parts.

    Format: cpe:2.3:part:vendor:product:version:update:edition:language:sw_edition:target_sw:target_hw:other
    """
    if not cpe_str.startswith("cpe:2.3:"):
        return None
    parts = cpe_str.split(":")
    if len(parts) < 5:
        return None
    return {
        "part": parts[2],
        "vendor": parts[3].replace("\\", ""),
        "product": parts[4].replace("\\", ""),
        "version": parts[5].replace("\\", "") if len(parts) > 5 else "*",
        "update": parts[6].replace("\\", "") if len(parts) > 6 else "*",
        "edition": parts[7].replace("\\", "") if len(parts) > 7 else "*",
        "language": parts[8].replace("\\", "") if len(parts) > 8 else "*",
        "sw_edition": parts[9].replace("\\", "") if len(parts) > 9 else "*",
        "target_sw": parts[10].replace("\\", "").lower() if len(parts) > 10 else "*",
        "target_hw": parts[11].replace("\\", "") if len(parts) > 11 else "*",
        "other": parts[12].replace("\\", "") if len(parts) > 12 else "*",
    }


def map_cpe_to_package_ecosystem(
    cpe_dict: dict[str, str],
) -> tuple[str, str, str] | None:
    """Safely map a parsed CPE 2.3 dict to (ecosystem, package_name, range_type).

    CRITICAL RULE:
    Returns None if the CPE cannot be safely and unambiguously mapped to a package ecosystem.
    Never assumes a generic application CPE (e.g. apache:httpd) is a PyPI or npm package.
    """
    # Only application ('a') part can map to software packages
    if cpe_dict.get("part") != "a":
        return None

    target_sw = cpe_dict.get("target_sw", "*")
    if target_sw in _TARGET_SW_ECOSYSTEM_MAP:
        ecosystem, range_type = _TARGET_SW_ECOSYSTEM_MAP[target_sw]
        package_name = cpe_dict.get("product", "")
        if package_name and package_name != "*":
            return ecosystem, package_name, range_type

    # Specific vendor conventions known to be package registries
    vendor = cpe_dict.get("vendor", "").lower()
    product = cpe_dict.get("product", "")
    if vendor in _TARGET_SW_ECOSYSTEM_MAP:
        ecosystem, range_type = _TARGET_SW_ECOSYSTEM_MAP[vendor]
        if product and product != "*":
            return ecosystem, product, range_type

    return None


class NVDSource:
    """NVD (National Vulnerability Database) source adapter.

    Queries the NIST NVD CVE API 2.0 and normalizes vulnerabilities into
    the canonical domain model.
    """

    def __init__(
        self,
        settings: NVDSourceSettings | None = None,
        http_client: httpx.AsyncClient | None = None,
    ) -> None:
        self._settings = settings or NVDSourceSettings()
        self._client = http_client
        self._cached_records: list[VulnerabilityRecord] = []

    @property
    def records(self) -> list[VulnerabilityRecord]:
        return self._cached_records

    @property
    def name(self) -> str:
        return "NVD"

    @property
    def source_type(self) -> str:
        return "nvd"

    @property
    def url(self) -> str:
        return self._settings.base_url

    async def _get_client(self) -> httpx.AsyncClient:
        if self._client is not None:
            return self._client
        headers: dict[str, str] = {"User-Agent": self._settings.user_agent}
        if self._settings.api_key:
            headers["apiKey"] = self._settings.api_key
        return httpx.AsyncClient(
            timeout=self._settings.timeout_seconds,
            headers=headers,
        )

    async def get_cve(self, cve_id: str) -> VulnerabilityRecord | None:
        """Fetch a specific CVE from NVD by ID."""
        cve_clean = cve_id.strip().upper()
        params = {"cveId": cve_clean}
        raw_json = await self._fetch_json(self._settings.base_url, params=params)

        vulns = raw_json.get("vulnerabilities", [])
        if not isinstance(vulns, list) or not vulns:
            return None

        record = self.normalize(vulns[0])
        self._cached_records.append(record)
        return record

    async def query_cves(
        self,
        start_index: int = 0,
        results_per_page: int | None = None,
        cpe_name: str | None = None,
        keyword: str | None = None,
    ) -> tuple[list[VulnerabilityRecord], int]:
        """Query NVD CVEs with pagination support.

        Args:
            start_index: 0-indexed offset.
            results_per_page: Page size.
            cpe_name: Optional CPE match string.
            keyword: Optional keyword search.

        Returns:
            tuple[records, total_results]
        """
        per_page = results_per_page or self._settings.results_per_page
        params: dict[str, Any] = {
            "startIndex": start_index,
            "resultsPerPage": per_page,
        }
        if cpe_name:
            params["cpeName"] = cpe_name
        if keyword:
            params["keywordSearch"] = keyword

        raw_json = await self._fetch_json(self._settings.base_url, params=params)

        total_results = raw_json.get("totalResults", 0)
        vulns_data = raw_json.get("vulnerabilities", [])
        if not isinstance(vulns_data, list):
            raise SourceParseError("Expected 'vulnerabilities' list from NVD response")

        records: list[VulnerabilityRecord] = []
        for item in vulns_data:
            if isinstance(item, dict):
                records.append(self.normalize(item))

        self._cached_records.extend(records)
        return records, int(total_results)

    async def sync(self, limit: int | None = None) -> SyncResult:
        """Verify connectivity and fetch a sample page from NVD."""
        start = datetime.now(UTC)
        try:
            records, total = await self.query_cves(start_index=0, results_per_page=limit or 5)
            duration = (datetime.now(UTC) - start).total_seconds()
            return SyncResult(
                source_name=self.name,
                success=True,
                records_synced=len(records),
                records_total=total,
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
        """Transform raw NVD CVE item payload into canonical VulnerabilityRecord.

        Handles:
        - CVE identification as canonical_id and primary identifier
        - Aliases from NVD references or alias list if present
        - CVSS metrics (v4.0, v3.1, v3.0, v2.0)
        - Weaknesses (CWE identifiers)
        - Safe configuration / CPE range extraction (NO false package ranges)
        - Source record provenance with full raw payload
        """
        if not isinstance(raw_data, dict):
            raise SourceParseError("NVD item must be a dictionary")

        cve_data = raw_data.get("cve", raw_data)
        if not isinstance(cve_data, dict) or "id" not in cve_data:
            raise SourceParseError("NVD record must contain a 'cve' object with an 'id' field")

        cve_id = str(cve_data["id"]).strip().upper()
        if not cve_id.startswith("CVE-"):
            raise SourceParseError(f"Invalid NVD CVE identifier: '{cve_id}'")

        # 1. Identifiers
        identifiers: list[VulnerabilityIdentifier] = [
            VulnerabilityIdentifier(
                identifier=cve_id,
                identifier_type=IdentifierType.CVE,
                source="NVD",
            )
        ]
        seen_idents: set[str] = {cve_id}

        # Check aliases if provided by NVD or references
        raw_aliases = cve_data.get("aliases", [])
        if isinstance(raw_aliases, list):
            for a in raw_aliases:
                if isinstance(a, str) and a.strip() and a.strip() not in seen_idents:
                    val = a.strip()
                    seen_idents.add(val)
                    itype = (
                        IdentifierType.GHSA
                        if val.upper().startswith("GHSA-")
                        else (
                            IdentifierType.OSV
                            if val.upper().startswith("OSV-")
                            else IdentifierType.ALIAS
                        )
                    )
                    identifiers.append(
                        VulnerabilityIdentifier(
                            identifier=val,
                            identifier_type=itype,
                            source="NVD",
                        )
                    )

        # 2. Descriptions
        descriptions = cve_data.get("descriptions", [])
        short_description = ""
        if isinstance(descriptions, list):
            for d in descriptions:
                if isinstance(d, dict) and d.get("lang") == "en":
                    short_description = d.get("value", "")
                    break
            if not short_description and descriptions and isinstance(descriptions[0], dict):
                short_description = descriptions[0].get("value", "")

        # 3. Dates
        published_dt = None
        if "published" in cve_data and isinstance(cve_data["published"], str):
            with contextlib.suppress(ValueError):
                published_dt = datetime.fromisoformat(cve_data["published"].replace("Z", "+00:00"))

        # 4. CVSS & Severity
        severity_val: str | None = None
        cvss_score: float | None = None
        metrics = cve_data.get("metrics", {})
        if isinstance(metrics, dict):
            # Check v4.0, v3.1, v3.0, v2.0 in order
            for metric_key in ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
                metric_list = metrics.get(metric_key, [])
                if isinstance(metric_list, list) and metric_list:
                    primary_entry = metric_list[0]
                    if isinstance(primary_entry, dict):
                        cvss_data = primary_entry.get("cvssData", {})
                        if isinstance(cvss_data, dict):
                            if "baseScore" in cvss_data:
                                with contextlib.suppress(ValueError):
                                    cvss_score = float(cvss_data["baseScore"])
                            sev = cvss_data.get("baseSeverity") or primary_entry.get(
                                "baseSeverity"
                            )
                            if sev:
                                severity_val = str(sev).upper()
                        elif "baseSeverity" in primary_entry:
                            severity_val = str(primary_entry["baseSeverity"]).upper()
                        if cvss_score is not None or severity_val is not None:
                            break

        # 5. CWEs
        cwes: list[str] = []
        weaknesses = cve_data.get("weaknesses", [])
        if isinstance(weaknesses, list):
            for w in weaknesses:
                if not isinstance(w, dict):
                    continue
                w_descs = w.get("description", [])
                if isinstance(w_descs, list):
                    for wd in w_descs:
                        if isinstance(wd, dict):
                            cwe_id = wd.get("value", "").strip()
                            if cwe_id.upper().startswith("CWE-") and cwe_id not in cwes:
                                cwes.append(cwe_id)

        # 6. Configurations & CPEs -> Affected Ranges
        affected_ranges: list[AffectedVersionRange] = []
        vendor_project = ""
        primary_product = ""

        configurations = cve_data.get("configurations", [])
        if isinstance(configurations, list):
            for config in configurations:
                if not isinstance(config, dict):
                    continue
                nodes = config.get("nodes", [])
                if not isinstance(nodes, list):
                    continue
                for node in nodes:
                    if not isinstance(node, dict):
                        continue
                    cpe_matches = node.get("cpeMatch", [])
                    if not isinstance(cpe_matches, list):
                        continue
                    for match in cpe_matches:
                        if not isinstance(match, dict) or not match.get("vulnerable", False):
                            continue
                        criteria = match.get("criteria", "")
                        parsed_cpe = parse_cpe_23(criteria)
                        if not parsed_cpe:
                            continue

                        if not vendor_project and parsed_cpe.get("vendor"):
                            vendor_project = parsed_cpe["vendor"]
                        if not primary_product and parsed_cpe.get("product"):
                            primary_product = parsed_cpe["product"]

                        # Check if safe package mapping exists
                        mapped = map_cpe_to_package_ecosystem(parsed_cpe)
                        if mapped is None:
                            # CRITICAL: DO NOT invent a package range for generic application CPEs
                            continue

                        ecosystem, package_name, range_type = mapped

                        # Extract version range boundaries
                        intro = match.get("versionStartIncluding") or match.get(
                            "versionStartExcluding"
                        )
                        fixed = match.get("versionEndExcluding")
                        last_aff = match.get("versionEndIncluding")

                        if not intro and parsed_cpe.get("version") not in ("*", "-"):
                            intro = parsed_cpe["version"]
                            if not fixed and not last_aff:
                                last_aff = parsed_cpe["version"]

                        raw_expr_parts = []
                        if intro:
                            raw_expr_parts.append(f">= {intro}")
                        if fixed:
                            raw_expr_parts.append(f"< {fixed}")
                        elif last_aff:
                            raw_expr_parts.append(f"<= {last_aff}")

                        raw_range_str = ", ".join(raw_expr_parts) if raw_expr_parts else None

                        affected_ranges.append(
                            AffectedVersionRange(
                                ecosystem=ecosystem,
                                package_name=package_name,
                                range_type=range_type,
                                introduced=str(intro) if intro else None,
                                fixed=str(fixed) if fixed else None,
                                last_affected=str(last_aff) if last_aff else None,
                                raw_range=raw_range_str,
                                source_name="NVD",
                            )
                        )

        # 7. Source record provenance
        source_record = VulnerabilitySourceRecord(
            source_name="NVD",
            source_identifier=cve_id,
            has_kev_evidence=False,
            has_affected_range=bool(affected_ranges),
            raw_payload=raw_data,
            synced_at=datetime.now(UTC),
        )

        return VulnerabilityRecord(
            canonical_id=cve_id,
            cve_id=cve_id,
            source_name="NVD",
            vendor_project=vendor_project,
            product=primary_product or cve_id,
            vulnerability_name=cve_id,
            short_description=short_description,
            date_added=published_dt,
            severity=severity_val,
            cvss_score=cvss_score,
            cwes=cwes,
            identifiers=identifiers,
            source_records=[source_record],
            affected_ranges=affected_ranges,
        )

    async def _fetch_json(
        self,
        url: str,
        params: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Execute an asynchronous GET request to the NVD API."""
        client = await self._get_client()
        should_close = self._client is None

        try:
            resp = await client.get(url, params=params)
            resp.raise_for_status()
            return resp.json()
        except httpx.TimeoutException as exc:
            raise SourceSyncError(f"Timeout querying NVD API: {exc}") from exc
        except httpx.HTTPStatusError as exc:
            raise SourceSyncError(
                f"HTTP error {exc.response.status_code} querying NVD API: {exc}"
            ) from exc
        except httpx.RequestError as exc:
            raise SourceSyncError(f"Connection failed querying NVD API: {exc}") from exc
        except Exception as exc:
            raise SourceParseError(f"Failed to parse NVD API JSON response: {exc}") from exc
        finally:
            if should_close:
                await client.aclose()
