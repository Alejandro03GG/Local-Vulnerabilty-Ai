# Vulnerability Intelligence Sources

**Local Vulnerability AI** ingests and correlates threat data from multiple authoritative intelligence feeds to construct a comprehensive local vulnerability catalog.

---

## 1. Supported Sources Overview

| Source | Identifier Scheme | Ingestion Method | Version Range Support | Exploitation Evidence |
| :--- | :--- | :--- | :--- | :--- |
| **CISA KEV** | CVE (`CVE-YYYY-NNNN`) | Direct JSON Catalog Feed | :x: No package range bounds | :white_check_mark: Active in-the-wild exploitation |
| **OSV** | GHSA, CVE, PYSEC, GO | Asynchronous REST API / Ecosystem feeds | :white_check_mark: Precise ecosystem ranges | :warning: Contextual advisory notes |
| **NVD** | CVE (`CVE-YYYY-NNNN`) | REST API 2.0 (JSON) | :white_check_mark: CPE-mapped configurations | :white_check_mark: CVSS v3.1 / v2.0 severity metrics |

---

## 2. CISA KEV (Known Exploited Vulnerabilities)

The **Cybersecurity and Infrastructure Security Agency (CISA) KEV** catalog is the authoritative register of vulnerabilities confirmed to be actively exploited in the wild.

### Purpose & Value
- Provides definitive proof of real-world adversary activity.
- Identifies critical threats demanding immediate mitigation regardless of theoretical CVSS score.
- Highlights whether a vulnerability is associated with known ransomware campaigns.

### Version Range Limitation
- CISA KEV records identify products at the system/software level (e.g., `vendor_project="Apache"`, `product="Log4j"`).
- **Critical Architectural Constraint**: CISA KEV data does **not** provide granular package version range boundaries (such as `[2.0.0, 2.15.0)`).
- **Engine Behavior**: When a component matches an entry in CISA KEV solely by product/vendor name without accompanying range evidence, the system assigns the verdict `DETECTED`. It never automatically concludes `LIKELY_AFFECTED` without version corroboration.

### Synchronization
- Ingested from: `https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json`
- Configurable auto-sync interval (default: 24 hours).
- Local storage: Stored in SQLite table `vulnerabilities` with `source_type="kev"`.

---

## 3. OSV (Open Source Vulnerabilities)

The **OSV** database provides distributed open-source advisory data formatted under the standard OSV schema.

### Purpose & Value
- Granular, ecosystem-specific advisory data across PyPI, npm, Cargo, Go, Maven, and NuGet.
- Captures precise package-level version intervals.
- Maps cross-source aliases (e.g., relating a GHSA advisory to its canonical CVE ID).

### Range Event Semantics
OSV records express versions through ordered event pairs:
- `introduced`: The earliest version containing the vulnerability (inclusive, e.g., `1.0.0`).
- `fixed`: The version in which the vulnerability was remediated (exclusive, e.g., `1.2.3`). Resolves to interval `[introduced, fixed)`.
- `limit`: An upper limit event indicating an unbounded upper evaluation range (exclusive, e.g., `[introduced, limit)`).
- `last_affected`: The latest affected version (inclusive, e.g., `[introduced, last_affected]`).

### Synchronization
- Query client: `https://api.osv.dev/v1/query`
- Supports batch queries by package name and ecosystem.

---

## 4. NVD (National Vulnerability Database)

Maintained by the **National Institute of Standards and Technology (NIST)**, NVD provides official Common Vulnerabilities and Exposures (CVE) metadata.

### Purpose & Value
- Authoritative CVE descriptions, CWE weakness classifications, and reference links.
- Official CVSS vector strings, base scores, and exploitability sub-scores.
- Common Platform Enumeration (CPE) configurations.

### Ecosystem Mapping Limitations
- NVD version ranges are keyed against CPE strings rather than native language package managers.
- Matching CPE identifiers against native package names (e.g., PyPI package names vs CPE vendor/product strings) carries risk of false positives.
- The matcher applies normalization to sanitize names before evaluation.

---

## 5. Multi-Source Deduplication & Correlation

When multiple sources report the same vulnerability (e.g., an OSV record referencing `CVE-2024-1234` and an NVD entry for `CVE-2024-1234`):

1. **Single Canonical Record**: The system deduplicates advisories against `cve_id` and known aliases, storing exactly one canonical record in `vulnerabilities`.
2. **Preserved Source Records**: Individual raw source payloads are retained in `vulnerability_source_records` to preserve lineage.
3. **Range Stacking**: Range intervals from all participating sources are preserved in `vulnerability_affected_ranges`.
4. **Conflict Resolution**: If OSV and NVD define conflicting version range boundaries for the same component, the [ConflictResolver](conflict-resolution.md) detects the discrepancy and flags the match for human review.
