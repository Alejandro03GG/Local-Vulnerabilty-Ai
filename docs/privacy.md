# Privacy & Data Handling Specification

**Local Vulnerability AI** is architected on a strict **local-first** security model. This document defines the boundaries of data processing, storage, and network transmission.

---

## 1. Core Privacy Guarantees

| Data Category | Processed Locally? | Transmitted to AI? | Transmitted Externally? | Storage Location |
| :--- | :--- | :--- | :--- | :--- |
| **Project Source Code** | :white_check_mark: Yes (AST / parser only) | :x: **NEVER** | :x: **NEVER** | Not persisted |
| **Manifest Files** (`requirements.txt`, etc.) | :white_check_mark: Yes (parsing only) | :x: **NEVER** | :x: **NEVER** | Not persisted |
| **Component Metadata** (name, version, ecosystem) | :white_check_mark: Yes | :white_check_mark: Non-sensitive context | :warning: Package **name + ecosystem** may be sent to OSV during source sync/query; optional AI may receive name/version/ecosystem + manifest path | Local SQLite DB |
| **Vulnerability Advisories** | :white_check_mark: Yes | :white_check_mark: Advisory summary only | Downloaded from OSV/NVD/CISA | Local SQLite DB |
| **User Credentials / Secrets** | :x: Not collected | :x: **NEVER** | :x: **NEVER** | Not stored |
| **Usage Telemetry / Analytics** | :x: **Zero telemetry** | :x: **NEVER** | :x: **NEVER** | None |

---

## 2. Source Code Boundary

A foundational architectural requirement is that **proprietary source code must never leave your machine or enter an LLM prompt**:

1. **Local AST & Manifest Parsing**: Scanners parse package specifications directly from local files (`requirements.txt`, `pyproject.toml`, `setup.py`, `Pipfile`).
2. **Metadata Extraction**: Only structured dependency records are extracted:
   - Package name (e.g., `requests`)
   - Declared version (e.g., `2.31.0`)
   - Specifier type (e.g., `EXACT`)
3. **AI Context Payload**: When local AI analysis is enabled, the prompt receives **only non-sensitive metadata**:
   - Component name
   - Installed version
   - Ecosystem
   - Matched vulnerability advisory ID and published summary
4. Source code contents, comments, and function implementations are never sent to any language model. Optional AI prompts may include the **manifest/lockfile relative path** (`source_file`, e.g. `requirements.txt`) together with package metadata — never file body contents. Disable AI with `VULN_AI_AI__ENABLED=false` or `--no-ai`.

---

## 3. Network Egress Boundaries

Network requests are restricted exclusively to:

1. **Vulnerability Feed Ingestion** (during `sources sync` / package queries; not required for offline scans against a local catalog):
   - `api.osv.dev`: HTTP **POST** queries carrying package **name** and **ecosystem** (not source code).
   - `services.nvd.nist.gov`: HTTP GET CVE 2.0 API metadata queries.
   - `www.cisa.gov` (and optional KEV mirror): HTTP GET Known Exploited Vulnerabilities catalog JSON.
2. **Local AI Daemon** (optional):
   - `http://localhost:11434`: Local loopback communication with the user's Ollama instance.

No telemetry, diagnostic pings, analytics, or user identifiers are ever transmitted to external servers.
Source code file bodies are never uploaded to OSV/NVD/CISA.

---

## 4. Local Persistence Security

All scan results, match evidence, and intelligence records are stored in a local SQLite database (`vuln_ai.db`) located in the user's data directory (`~/.local/share/vuln-ai/` by default).

- The database file is protected by the user's standard operating system permissions.
- The repository `.gitignore` ensures that database files (`*.db`, `*.sqlite`) are never committed to version control.

---

## 5. Offline Mode

When vulnerability feeds are already synchronized locally, the following work **without Internet**:

- `vuln-ai scan` / `vuln-ai image scan`
- Risk and Policy evaluation
- Suppressions
- SARIF / CycloneDX / SPDX export
- Frontend against a local API

Operations that require network (unless cached locally):

- `vuln-ai sources sync` (OSV / NVD / CISA KEV)
- Optional Ollama calls when AI is enabled (localhost only)

