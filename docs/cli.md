# Command-Line Interface (CLI) & CI/CD Integration

Local Vulnerability AI provides an official, standalone command-line interface (`vuln-ai`) that enables headless scans, automated vulnerability auditing, and direct pipeline integration into GitHub Actions, GitLab CI, Jenkins, and shell scripts.

The CLI acts purely as an **ergonomic presentation layer**. It does NOT duplicate security logic; it shares the exact same domain engine, dependency scanners, version matchers, multi-source conflict resolution, and deterministic risk rules utilized by the REST API and the Web UI.

---

## 1. Architectural Model

```text
               ┌────────────────────────────────────────────────────────┐
               │              Local Vulnerability AI Engine             │
               │ (Scanners, OSV/NVD/KEV, Matcher, Conflict, RiskEngine) │
               └───────────┬────────────────────────────────┬───────────┘
                           │                                │
                           ▼                                ▼
                 FastAPI Backend Server                Official CLI
                    (Web & REST API)                 (`vuln-ai` tool)
                           │                                │
                           ▼                                ▼
                    React SOC Console              Terminal / CI / Scripts
```

- **Headless Execution:** Does not require launching Uvicorn, FastAPI, or a browser.
- **Direct SQLite Access:** Executes directly against the configured local SQLite database with write-ahead logging (WAL).
- **Separation of Concerns:** Human-oriented tables or machine-readable JSON are streamed to `stdout`, while telemetry, status banners, and warnings are isolated on `stderr`.

---

## 2. Installation & Entry Point

When installed in an active Python virtual environment (Python $\ge 3.12$):

```bash
cd backend
python -m venv .venv
source .venv/bin/activate
pip install -e .
```

The `vuln-ai` executable is automatically registered in your environment PATH via Hatchling entry points:

```bash
vuln-ai --help
```

Alternatively, you can invoke the CLI as a Python module:

```bash
python -m vuln_ai.cli --help
```

---

## 3. Global Options & Version

### Version Check

Display the canonical application version:

```bash
vuln-ai version
# Output: Local Vulnerability AI 1.1.1
```

or via root flags:

```bash
vuln-ai --version
vuln-ai -v
```

### Global Help

```bash
vuln-ai --help
```

```text
Usage: vuln-ai [OPTIONS] COMMAND [ARGS]...

Local Vulnerability AI — local-first vulnerability scanning and intelligence.

Options:
  --version, -v  Show application version and exit.
  --help         Show this message and exit.

Commands:
  version  Show application version and exit.
  scan     Scan a project directory for dependency vulnerabilities.
  doctor   Run diagnostic health checks on database and services.
  sources  Manage vulnerability catalog sources (CISA KEV, OSV, NVD).
```

---

## 4. `scan` Command

The `scan` command audits dependency manifests in a target directory.

```bash
vuln-ai scan [PATH] [OPTIONS]
```

### Arguments

- `PATH` (optional, default: `.`): Path to the project directory containing manifests or lockfiles:
  - Python: `requirements.txt`, `pyproject.toml`, `poetry.lock`
  - Node.js: `package.json`, `package-lock.json` (npm), `pnpm-lock.yaml` (pnpm)
  - Rust: `Cargo.toml`, `Cargo.lock`

### Options

| Option | Flag | Default | Description |
| :--- | :--- | :--- | :--- |
| `--format` | `-f` | `table` | Output format: `table`, `json`, `sarif` (SARIF 2.1.0), `cyclonedx` (CycloneDX 1.5 JSON), `spdx` (SPDX 2.3 JSON). |
| `--no-ai` | | `false` | Disable local Ollama LLM and SystemOne inference; continue using deterministic rules. |
| `--output` | `-o` | `None` | Save the generated report to a file path atomically. |
| `--fail-on` | | `none` | Trigger exit code `1` if any finding reaches or exceeds severity: `none`, `low`, `medium`, `high`, `critical`. |
| `--fail-on-review` | | `false` | Trigger exit code `1` if any finding requires human security review. |

---

## 5. Output Formats

### 5.1 Terminal Table Format (Default)

Produces styled tables with color-coded applicability, risk severity, and dependency provenance:

```bash
vuln-ai scan ./my-project
```

Example output:
```text
╭──────────────────────────────────────────────────────────────────────────────╮
│ Local Vulnerability AI                                                       │
│ Project:     my-project (/path/to/my-project)                                │
│ Status:      COMPLETED                                                       │
│ Duration:    0.14s | AI Pipeline: enabled                                    │
│ Components:  96 detected (12 direct, 84 transitive) | Edges: 137 | Lockfiles: │
│ poetry.lock                                                                  │
╰──────────────────────────────────────────────────────────────────────────────╯
Risk Findings: CRITICAL: 0  HIGH: 1  MEDIUM: 1  LOW: 0  INFO/UNKNOWN: 0 | Requires Review: 0 | KEV Matches: 0

Detected Vulnerability Matches
┏━━━━━━━━━━┳━━━━━━━━━┳━━━━━━━━━━━━┳━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━┳━━━━━━━━┳━━━━━━━━━━━━━━━━━┳━━━━━━┳━━━━━┳━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
┃ Package  ┃ Version ┃ Type       ┃ Origin      ┃ Vulnerability ID ┃ Source ┃ Applicability   ┃ Risk ┃ KEV ┃ Review ┃ Action / Rationale          ┃
┡━━━━━━━━━━╇━━━━━━━━━╇━━━━━━━━━━━━╇━━━━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━╇━━━━━━━━╇━━━━━━━━━━━━━━━━━╇━━━━━━╇━━━━━╇━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┩
│ urllib3  │ 2.0.5   │ TRANSITIVE │ poetry.lock │ CVE-2023-45803   │ OSV    │ LIKELY_AFFECTED │ HIGH │  -  │   -    │ High severity CVSS match... │
└──────────┴─────────┴────────────┴─────────────┴──────────────────┴────────┴─────────────────┴──────┴─────┴────────┴─────────────────────────────┘
```

Respects standard environment conventions:
- `NO_COLOR=1`: Disables ANSI color escapes.
- Non-TTY: Clean text rendering without animation artifacts.

---

### 5.2 JSON Output Format (Machine-Readable)

Pure JSON written to `stdout`, completely free of ANSI codes or logging pollution. Perfect for chaining with `jq` or ingestion into security dashboards:

```bash
vuln-ai scan ./my-project --format json
```

Example JSON schema:

```json
{
  "project_name": "my-project",
  "project_path": "/path/to/my-project",
  "scan_status": "completed",
  "duration_seconds": 0.142,
  "error": null,
  "summary": {
    "components_found": 12,
    "vulnerabilities_checked": 1400,
    "matches_found": 1,
    "kev_matches": 0,
    "requires_review_count": 0,
    "risk_counts": {
      "critical": 0,
      "high": 1,
      "medium": 0,
      "low": 0,
      "info": 0,
      "unknown": 0
    }
  },
  "matches": [
    {
      "component": {
        "name": "urllib3",
        "version": "2.0.5",
        "ecosystem": "pypi",
        "file_path": "requirements.txt"
      },
      "vulnerability": {
        "id": "CVE-2023-45803",
        "cve_id": "CVE-2023-45803",
        "severity": "HIGH",
        "cvss_score": 7.5,
        "source": "OSV",
        "has_kev_evidence": false
      },
      "applicability": "likely_affected",
      "risk_level": "high",
      "requires_human_review": false,
      "rule_ids": [
        "RULE_CVSS_HIGH"
      ],
      "rationale": "High severity CVSS score (7.5) with confirmed version applicability.",
      "recommended_action": "Upgrade urllib3 to a patched version (>= 2.0.7).",
      "has_conflicts": false,
      "conflicts": []
    }
  ]
}
```

### 5.3 SARIF Output Format (`--format sarif`)

Generates **SARIF 2.1.0** for direct ingestion into GitHub Code Scanning, GitLab security dashboards, and static analysis viewers:

```bash
# Output SARIF to stdout
vuln-ai scan . --format sarif | jq .

# Save SARIF to file atomically
vuln-ai scan . --format sarif --output results.sarif
```

### 5.4 CycloneDX SBOM Output Format (`--format cyclonedx`)

Generates **CycloneDX 1.5 JSON** Software Bill of Materials (SBOM) with Package URLs (`purl`), dependency graph topology, and vulnerability findings:

```bash
vuln-ai scan . --format cyclonedx --output sbom.cdx.json
```

### 5.5 SPDX SBOM Output Format (`--format spdx`)

Generates **SPDX 2.3 JSON** Software Bill of Materials with application root package, package external references, honest license declarations (`NOASSERTION`), and `DEPENDS_ON` relationships:

```bash
vuln-ai scan . --format spdx --output sbom.spdx.json
```

---

## 6. Exit Codes & CI Policy Enforcement

The CLI provides deterministic process exit codes according to industry standards:

| Exit Code | Meaning | Trigger Condition |
| :---: | :--- | :--- |
| `0` | **Success** | Scan completed and findings did not violate configured thresholds. |
| `1` | **Policy Threshold Violated** | Security findings met or exceeded `--fail-on` or `--fail-on-review`. |
| `2` | **Usage / Configuration Error** | Missing database tables, invalid arguments, or non-existent path. |
| `3` | **Internal Failure** | Uncaught exception or database runtime failure during scan execution. |

### Policy Enforcement Examples

Fail CI builds if any **High** or **Critical** vulnerabilities are detected:

```bash
vuln-ai scan . --fail-on high
```

Fail CI builds if any vulnerabilities require human triage due to multi-source ambiguity:

```bash
vuln-ai scan . --fail-on-review
```

Save JSON report to artifact file while enforcing failure thresholds:

```bash
vuln-ai scan . --format json --output report.json --fail-on high
```

---

## 7. AI Mode Control & Offline Resilience

### Explicitly Disabling AI (`--no-ai`)

When running in lean environments without local GPU or without Ollama:

```bash
vuln-ai scan . --no-ai
```

The pipeline skips LLM context generation and SystemOne inference, relying strictly on the deterministic Risk Engine and version matchers.

### Automatic Offline Fallback

If `--no-ai` is not specified but Ollama is offline or unreachable:
1. The CLI logs a non-fatal warning to `stderr`.
2. The scan proceeds without crashing.
3. Findings are evaluated deterministically with the rule `AI_UNAVAILABLE_FALLBACK`.

---

## 8. Catalog Management (`sources`)

### List Configured Catalogs

```bash
vuln-ai sources list
```

Displays sync status, last synchronization timestamp, and stored record counts for CISA KEV, OSV, and NVD.

### Synchronize Catalogs

Synchronize all configured catalogs:

```bash
vuln-ai sources sync
```

Or synchronize a single catalog:

```bash
vuln-ai sources sync --source "CISA KEV"
```

---

## 9. Environment Diagnostic (`doctor`)

Run an environmental health check across Python runtime, SQLite database, Alembic schema state, catalog volume, and local AI providers:

```bash
vuln-ai doctor
```

Example report:

```text
                        System & Environment Diagnostics                        
┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┳━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
┃ Diagnostic Item             ┃ Status  ┃ Details                              ┃
┡━━━━━━━━━━━━━━━━━━━━━━━━━━━━━╇━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┩
│ Python Runtime              │ OK      │ v3.12.2 on Linux (x86_64)            │
│ SQLite Database             │ OK      │ Schema ready (Alembic head: f8b2c4)  │
│ Vulnerability Catalog       │ OK      │ 2410 records stored locally          │
│ Ollama LLM Provider         │ ONLINE  │ http://localhost:11434 (llama3.2)    │
│ SystemOne Decision Provider │ ONLINE  │ http://localhost:11434 (deepseek)    │
│ Supported Scanners          │ OK      │ PythonScanner (requirements.txt, ...)│
└─────────────────────────────┴─────────┴──────────────────────────────────────┘

✔ Local Vulnerability AI diagnostics passed successfully.
```

---

## 10. CI/CD Pipeline Examples

### GitHub Actions

```yaml
name: Vulnerability Scan

on:
  push:
    branches: [main]
  pull_request:

jobs:
  security-scan:
    runs-on: ubuntu-latest
    steps:
      - name: Checkout Code
        uses: actions/checkout@v4

      - name: Set up Python
        uses: actions/setup-python@v5
        with:
          python-version: "3.12"
          cache: "pip"

      - name: Install Local Vulnerability AI
        run: |
          pip install --upgrade pip
          pip install -e ./backend

      - name: Initialize Local Database
        run: |
          cd backend
          alembic upgrade head

      - name: Run Vulnerability Scan
        run: |
          vuln-ai scan . \
            --no-ai \
            --format json \
            --output vuln-report.json \
            --fail-on high

      - name: Upload Security Report Artifact
        if: always()
        uses: actions/upload-artifact@v4
        with:
          name: vulnerability-report
          path: vuln-report.json
```

### GitLab CI

```yaml
stages:
  - security

vulnerability_scan:
  stage: security
  image: python:3.12-slim
  before_script:
    - pip install --upgrade pip
    - pip install -e ./backend
    - (cd backend && alembic upgrade head)
  script:
    - vuln-ai scan . --no-ai --format json --output gl-vuln-report.json --fail-on high
  artifacts:
    when: always
    paths:
      - gl-vuln-report.json
    expire_in: 1 week
```

### Jenkins Pipeline

```groovy
pipeline {
    agent { docker { image 'python:3.12' } }
    stages {
        stage('Security Audit') {
            steps {
                sh '''
                    pip install -e ./backend
                    cd backend && alembic upgrade head && cd ..
                    vuln-ai scan . --no-ai --format table --fail-on high
                '''
            }
        }
    }
}
```

---

## Policy & Suppression Commands (Etapa 16)

### `vuln-ai policy validate`
Validate the structure, syntax, and schema of a YAML policy file without running a scan.

```bash
vuln-ai policy validate path/to/.vuln-ai.yaml
```

**Checks Performed:**
- File size under 1MB.
- Valid YAML syntax and safe parsing (no executable code).
- Conformance to policy schema (rules, thresholds, conditions, actions).
- No duplicate rule IDs.
- Canonical terminology enforcement.

### `vuln-ai policy check`
Inspect and display the rule set, conditions, and actions of a policy in a formatted table.

```bash
vuln-ai policy check path/to/.vuln-ai.yaml
```

### `vuln-ai suppression list`
List all security exceptions registered in the database, including active status, owner, expiration, and target finding criteria.

```bash
# Formatted Rich table
vuln-ai suppression list

# JSON format for automated pipelines
vuln-ai suppression list --json
```

### Scan Policy Flags
Enhance `vuln-ai scan` with declarative policy evaluation:

```bash
# Explicit policy document
vuln-ai scan . --policy custom-policy.yaml

# Bypass repository policy and execute raw scanner matching
vuln-ai scan . --no-policy

# Display Policy & Compliance Evaluation table in console output
vuln-ai scan . --show-policy

# Display active suppressions applied to current findings
vuln-ai scan . --show-suppressions
```

### CLI Exit Codes
- `0`: Success (no violations found, or all violations covered by active suppressions).
- `1`: Policy violation or expired suppression build failure.
- `2`: CLI usage, configuration, or policy parser error.
- `3`: Internal application or database error.

---

## Container & Image Commands (Etapa 17)

Static inspection of Docker / OCI container image tarballs (`.tar`) and Dockerfiles with zero workload execution guarantee.

### `vuln-ai image scan`
Scan an immutable Docker or OCI tar archive.

```bash
# Basic scan
vuln-ai image scan /path/to/image.tar

# Scan with custom reference tag
vuln-ai image scan /path/to/image.tar --reference "myorg/service:1.2.0"

# Evaluate declarative security policy during scan
vuln-ai image scan /path/to/image.tar --policy .vuln-ai.yaml

# Disable Generative AI contextual analysis (pure deterministic mode)
vuln-ai image scan /path/to/image.tar --no-ai

# Export findings to SARIF, CycloneDX, or JSON
vuln-ai image scan /path/to/image.tar --format sarif --output container-findings.sarif
```

### Dockerfile static analysis via `image scan`

Pass a Dockerfile path to the same command (static AST only; never builds):

```bash
vuln-ai image scan /path/to/Dockerfile
vuln-ai image scan /path/to/Dockerfile --format json
```

> Inventory/detail of previously scanned images is available via the API (`GET /api/v1/images`) and the frontend **Container Images** page. Dedicated `image list` / `image info` CLI subcommands are reserved as future work.

## Stage 19.1 CLI notes

- `vuln-ai scan <path>` discovers manifests in monorepo subdirectories (safe exclusions apply).
- Supported Python lockfiles include `requirements.txt`, `poetry.lock`, and `uv.lock`.
- npm ecosystems: `package-lock.json` and multi-document `pnpm-lock.yaml`.
- When using `-o/--output`, machine-readable exports are written to the file only; stdout stays operational (H15).
- `vuln-ai image scan Dockerfile` persists the static AST when the local DB is initialized.
