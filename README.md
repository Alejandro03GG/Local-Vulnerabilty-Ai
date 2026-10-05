# Local Vulnerability AI

> An open-source, local-first vulnerability analysis and Software Composition Analysis (SCA) platform combining deterministic multi-source version matching with local contextual AI analysis, container/image scanning, and an auditable Risk & Policy Engine.

[![Python](https://img.shields.io/badge/Python-3.12%20%7C%203.13%20%7C%203.14-3776AB?logo=python&logoColor=white)](https://python.org)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.110+-009688?logo=fastapi&logoColor=white)](https://fastapi.tiangolo.com)
[![React](https://img.shields.io/badge/React-18-61DAFB?logo=react&logoColor=black)](https://react.dev)
[![TypeScript](https://img.shields.io/badge/TypeScript-5.6-3178C6?logo=typescript&logoColor=white)](https://www.typescriptlang.org)
[![Coverage](https://img.shields.io/badge/Coverage-95%25+-success)](backend/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Status: Release Ready](https://img.shields.io/badge/Status-v1.1.3%20Release%20Ready-blue.svg)](CHANGELOG.md)

---

## Why?

Modern software development relies heavily on open-source dependencies and container images. However, securing this software supply chain often forces organizations to upload their proprietary source code, private manifests, or container archives to closed third-party cloud services.

**Local Vulnerability AI** was built to solve this challenge by running **100% locally on your own infrastructure**:

1. **Zero Source Code Exfiltration**: Scans manifests, lockfiles, and container archives locally. Your private source code never leaves your workstation or CI/CD runner.
2. **Multi-Source Truth Without Cloud Lock-in**: Correlates OSV, NIST NVD, and CISA KEV into a single canonical catalog stored locally in SQLite.
3. **Deterministic Math Over Generative Hallucinations**: Version ranges are evaluated with exact mathematical interval logic (PEP 440, SemVer, Maven, Debian, Alpine, RPM). AI is **never** given authority to invent CVEs, alter applicability, or override deterministic policy gates.
4. **Contextual AI on Your Terms**: Optional local LLM support via Ollama runs on `localhost` to provide plain-English summaries and triage assistance without cloud API costs or data leakage.
5. **Single Consistent Security Engine**: One unified pipeline evaluating dependencies, container layers, policies, suppressions, and standard security exports (SARIF, CycloneDX, SPDX).

---

## Features

Local Vulnerability AI 1.0.0 delivers a feature-complete, production-ready local security stack:

- **Dependency Scanning**: Automatic discovery and parsing of Python (`requirements.txt`, `pyproject.toml`, `poetry.lock`), Node.js (`package.json`, `package-lock.json`, `pnpm-lock.yaml`), and Rust (`Cargo.toml`, `Cargo.lock`).
- **Dependency Graph**: Directed acyclic graph tracking direct vs. transitive relationships, resolution depth, and multi-version package support (e.g. `lodash@3.x` and `lodash@4.x` coexisting).
- **CISA KEV Integration**: Automated tracking of Known Exploited Vulnerabilities catalog with in-the-wild exploitation indicators and ransomware flags.
- **OSV Intelligence**: Fast ecosystem advisory ingestion with exact `[introduced, fixed)` and `[introduced, limit)` version event ranges.
- **NVD (CVE 2.0)**: Ingestion of CVSS v2/v3/v4 metrics, CWE classifications, and official NIST advisory metadata.
- **Version-Aware Matching**: Formal interval math for PEP 440, SemVer 2.0, Cargo, Maven, and OS package versions (`deb`, `apk`, `rpm`).
- **Canonical Applicability Vocabulary**: Evaluates components into strict canonical states: `LIKELY_AFFECTED`, `LIKELY_NOT_AFFECTED`, `REQUIRES_REVIEW`, `DETECTED`, and `UNKNOWN`. (The misleading status `VULNERABLE` is strictly prohibited).
- **Multi-Source Conflict Resolution**: Detects divergent verdicts across sources (e.g. OSV affected vs NVD unaffected) and routes them conservatively to `REQUIRES_REVIEW`.
- **Container Image Scanning**: Pure static OCI and Docker archive (`.tar`) inspection with layer extraction, whiteout handling (`.wh.*`, `.wh..wh..opq`), and OS package detection (Alpine APK, Debian/Ubuntu DPKG, Red Hat RPM).
- **Dockerfile AST Lexer**: Static analysis of Dockerfile ASTs without executing builds, detecting multi-stage targets and package manager instructions.
- **Deterministic Risk Engine**: Rule-based scoring evaluating KEV status, CVSS metrics, conflicts, and fallbacks with auditable `rule_ids`.
- **Policy Engine**: Declarative `.vuln-ai.yaml` policies with multi-criteria conditions, action hierarchies (`BLOCK`, `REQUIRE_REVIEW`, `ACCEPT_RISK`, `ALLOW`), and deterministic CI exit codes.
- **Suppression Management**: Auditable, time-bound vulnerability exemptions (`ACTIVE`, `EXPIRED`, `DISABLED`) with an injectable clock for testability. Findings are never deleted or hidden.
- **Local AI (Ollama & SystemOne)**: Optional contextual plain-English remediation narratives via local Ollama (`llama3.2`) and fast triage classification (`SystemOne`). Fully optional with `--no-ai` fallback.
- **Standard Exports**: Full export capabilities for SARIF 2.1.0, CycloneDX 1.5 JSON, and SPDX 2.3 JSON with container layer provenance.
- **Command-Line Interface (CLI)**: Rich terminal outputs, machine-readable JSON on stdout, headless CI/CD execution, and system diagnostics (`vuln-ai doctor`).
- **REST API**: Versioned FastAPI gateway (`/api/v1`) with OpenAPI Swagger UI, structured error formats, and request tracing.
- **Web UI Console**: Dark-mode React 18 / TypeScript operations console with interactive dependency graphs, match detail cards, container image viewers, and global command menu (⌘K / Ctrl+K).

---

## Architecture

The platform operates as a decoupled, deterministic security pipeline:

```text
CLI / API / Frontend
        ↓
    Scan Engine
        ↓
 Dependency Graph (+ Container ImageSource)
        ↓
     Catalog (CISA KEV, OSV, NVD)
        ↓
     Matcher (PEP 440, SemVer, Maven, DEB, APK, RPM)
        ↓
 Conflict Resolver (Discrepancy Detection & Categorization)
        ↓
 AI / SystemOne (Optional, Supplementary, Non-Authoritative)
        ↓
    Risk Engine (Deterministic Rules & Auditable Rule IDs)
        ↓
 Policy Engine (Declarative YAML, Actions: BLOCK / ALLOW)
        ↓
   Suppression (Active Exemption / Expired CI Failure)
        ↓
 SARIF 2.1.0 / CycloneDX 1.5 / SPDX 2.3
```

For complete architectural details, see **[docs/architecture.md](docs/architecture.md)**.

---

## Installation

### Prerequisites

- **Python**: `>= 3.12` (Python 3.12, 3.13, or 3.14)
- **Node.js**: `>= 18.0.0` & **npm**: `>= 9.0.0`
- **Git**
- *(Optional)*: [Ollama](https://ollama.ai/) with `llama3.2` running locally on port `11434` for contextual AI explanations.

### Step 1: Clone Repository

```bash
git clone https://github.com/Alejandro03GG/Local-Vulnerabilty-Ai.git
cd Local-Vulnerabilty-Ai
```

### Step 2: Backend Setup

```bash
cd backend

# Create and activate virtual environment
python3 -m venv .venv
source .venv/bin/activate   # On Windows: .venv\Scripts\activate

# Install backend in editable mode with development dependencies
pip install -e ".[dev]"

# Initialize local SQLite database schema
alembic upgrade head

# Copy environment configuration
cp .env.example .env
cd ..
```

### Step 3: Frontend Setup

```bash
cd frontend
npm install
cp .env.example .env
cd ..
```

---

## Quick Start

### 1. Verify Installation with CLI

With your backend virtual environment active:

```bash
# Display CLI help and available commands
vuln-ai --help

# Check version
vuln-ai version

# Run system health diagnostics (Python, SQLite, Alembic, Feeds, Ollama)
vuln-ai doctor
```

### 2. Run a Vulnerability Scan

Scan any project directory containing manifests or lockfiles:

```bash
# Scan a project and view formatted terminal tables:
vuln-ai scan ./my-project

# Run headless without AI (pure deterministic mode):
vuln-ai scan ./my-project --no-ai

# Output machine-readable JSON for scripts:
vuln-ai scan ./my-project --format json --no-ai

# Fail CI with exit code 1 if High or Critical vulnerabilities are found:
vuln-ai scan ./my-project --fail-on high --no-ai

# Export directly to SARIF 2.1.0 for GitHub Security tab:
vuln-ai scan ./my-project --format sarif --output results.sarif --no-ai
```

### 3. Start the Web Console & REST API

```bash
# Terminal 1: Start FastAPI Gateway (http://localhost:8000)
cd backend
source .venv/bin/activate
uvicorn vuln_ai.api.main:app --reload --port 8000

# Terminal 2: Start React Web Console (http://localhost:5173)
cd frontend
npm run dev
```

Open your browser to **`http://localhost:5173`** to access the Security Operations Console, or visit **`http://localhost:8000/docs`** for interactive Swagger API documentation.

---

## Sources

Local Vulnerability AI synthesizes threat intelligence from three primary authorities into a local SQLite catalog:

- **CISA KEV (Known Exploited Vulnerabilities)**: Official United States Cybersecurity and Infrastructure Security Agency catalog tracking vulnerabilities actively exploited in the wild, remediation deadlines, and known ransomware campaign association.
- **OSV (Open Source Vulnerabilities)**: Google's distributed open-source vulnerability database, providing precise package ecosystems, commit-level version ranges, and cross-reference aliases.
- **NVD (National Vulnerability Database)**: NIST CVE 2.0 feed providing Common Vulnerability Scoring System (CVSS v2/v3/v4) base metrics, vector strings, and Common Weakness Enumeration (CWE) taxonomies.

To manage and synchronize sources:

```bash
vuln-ai sources list
vuln-ai sources sync
```

For technical details, see **[docs/sources.md](docs/sources.md)**.

---

## AI

Local Vulnerability AI integrates **local Large Language Models** as an optional supplementary layer:

- **Local Execution via Ollama**: Connects to an Ollama daemon running on `localhost:11434` (default model: `llama3.2`).
- **Strict Privacy**: Your private source code, repository structure, and application code are **never** transmitted to the LLM. Only component metadata (package name, installed version, advisory title) is provided to generate contextual triage notes.
- **Non-Authoritative**: AI output does **not** determine vulnerability presence, mathematically affected versions, or policy pass/fail decisions. All verdicts are governed by the deterministic Version Matcher and Risk Engine.
- **Graceful Fallback**: If Ollama is offline or if `--no-ai` is passed, scans complete without interruption, logging an auditable `AI_UNAVAILABLE_FALLBACK` rule ID in the risk trace.

For technical details, see **[docs/ai.md](docs/ai.md)**.

---

## Container Scanning

Local Vulnerability AI 1.0.0 features a dedicated, pure static container and image analysis engine:

- **Zero-Execution Guarantee**: Scans OCI and Docker image archives (`.tar`) and Dockerfiles completely statically. The scanner **never** calls `docker run`, `docker exec`, `docker build`, `podman`, or container runtimes.
- **Rootless & Daemonless**: Operates without a Docker daemon, socket connection, or root privileges.
- **Layer Stacking & Whiteouts**: Correctly handles overlay filesystems, standard whiteouts (`.wh.<filename>`), and opaque whiteout markers (`.wh..wh..opq`).
- **Operating System Packages**: Static parsers for Alpine Linux (`APK`), Debian/Ubuntu (`DPKG`), and Red Hat/CentOS (`RPM`), attributing each package to its introducing layer.
- **Embedded Application Discovery**: Recursively extracts and scans application lockfiles located inside container layers (`package-lock.json`, `Cargo.lock`, `requirements.txt`, etc.).
- **Static Dockerfile AST Analysis**: Pure AST lexer analyzing multi-stage builds, target stages, and package installation commands.

```bash
# Scan a container archive:
vuln-ai image scan ./my-image.tar --no-ai

# Scan a Dockerfile statically:
vuln-ai image scan ./Dockerfile --no-ai
```

> **Notice**: Container registry remote authentication, runtime monitoring, and Kubernetes cluster scanning are **intentionally not included** in 1.0.0. See [docs/container-scanning.md](docs/container-scanning.md) and [docs/dockerfile-scanning.md](docs/dockerfile-scanning.md).

---

## Policies

The **Declarative Policy & Suppression Engine** enables automated governance for development and CI/CD workflows:

- **Declarative YAML Rules (`.vuln-ai.yaml`)**: Define security gates based on severity, risk level, CVSS thresholds, KEV evidence, ecosystem, package scope (`RUNTIME` vs `DEV`), and direct vs. transitive status.
- **Action Hierarchy**: Enforces deterministic actions: `BLOCK` > `REQUIRE_REVIEW` > `ACCEPT_RISK` > `ALLOW`.
- **Suppression Management**: Allows auditable, temporary exemptions with required reasons, owners, and expiration dates (`expires_at`).
- **Lifecycle Guarantees**:
  - `ACTIVE`: Finding is noted but exempted from blocking CI (Exit code `0`).
  - `EXPIRED`: Suppression is invalidated, warning is issued, and CI fails (Exit code `1`).
  - Findings are **never** hidden or deleted from reports or audit logs.

```bash
# Validate a policy file syntax and schema:
vuln-ai policy validate .vuln-ai.yaml

# Inspect rules configured in a policy:
vuln-ai policy check .vuln-ai.yaml

# List active and expired suppressions:
vuln-ai suppression list
```

For complete documentation, see **[docs/policy.md](docs/policy.md)** and **[docs/suppressions.md](docs/suppressions.md)**.

---

## Export Formats

Local Vulnerability AI exports complete security findings and Software Bills of Materials (SBOM) in industry-standard formats:

- **SARIF 2.1.0 (Static Analysis Results Interchange Format)**: Integrates directly with GitHub Code Scanning, GitLab Security Dashboard, and IDE viewers. Includes native suppression objects and policy metadata.
- **CycloneDX 1.5 JSON**: Comprehensive application and container SBOM with full component dependency graphs, vulnerability entries, and policy status properties.
- **SPDX 2.3 JSON**: Standard Software Package Data Exchange format preserving component versions and licensing assertions.

```bash
# Export to SARIF:
vuln-ai scan ./project --format sarif --output results.sarif --no-ai

# Export to CycloneDX SBOM:
vuln-ai scan ./project --format cyclonedx --output sbom.cdx.json --no-ai

# Export to SPDX SBOM:
vuln-ai scan ./project --format spdx --output sbom.spdx.json --no-ai
```

For format mapping specifications, see **[docs/export-formats.md](docs/export-formats.md)**.

---

## Privacy

Local Vulnerability AI is designed from the ground up for strict data isolation:

- **Zero Source Code Transmission**: Your private source code is never transmitted across the network, nor is it sent to AI providers.
- **Minimal Documented Egress**:
  - `OSV`: Queries send only package names and ecosystems (e.g. `npm/lodash`) via HTTP POST to the public OSV API.
  - `NVD` & `CISA KEV`: Standard HTTP GET requests fetch public vulnerability feed records.
  - `Ollama`: Connects exclusively to local loopback (`http://localhost:11434`).
- **Air-Gapped / Offline Support**: The platform can run completely offline once the local database is populated.
- **Zero Telemetry**: No usage metrics, pings, analytics, or behavioral data are collected.

For complete privacy specifications, see **[docs/privacy.md](docs/privacy.md)**.

---

## Security

We take the security of this project and its dependency analysis pipeline seriously:

- To report a security vulnerability, please review our disclosure guidelines in **[SECURITY.md](SECURITY.md)**.
- Please do **not** open public GitHub issues for security vulnerabilities.
- For architectural security controls (path traversal protection, safe YAML parsing, zero-execution sandbox), see **[docs/image-security.md](docs/image-security.md)**.

---

## Limitations

Local Vulnerability AI 1.0.0 focuses on **deterministic, local-first static analysis**. The following capabilities are **intentionally out of scope**:

- **No Remote Registry Authentication**: Scans local `.tar` archives only; does not store or manage Docker registry credentials.
- **No Docker Daemon Dependency**: Does not communicate with Docker or Podman daemons.
- **No Kubernetes / Helm / Cloud Scans**: Does not scan live Kubernetes clusters or cloud infrastructure posture.
- **No Runtime Monitoring**: Does not monitor executing processes, network packets, or memory in running containers.
- **No License Compliance Scanner**: Does not evaluate license legal compatibility.
- **Single-Node Storage**: Uses local SQLite with write-ahead logging; multi-tenant cloud databases are not included.

See **[docs/future-work.md](docs/future-work.md)** for post-1.0 exploration items.

---

## Contributing

We welcome contributions from the open-source community!

Please see **[CONTRIBUTING.md](CONTRIBUTING.md)** for our setup guide, code standards, architectural principles, and quality gates. Before opening a Pull Request, ensure that all automated quality checks pass:

```bash
# In backend/:
pytest --cov=src --cov-report=term-missing --cov-fail-under=95
ruff check src tests
ruff format --check src tests
alembic upgrade head

# In frontend/:
npm test
npm run typecheck
npm run lint
npm run format:check
npm run build
```

---

## License

Distributed under the **MIT License**. See **[LICENSE](LICENSE)** for the full text.

---

## Status

**Version 1.1.3 — Release Ready**  
Production-ready open-source release including Stage 19.2 post-retest hardening plus CI format-gate fixes on top of v1.1.2.

## Stage 19.2 — Post-Retest Hardening

Residual hardening after Stage 19.1 revalidation: CLI policy persistence to API/UI, native OSV sync idempotence, Cargo path dependency versions, policy documentation schema alignment, clean FP fixture refresh, and verified KEV/NVD sync coverage. See `STAGE-19.2-HARDENING-REPORT.md`.

## Stage 19.1 — Product Hardening

Post–Stage 19 validation hardening on the main product: nullable CVE IDs, incremental catalog sync, policy/applicability alignment, monorepo discovery, `uv.lock` / pnpm multi-doc support, Dockerfile AST persistence, and EN/ES UI branding. See `STAGE-19.1-HARDENING-REPORT.md`.
