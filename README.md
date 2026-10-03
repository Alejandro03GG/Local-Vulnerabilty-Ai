# Local Vulnerability AI

> An open-source, local-first vulnerability intelligence and Software Composition Analysis (SCA) platform combining deterministic multi-source version matching with local contextual AI analysis and an auditable Risk Engine.

[![Python](https://img.shields.io/badge/Python-3.12%20%7C%203.13%20%7C%203.14-3776AB?logo=python&logoColor=white)](https://python.org)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.110+-009688?logo=fastapi&logoColor=white)](https://fastapi.tiangolo.com)
[![React](https://img.shields.io/badge/React-18-61DAFB?logo=react&logoColor=black)](https://react.dev)
[![TypeScript](https://img.shields.io/badge/TypeScript-5.6-3178C6?logo=typescript&logoColor=white)](https://www.typescriptlang.org)
[![Coverage](https://img.shields.io/badge/Coverage-96%25-success)](backend/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

---

## 1. What is Local Vulnerability AI?

Modern applications rely on hundreds of open-source software dependencies. Keeping them secure often forces teams into proprietary cloud platforms that demand access to private source code and code repositories.

**Local Vulnerability AI** solves this problem by running entirely on your local infrastructure:

- **Local-First & Private**: Scans software manifests, correlates advisories, and stores findings locally. Your source code **never leaves your machine**.
- **Multi-Source Intelligence**: Synthesizes vulnerability advisories from **OSV**, **NVD (CVE 2.0)**, and **CISA KEV (Known Exploited Vulnerabilities)** into a unified canonical catalog.
- **Deterministic Precedence**: Dependency applicability is computed using formal version semantics (PEP 440, SemVer, Maven). Generative models do **not** invent vulnerabilities or dictate risk conclusions.
- **Contextual AI Decision Support**: Integrates local LLMs via [Ollama](https://ollama.ai/) (`llama3.2`, `systemone`) strictly for plain-English explanations and probabilistic triage assistance.
- **Security Operations Console**: A dark-first React console designed for security analysts, featuring multi-source conflict panels, metric strips, and end-to-end audit traces.

---

## 2. System Architecture

The platform operates as a deterministic, decoupled security pipeline:

```text
Target Project (Manifests & Lockfiles)
   ├── Python: requirements.txt, pyproject.toml, poetry.lock
   ├── Node.js: package.json, package-lock.json (npm), pnpm-lock.yaml (pnpm)
   └── Rust: Cargo.toml, Cargo.lock
   ↓
Dependency Intelligence & Graph Engine (LOCKFILE > MANIFEST)
   ├── Dependency Nodes & Directed Edges
   ├── Direct vs. Transitive Classification
   └── Multi-Version Package Support (e.g. lodash 3.x & 4.x)
   ↓
Resolved Components (Exact Version, Provenance Path, Scope)
   ↓
Canonical Vulnerability Catalog
   ├── OSV (Ecosystem Advisories & Version Events)
   ├── NVD (CVE Metadata, CVSS Scores, CWEs)
   └── CISA KEV (Active In-the-Wild Exploitation)
   ↓
Version-Aware Matcher (PEP 440, SemVer 2.0, Cargo/Maven Comparators)
   ↓
Match Evidence ([introduced, fixed), [introduced, limit), KEV presence)
   ↓
Multi-Source Conflict Resolver (Discrepancy Detection & Categorization)
   ↓
Consolidated Applicability (LIKELY_AFFECTED | LIKELY_NOT_AFFECTED | REQUIRES_REVIEW | DETECTED)
   ↓
Local AI Analysis (Ollama / llama3.2) & SystemOne (Fast Inference, Supplementary)
   ↓
Deterministic Risk Engine (Rule-based evaluation: KEV, CVSS, Conflicts, Fallbacks)
   ↓
Risk Assessment (RiskLevel, requires_human_review, rule_ids, rationale)
   ↓
SQLite Database (Async SQLAlchemy with Write-Ahead Logging & Alembic)
   ↓
Declarative Policy & Suppression Engine (Etapa 16)
   ├── Declarative Policy Rules (.vuln-ai.yaml, 1MB limit, safe parsing)
   ├── Suppression Lifecycles (ACTIVE, EXPIRED, DISABLED with injectable Clock)
   ├── Precedence: Active Suppression > Expired Alert > Rule Hierarchy > Thresholds > Default
   └── Deterministic CI Gating: Exit 0 (Pass/Suppressed) vs Exit 1 (Policy Violation)
   ↓
Container & Image Scanning Engine (Etapa 17):
   ├── Pure Static OCI & Docker Archive (.tar) Parser (No Daemon, Zero Execution Guarantee)
   ├── Layer Extraction, Stacking, and Standard/Opaque Whiteout Resolution (.wh.*)
   ├── Operating System Package Discovery: Alpine (APK), Debian/Ubuntu (DPKG), RHEL/CentOS (RPM)
   ├── Recursive Application Dependency Discovery (Python, Node.js, Java, Rust, Go inside layers)
   ├── Static Dockerfile AST Lexer & Multi-Stage Runtime Stage Resolution
   └── Seamless Pipeline Reuse: OS & App components fed to single catalog, risk & policy engines
   ↓
Interfaces & Export Formats (ONE ENGINE, MULTIPLE INTERFACES):
   ├── Official CLI (`vuln-ai scan`, `vuln-ai image scan/list/info/dockerfile`, `vuln-ai policy`)
   ├── Policy & Suppression CLI (`vuln-ai policy validate/check`, `vuln-ai suppression list`)
   ├── FastAPI REST Gateway (`/api/v1/policies`, `/api/v1/images`, `/api/v1/container/dockerfile/scan`)
   ├── React Security Console (Container Images explorer, Layer detail view, Dockerfile AST analyzer)
   └── Standard Export Formats:
       ├── SARIF 2.1.0 (Native suppressions & policy metadata)
       ├── CycloneDX 1.5 JSON (vuln_ai:policy_status & suppression properties)
       └── SPDX 2.3 JSON (Preserves NOASSERTION licensing)
```

For detailed architecture, container scanning, policy engine, and export format documentation, see [docs/architecture.md](docs/architecture.md), [docs/container-scanning.md](docs/container-scanning.md), [docs/dockerfile-scanning.md](docs/dockerfile-scanning.md), [docs/image-security.md](docs/image-security.md), [docs/security.md](docs/security.md), [docs/policy.md](docs/policy.md), [docs/suppressions.md](docs/suppressions.md), and [docs/export-formats.md](docs/export-formats.md).

---

## 3. Privacy & Data Boundaries

We enforce strict data isolation guarantees:

```text
Source Code:            NEVER sent to AI models, NEVER transmitted over network
Secrets & Credentials:  NEVER stored in local database
Local AI Execution:     Ollama runs locally on loopback (http://localhost:11434)
Database Storage:       Local SQLite database in user share directory (~/.local/share/vuln-ai/)
Network Access:         Strictly outbound GET requests to public advisory feeds (OSV, NVD, CISA)
Telemetry:              ZERO usage analytics, telemetry, or tracking pings
```

For complete privacy specifications, see [docs/privacy.md](docs/privacy.md).

---

## 4. Canonical Applicability States

The system evaluates vulnerability applicability into five canonical states. The status `VULNERABLE` is **strictly prohibited** across all layers because catalog presence is an indicator, not confirmed execution compromise:

| Status | Badge Color | Description |
| :--- | :--- | :--- |
| `LIKELY_AFFECTED` | Rose | Installed version is mathematically confirmed within the advisory range $[introduced, fixed)$. |
| `LIKELY_NOT_AFFECTED` | Emerald | Installed version is mathematically proven outside the affected version intervals. |
| `REQUIRES_REVIEW` | Amber | Discrepancy detected between intelligence sources (e.g. OSV affected vs NVD unaffected). |
| `DETECTED` | Purple | Component matched in catalog (e.g. CISA KEV) without declared version range bounds. |
| `UNKNOWN` | Slate | Insufficient version data or unsupported packaging ecosystem. |

---

## 5. Deterministic Risk Engine

In Local Vulnerability AI, **AI is not the final authority**:

- Risk classifications (`LOW`, `MEDIUM`, `HIGH`, `CRITICAL`) are computed exclusively by the rule-based **Deterministic Risk Engine** (`vuln_ai.risk.engine`).
- Final assessments evaluate corroborated signals: version applicability, CISA KEV active exploitation, ransomware use, CVSS base scores, and multi-source conflicts.
- Supplementary AI narratives and SystemOne probabilities are logged as contextual evidence but cannot override mathematical range evaluations.
- Every assessment includes an auditable list of `rule_ids` (e.g. `KEV_CONFIRMED`, `SOURCE_APPLICABILITY_CONFLICT`, `AI_UNAVAILABLE_FALLBACK`).

---

## 6. Quick Start (Local Setup in 7 Steps)

### Prerequisites

- **Python**: `>= 3.12` (Python 3.12, 3.13, or 3.14)
- **Node.js**: `>= 18.0.0` & **npm**: `>= 9.0.0`
- **Git**
- *(Optional)*: [Ollama](https://ollama.ai/) with `llama3.2` model installed locally.

---

### Step 1: Clone & Backend Environment

```bash
git clone https://github.com/Alejandro03GG/Local-Vulnerabilty-Ai.git
cd Local-Vulnerabilty-Ai/backend

# Create virtual environment
python3 -m venv .venv

# Activate virtual environment
# On Linux / macOS:
source .venv/bin/activate
# On Windows (cmd.exe):
# .venv\Scripts\activate.bat
# On Windows (PowerShell):
# .venv\Scripts\Activate.ps1

# Install backend package with development dependencies
pip install -e ".[dev]"
```

---

### Step 2: Database Migrations

Initialize the local SQLite database with all canonical tables using Alembic:

```bash
alembic upgrade head
```

---

### Step 3: Environment Configuration

```bash
# Backend environment (defaults work out of the box)
cp .env.example .env

# Frontend environment
cd ../frontend
cp .env.example .env
cd ../backend
```

#### Key Environment Variables Breakdown

| Variable | Default | Required? | Purpose |
| :--- | :--- | :--- | :--- |
| `VULN_AI_DATABASE__URL` | `sqlite+aiosqlite:///.../vuln_ai.db` | **No** | SQLite database path with async driver |
| `VULN_AI_API__PORT` | `8000` | **No** | FastAPI HTTP listen port |
| `VULN_AI_API__CORS_ORIGINS` | `["http://localhost:3000","http://localhost:5173"]` | **No** | Allowed frontend browser origins |
| `VULN_AI_AI__OLLAMA_BASE_URL` | `http://localhost:11434` | **No** (Optional) | Local Ollama endpoint |
| `VULN_AI_AI__DEFAULT_MODEL` | `llama3.2` | **No** (Optional) | Model tag for contextual AI narratives |
| `VULN_AI_NVD__API_KEY` | *(empty)* | **No** (Optional) | NIST NVD API key to bypass unauthenticated rate limits |
| `VITE_API_BASE_URL` | `http://localhost:8000` | **No** | Frontend gateway endpoint |

---

### Step 4: Start FastAPI Backend Gateway

```bash
# In backend/ with .venv active:
uvicorn vuln_ai.api.main:app --reload --port 8000
```

- **API Base**: `http://localhost:8000`
- **Swagger UI**: [http://localhost:8000/docs](http://localhost:8000/docs)
- **ReDoc**: [http://localhost:8000/redoc](http://localhost:8000/redoc)
- **Liveness Probe**: [http://localhost:8000/health](http://localhost:8000/health)
- **Readiness Probe**: [http://localhost:8000/health/ready](http://localhost:8000/health/ready)

---

### Step 5: Frontend Setup

Open a second terminal window:

```bash
cd Local-Vulnerabilty-Ai/frontend
npm install
```

---

### Step 6: Start Frontend Console

```bash
npm run dev
```

Open your browser to: **`http://localhost:5173`**

---

### Step 7: Run Quality Gates

Verify that all automated tests and linters pass cleanly:

```bash
# Backend Quality Suite (in backend/ with .venv active):
pytest --cov=src --cov-report=term-missing --cov-fail-under=95
ruff check src tests
ruff format --check src tests

# Frontend Quality Suite (in frontend/):
npm run typecheck
npm run lint
npm run format:check
npm test
npm run build
```

---

## 7. Run Your First Vulnerability Scan

Here is a step-by-step walkthrough to scan a project:

1. **Populate Intelligence Feeds**:
   - In the frontend, navigate to **Sources** (`/sources`).
   - Click **Sync Now** on **CISA KEV** or **OSV** to download threat records to your local database.
2. **Register a Project**:
   - Navigate to **Projects** (`/projects`) and click **Register Project**.
   - Enter a name (e.g. `My Application`) and the absolute path to your codebase directory containing a `requirements.txt` or `pyproject.toml`.
3. **Execute the Scan**:
   - In the project detail view, click **Launch Scan**.
   - The scanner parses installed components, queries the local catalog, evaluates version ranges, resolves conflicts, and queries local Ollama if available.
4. **Review Findings & Audit Trail**:
   - Open **Matches** (`/matches`) to inspect detected advisories.
   - Click any match to open the **Match Detail** view (`/matches/:id`):
     - **Evidence Panel**: Inspect exact range intervals evaluated across sources.
     - **Conflict Panel**: Review any divergent verdicts between OSV, NVD, and CISA.
     - **AI Narrative**: Read plain-English explanations and remediation guidance.
     - **Audit Trace**: View the deterministic rules triggered by the Risk Engine.

---

## 8. Command-Line Interface (CLI) & Headless Scanning

In addition to the Web UI, **Local Vulnerability AI** includes an official CLI (`vuln-ai`) for terminal workflows, automated scripts, and CI/CD pipelines (GitHub Actions, GitLab CI, Jenkins):

```bash
# Scan a project and view rich terminal tables:
vuln-ai scan ./my-project

# Machine-readable JSON output for automation:
vuln-ai scan ./my-project --format json

# Fail CI builds if High or Critical vulnerabilities are found:
vuln-ai scan ./my-project --fail-on high

# Export report to file and run without AI:
vuln-ai scan ./my-project --no-ai --format json --output report.json

# Check environment, database, and local AI health:
vuln-ai doctor

# Manage vulnerability intelligence feeds:
vuln-ai sources list
vuln-ai sources sync
```

For complete CLI documentation, options, and CI/CD integration guides, see **[docs/cli.md](docs/cli.md)**.

---

## 9. Documentation Index

Comprehensive technical documentation is maintained in `/docs`:

- **[CLI & CI/CD Guide](docs/cli.md)**: Headless scanning, JSON output, exit codes, and pipeline integrations.
- **[System Architecture](docs/architecture.md)**: Deep dive into domain models, repositories, and services.
- **[Intelligence Sources](docs/sources.md)**: Ingestion mechanisms and limitations for OSV, NVD, and CISA KEV.
- **[Version-Aware Matching](docs/version-matching.md)**: Mathematical interval evaluation for PEP 440, SemVer, and Maven.
- **[Conflict Resolution](docs/conflict-resolution.md)**: Multi-source discrepancy detection and resolution policies.
- **[AI & Decision Support](docs/ai.md)**: Ollama integration, SystemOne probabilities, and offline fallbacks.
- **[REST API Specification](docs/api.md)**: Endpoint documentation, parameters, and payloads.
- **[API & Frontend Contract](docs/api-contract.md)**: Enums, TypeScript mappings, and error formats.
- **[Development Guide](docs/development.md)**: Copy-pasteable testing, formatting, and migration commands.
- **[Troubleshooting Guide](docs/troubleshooting.md)**: Solutions for common connectivity, database, and sync errors.
- **[Privacy Specification](docs/privacy.md)**: Detailed boundaries on data storage and network transmission.

---

## 10. Repository Structure

```text
Local-Vulnerabilty-Ai/
├── .github/
│   └── workflows/
│       └── ci.yml                 # Automated CI quality gates
├── backend/
│   ├── alembic/                  # Database migration versions
│   ├── alembic.ini               # Alembic configuration
│   ├── pyproject.toml            # Python dependencies, tool configs & CLI entrypoint
│   ├── .env.example              # Backend environment template
│   ├── src/vuln_ai/
│   │   ├── ai/                   # Ollama, SystemOne & provider registry
│   │   ├── api/                  # FastAPI routers, middleware & services
│   │   ├── cli/                  # vuln-ai CLI commands, tables & JSON outputs
│   │   ├── core/                 # Scanners, engine & domain models
│   │   ├── db/                   # Async SQLAlchemy models & repositories
│   │   ├── matching/             # Version matcher & conflict resolver
│   │   ├── risk/                 # Deterministic Risk Engine
│   │   └── sources/              # OSV, NVD, and CISA KEV connectors
│   └── tests/
│       ├── api/                  # REST API integration tests
│       ├── cli/                  # CLI execution, exit code & JSON format tests
│       ├── e2e/                  # End-to-end full system integration tests
│       ├── integration/          # Engine and pipeline tests
│       └── unit/                 # Unit tests across core modules
├── frontend/
│   ├── src/
│   │   ├── app/                  # Providers and React Router setup
│   │   ├── components/           # UI components, badges, intelligence cards
│   │   ├── pages/                # Operational SOC pages
│   │   ├── services/             # Typed API client and endpoint hooks
│   │   └── types/                # TypeScript interface contracts
│   ├── package.json              # Node dependencies and scripts
│   ├── vite.config.ts            # Vite configuration
│   └── .env.example              # Frontend environment template
├── docs/                         # Technical architecture and guides
├── CHANGELOG.md                  # Release version history
├── CONTRIBUTING.md               # Contributor and developer guidelines
├── SECURITY.md                   # Vulnerability disclosure policy
├── LICENSE                       # MIT License
└── README.md                     # Main project entrance
```

---

## 11. Contributing

We welcome contributions from the community! Please read our [CONTRIBUTING.md](CONTRIBUTING.md) guide for details on development setup, architectural rules, coding standards, and our pre-PR checklist.

---

## 12. Security & Disclosure

To report a security vulnerability, please review our [SECURITY.md](SECURITY.md) policy. Please do **not** file public GitHub issues for security vulnerabilities.

---

## 13. License

Distributed under the **MIT License**. See [LICENSE](LICENSE) for details.
