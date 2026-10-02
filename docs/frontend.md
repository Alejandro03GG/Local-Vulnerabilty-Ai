# Frontend Architecture & Design System — Local Vulnerability AI (Phase 4)

The frontend layer of **Local Vulnerability AI** is an operational security console built with **React 18**, **TypeScript**, **Vite**, **Tailwind CSS**, and **TanStack Query**. It directly consumes the versioned REST API (`/api/v1`) from Phase 3 without intermediate mock layers, simulated states, or duplicate business logic.

---

## 1. Visual Direction & Design Principles

The interface follows a **"Modern Security Operations Interface"** aesthetic:

* **Dark-First Technical Palette**:
  * Background: Deep slate/zinc `#080c14` (`--background`)
  * Surfaces: Structured elevations `#0d1424` (`--surface`), `#141f36` (`--surface-elevated`)
  * Borders: Disciplined `#1f293d` (`--border`) with subtle focus rings
  * Accents: High-precision cyan `#06b6d4` (`--primary`)
* **Information Density & Hierarchy ("No Card Soup")**:
  * Prioritizes structured data tables, metric strips, and split inspection drawers over generic card clusters.
  * Monospace typography reserved for technical values: CVE IDs, package names, versions, rule IDs, hashes, and probabilities.
* **Conservative Semantic Security States**:
  * Enforces the backend domain model strictly:
    * `DETECTED`: Informational catalog match (Sky)
    * `LIKELY_AFFECTED`: Warning / High attention (Rose/Red)
    * `LIKELY_NOT_AFFECTED`: Safe / Positive (Emerald)
    * `REQUIRES_REVIEW`: Attention / Analyst needed (Amber)
    * `UNKNOWN`: Neutral / Unresolved (Slate)
  * **Critical Principle**: The status `VULNERABLE` does not exist and is never displayed. A catalog match is an indicator, not a confirmed compromise.

---

## 2. Directory Structure

```text
src/
├── app/
│   ├── app.tsx                 # Root application component
│   ├── providers.tsx           # QueryClientProvider, ToastProvider, BrowserRouter
│   └── router.tsx              # React Router v6 nested routes and 404 handler
│
├── components/
│   ├── ui/                     # Primitives (button, badge, input, table, dialog, tabs, skeleton, toast)
│   ├── layout/                 # AppShell, Topbar (live health probe), Sidebar (collapsible + mobile drawer)
│   ├── navigation/             # CommandMenu (⌘K palette)
│   ├── feedback/               # EmptyState, ErrorState with retry actions
│   └── security/               # SecurityStatusBadge, RiskLevelBadge, RuleTraceView, AIFallbackAlert
│
├── features/                   # Feature domain modules
│
├── pages/
│   ├── dashboard/              # Metrics, recent scans, catalog feed status
│   ├── projects/               # Workspace list, registration modal, project detail (tabs)
│   ├── scans/                  # Historical scan executions, findings table, duration
│   ├── components/             # Local software dependencies, manifest source, version certainty
│   ├── vulnerabilities/        # CISA KEV catalog search with filters (CVE, product, vendor)
│   ├── sources/                # Feed management with live synchronization triggers
│   ├── matches/                # 4-stage pipeline audit (Match → AI → SystemOne → Risk Engine)
│   └── settings/               # System configuration, AI inference parameters, air-gap guarantees
│
├── lib/
│   ├── api/                    # Centralized typed HTTP client & resource modules
│   │   ├── client.ts           # Fetch client with X-Request-ID, base URL, error parsing
│   │   ├── health.ts           # /health and /health/ready probes
│   │   ├── projects.ts         # /api/v1/projects CRUD
│   │   ├── scans.ts            # /api/v1/scans and scan triggers
│   │   ├── components.ts       # /api/v1/projects/{id}/components
│   │   ├── vulnerabilities.ts  # /api/v1/vulnerabilities catalog query
│   │   ├── sources.ts          # /api/v1/sources and sync trigger
│   │   └── matches.ts          # /api/v1/matches and AI re-analysis
│   │
│   ├── query/
│   │   └── query-keys.ts       # Centralized query keys factory
│   │
│   └── utils.ts                # cn() class merger and date/duration formatters
│
├── styles/
│   └── globals.css             # Tailwind base layers, security variables, custom scrollbars
│
└── types/                      # Pydantic-aligned TypeScript schemas
    ├── api.ts                  # ApiError, ErrorResponse, PaginatedResponse
    ├── project.ts              # Project, ProjectCreate, ProjectUpdate
    ├── scan.ts                 # Scan, ScanSummary, ScanCreateRequest
    ├── component.ts            # Component
    ├── vulnerability.ts        # Vulnerability, VulnerabilityFilters
    ├── source.ts               # Source, SourceSyncResult
    ├── match.ts                # Match
    ├── ai.ts                   # AIAnalysis, DecisionResult
    └── risk.ts                 # RiskAssessment, SecurityStatus, RiskLevel
```

---

## 3. The 4-Layer Inspection Pipeline

The platform is designed around strict separation of analytical stages:

```text
┌────────────────────────────────────────────────────────┐
│ 1. Deterministic Match Layer                           │
│    - Package name equality (e.g. Django -> Django)     │
│    - Match confidence score (0.0 - 1.0)                │
│    - Explicit evidence statements                      │
└────────────────────────────────────────────────────────┘
                           │
                           ▼
┌────────────────────────────────────────────────────────┐
│ 2. Contextual AI Narrative (Ollama LLM)                │
│    - Model & Provider attribution (e.g. llama3.2)      │
│    - Contextual explanation & extracted evidence       │
│    - Honest fallback disclosure when offline           │
└────────────────────────────────────────────────────────┘
                           │
                           ▼
┌────────────────────────────────────────────────────────┐
│ 3. SystemOne Probabilistic Decision                    │
│    - Applicability probability bar (0 - 100%)          │
│    - Urgency prioritization score                      │
│    - Structured model responses                        │
└────────────────────────────────────────────────────────┘
                           │
                           ▼
┌────────────────────────────────────────────────────────┐
│ 4. Deterministic Risk Assessment & Rule Trace          │
│    - Conservative status (REQUIRES_REVIEW, etc.)       │
│    - Auditable rule IDs (MATCH_COMPONENT_ONLY, etc.)   │
│    - Concrete remediation instructions                 │
└────────────────────────────────────────────────────────┘
```

---

## 4. API Endpoints Consumed

All endpoints match the FastAPI backend from Phase 3 (`docs/api.md`):

| Method | Endpoint | Description |
|---|---|---|
| `GET` | `/health` | Liveness probe |
| `GET` | `/health/ready` | Readiness probe (database connectivity) |
| `GET` | `/api/v1/projects` | Paginated project list |
| `POST` | `/api/v1/projects` | Register new workspace |
| `GET` | `/api/v1/projects/{id}` | Workspace detail |
| `DELETE` | `/api/v1/projects/{id}` | Delete project |
| `POST` | `/api/v1/projects/{id}/scans` | Initiate scan (`run_ai: true`) |
| `GET` | `/api/v1/scans` | List historical scans |
| `GET` | `/api/v1/scans/{id}` | Get scan detail and matches |
| `GET` | `/api/v1/projects/{id}/components` | List detected dependencies |
| `GET` | `/api/v1/components/{id}` | Component detail |
| `GET` | `/api/v1/vulnerabilities` | Query catalog with `cve`, `vendor`, `product` |
| `GET` | `/api/v1/vulnerabilities/{id}` | Vulnerability catalog detail |
| `GET` | `/api/v1/sources` | Catalog sources list |
| `POST` | `/api/v1/sources/{id}/sync` | Trigger CISA KEV remote feed sync |
| `GET` | `/api/v1/matches/{id}` | Full match details |
| `GET` | `/api/v1/matches/{id}/analysis` | AI contextual narrative |
| `GET` | `/api/v1/matches/{id}/decision` | SystemOne decision probabilities |
| `POST` | `/api/v1/matches/{id}/reanalyze` | Re-evaluate match with AI & Risk Engine |
| `GET` | `/api/v1/matches/{id}/risk` | Deterministic Risk Engine evaluation |

---

## 5. Development & Testing Workflow

### Configuration

Create a `.env` file or export environment variables:

```bash
VITE_API_BASE_URL=http://localhost:8000
```

*(If unset in development, Vite proxies `/api` and `/health` requests directly to `http://127.0.0.1:8000`)*.

### Available Scripts

```bash
# Run local dev server (port 5173)
npm run dev

# Compile TypeScript and create production bundle
npm run build

# Run TypeScript static type check
npm run typecheck

# Run ESLint validation
npm run lint

# Format codebase with Prettier
npm run format

# Verify code formatting
npm run format:check

# Run Vitest test suite
npm run test

# Run Vitest with V8 code coverage
npm run test:coverage
```
