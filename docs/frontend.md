# Frontend Architecture & Implementation — Local Vulnerability AI (Etapa 10)

The frontend layer of **Local Vulnerability AI** is an operational security console built with **React 18**, **TypeScript**, **Vite**, **Tailwind CSS**, and **TanStack Query**. It directly consumes the versioned REST API (`/api/v1`) without intermediate mock layers, simulated states, or duplicate security logic.

---

## 1. Visual Direction & Design Principles

The interface follows a **"Modern Security Operations Interface"** aesthetic:

* **Dark-First Technical Palette**:
  * Background: `#090d16` (`bg-soc-bg`)
  * Surfaces: Structured elevations `#111827` (`bg-soc-surface`), `#1a2234` (`bg-soc-elevated`)
  * Borders: Disciplined `#1f293d` (`border-soc-border`) with subtle focus rings
  * Accents: High-precision blue `#2563eb` and cyan accents
* **Information Density & Hierarchy ("No Card Soup")**:
  * Prioritizes structured data tables (`DataTable`), metric strips (`Metric`), and intelligence split panels.
  * Monospace typography reserved for technical values: CVE IDs, package names, versions, rule IDs, and probabilities.
* **Conservative Semantic Security States**:
  * Enforces the backend domain model strictly:
    * `DETECTED`: Informational catalog match (Purple)
    * `LIKELY_AFFECTED`: Warning / High attention (Rose)
    * `LIKELY_NOT_AFFECTED`: Outside affected range (Emerald)
    * `REQUIRES_REVIEW`: Multi-source conflict / Human attention needed (Amber)
    * `UNKNOWN`: Neutral / Unresolved (Slate)
  * **Critical Principle**: The status `VULNERABLE` does not exist and is never displayed. A catalog match is an indicator, not a confirmed compromise.
* **Multi-Source Conflict & Audit Transparency**:
  * Discrepancies between sources (OSV, NVD, CISA KEV) are surfaced in `ConflictPanel`.
  * Deterministic rule-based evaluation reasons are chronologically audited in `AuditTrace`.
  * AI analysis (Ollama) and SystemOne fast-inference probabilities are explicitly designated as contextual decision support.

---

## 2. Directory Structure

```text
frontend/
├── public/
├── src/
│   ├── app/
│   │   ├── App.tsx                 # Root application component
│   │   ├── providers.tsx           # QueryClientProvider, ToastProvider
│   │   └── router.tsx              # React Router v6 routes
│   │
│   ├── components/
│   │   ├── badges/                 # Semantic status and risk indicators
│   │   │   ├── ApplicabilityBadge.tsx
│   │   │   ├── RiskBadge.tsx
│   │   │   ├── ScanStatusBadge.tsx
│   │   │   ├── SourceStatusBadge.tsx
│   │   │   └── ReviewBadge.tsx
│   │   ├── intelligence/           # Core Security Operations components
│   │   │   ├── AIAnalysisCard.tsx
│   │   │   ├── AuditTrace.tsx
│   │   │   ├── ConflictPanel.tsx
│   │   │   └── SystemOneCard.tsx
│   │   ├── layout/                 # Shell, Navigation, Topbar & Command Menu
│   │   │   ├── AppShell.tsx
│   │   │   ├── CommandMenu.tsx     # ⌘K / Ctrl+K Palette
│   │   │   ├── PageHeader.tsx
│   │   │   ├── Sidebar.tsx
│   │   │   └── Topbar.tsx
│   │   └── ui/                     # UI Primitives
│   │       ├── DataTable.tsx       # Dense, accessible, sortable data table
│   │       ├── EmptyState.tsx
│   │       ├── ErrorState.tsx      # With Request ID & Retry action
│   │       ├── LoadingState.tsx    # Skeletons and Spinners
│   │       ├── Metric.tsx
│   │       └── Toast.tsx
│   │
│   ├── context/
│   │   └── ToastContext.ts
│   ├── hooks/
│   │   └── useToast.ts
│   ├── lib/
│   │   └── utils.ts                # cn, formatDate, formatDuration, formatPercent
│   │
│   ├── pages/
│   │   ├── ComponentsPage.tsx
│   │   ├── DashboardPage.tsx
│   │   ├── MatchDetailPage.tsx     # Flagship deep intelligence screen
│   │   ├── MatchesPage.tsx
│   │   ├── ProjectDetailPage.tsx
│   │   ├── ProjectsPage.tsx
│   │   ├── ScanDetailPage.tsx
│   │   ├── ScansPage.tsx           # Auto-polling during active execution
│   │   ├── SettingsPage.tsx
│   │   ├── SourcesPage.tsx         # Source sync operations
│   │   ├── VulnerabilitiesPage.tsx
│   │   └── VulnerabilityDetailPage.tsx
│   │
│   ├── services/
│   │   └── api/
│   │       ├── client.ts           # Typed fetch client with X-Request-ID
│   │       ├── components.ts
│   │       ├── health.ts
│   │       ├── matches.ts
│   │       ├── projects.ts
│   │       ├── scans.ts
│   │       ├── sources.ts
│   │       └── vulnerabilities.ts
│   │
│   ├── styles/
│   │   └── globals.css
│   ├── test/                       # Unit and integration test suite
│   │   ├── apiClient.test.ts
│   │   ├── badges.test.tsx
│   │   ├── conflictAndAudit.test.tsx
│   │   ├── criticalConflict.test.tsx # Critical non-VULNERABLE check
│   │   ├── dataTableAndMetric.test.tsx
│   │   ├── details.test.tsx
│   │   ├── fixtures.ts
│   │   ├── routing.test.tsx
│   │   ├── setup.ts
│   │   └── uiStates.test.tsx
│   │
│   ├── types/
│   │   └── index.ts                # Domain models matching FastAPI schemas
│   ├── main.tsx
│   └── vite-env.d.ts
├── .env.example
├── index.html
├── package.json
├── tsconfig.json
├── vite.config.ts
├── vitest.config.ts
├── tailwind.config.js
├── postcss.config.js
├── eslint.config.js
└── prettier.config.js
```

---

## 3. Operational Routes

| Route | View | Description |
| :--- | :--- | :--- |
| `/` | `DashboardPage` | Real-time security posture, telemetry metrics, risk breakdown, recent scans |
| `/projects` | `ProjectsPage` | Target codebases, project registration modal, launch scan action |
| `/projects/:projectId` | `ProjectDetailPage` | Project meta, execution history, detected dependencies, scan trigger |
| `/scans` | `ScansPage` | Scan execution history with active polling (`pending` / `running`) |
| `/scans/:scanId` | `ScanDetailPage` | Scan duration, components, findings breakdown, failure diagnostics |
| `/components` | `ComponentsPage` | Global software component inventory across all projects |
| `/vulnerabilities` | `VulnerabilitiesPage` | Synchronized vulnerability advisories catalog |
| `/vulnerabilities/:vulnerabilityId` | `VulnerabilityDetailPage` | Advisory metadata, CWE classifications, and CISA KEV directives |
| `/matches` | `MatchesPage` | Correlated matches with strict semantic statuses and filters |
| `/matches/:matchId` | `MatchDetailPage` | Flagship screen: Evidence, Conflicts, AI, SystemOne, Risk & AuditTrace |
| `/sources` | `SourcesPage` | Intelligence sources status (OSV, NVD, CISA KEV) with sync action |
| `/settings` | `SettingsPage` | Environment diagnostics, API Gateway connectivity, reduced motion |

---

## 4. End-to-End Setup & Quality Verification

Follow this 7-step workflow to install, run, and verify the full application:

1. **Backend setup**: `cd backend && python3 -m venv .venv && source .venv/bin/activate && pip install -e ".[dev]"`
2. **Database migration**: `alembic upgrade head`
3. **Environment variables**: `cp backend/.env.example backend/.env` and `cp frontend/.env.example frontend/.env`
4. **Start API**: `uvicorn vuln_ai.api.main:app --port 8000`
5. **Frontend setup**: `cd frontend && npm install`
6. **Start frontend**: `npm run dev` (Runs on `http://localhost:5173`)
7. **Run tests**:
   * Frontend: `npm run typecheck && npm run lint && npm run format:check && npm test && npm run build`
   * Backend: `pytest --cov=src --cov-fail-under=95 && ruff check src tests && ruff format --check src tests`
