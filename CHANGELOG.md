# Changelog

## [Unreleased] — Stage 19.1 Product Hardening

### Fixed
- Nullable `cve_id` end-to-end (API/frontend/export) for GHSA/RUSTSEC-only advisories (H17)
- Incremental catalog upsert no longer destroys other ecosystems; KEV prune isolated (H1/H16/H2)
- `fail_on` severity thresholds skip `likely_not_affected` findings (H13)
- pnpm-lock.yaml multi-document YAML parsing (H21)
- uv.lock scanner for exact Python versions (H18)
- Safe recursive monorepo manifest discovery (H7)
- Global `GET /api/v1/components` aligned with frontend (H3)
- Risk engine no longer inflates LOW for not-applicable findings (H10)
- apt-get `package=version` extraction in Dockerfile AST (H8)
- Dockerfile AST persistence into Images API/UI (H9)
- Policy docs include required suppression audit fields (H12)
- Clearer policy threshold violation messages (H14)
- CLI `-o` exports no longer dump full JSON to stdout (H15)
- Unknown versions remain UNKNOWN / requires review (H19)

### Added
- Frontend branding assets and EN/ES i18n (ported from Stage 19 lab validation)


All notable changes to the **Local Vulnerability AI** platform are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [Unreleased]

## [1.0.1] - 2026-10-04

### Fixed
- Backend CI Quality Gates on GitHub Actions: enable coverage `sysmon` so the 95% gate matches local measurement.
- Pin SQLAlchemy to the 2.0.x line for async/SQLite stability in CI.
- Relax large-export timing assertion under coverage instrumentation on CI runners.
- CLI help regressions under `CI=true` force-color terminals (Rich ANSI splits inside `--format` / related flags).
- Isolate container image 404 API tests on the in-memory `api_client` fixture.

## [1.0.0] - 2026-10-03

### Security Engine
- Deterministic vulnerability matching, conflict resolution, and risk assessment pipeline.
- Canonical applicability vocabulary (`LIKELY_AFFECTED`, `LIKELY_NOT_AFFECTED`, `REQUIRES_REVIEW`, `UNKNOWN`); status `VULNERABLE` prohibited.

### Dependency Scanning
- Python, Poetry, npm, pnpm, and Cargo lockfile/manifest scanners.
- Dependency Graph with direct/transitive provenance and multi-version support.

### Container Scanning
- Static Docker/OCI archive and Dockerfile analysis via `ImageSource` / `LocalOCIArchiveSource`.
- OS package detection (`dpkg`, `apk`, `rpm`) with version strategies for `deb` / `apk` / `rpm`.
- Zero-execution guarantee (no container runtime invocation during analysis).
- CLI: `vuln-ai image scan <archive.tar|Dockerfile>`.

### AI
- Optional local Ollama / SystemOne assistance; non-authoritative; graceful offline degradation; `--no-ai` support.

### Risk / Policy / Suppressions
- Deterministic Risk Engine, Policy Engine, and auditable Suppression lifecycle with `FixedClock` support.
- Optional image-digest scoping for container findings.

### CLI / API / Frontend
- Headless CLI (`scan`, `image`, `sources`, `policy`, `suppression`, `doctor`, `version`).
- FastAPI surface for projects, scans, matches, sources, policies, suppressions, images, and exports.
- React SOC console including Container Images views.

### Exports
- SARIF 2.1.0, CycloneDX 1.5, and SPDX 2.3 with container provenance properties.

### Security & Privacy
- Local-first model; documented egress (OSV/NVD/CISA KEV + optional localhost Ollama).
- Archive/path/symlink hardening; YAML safe loading; no secret persistence for registry credentials.

### Documentation
- Installation, CLI, API, architecture, privacy, container/image security, policy, exports, and release checklist.

### Known Limitations
- No registry authentication, Docker daemon dependency, Kubernetes/Helm, or runtime monitoring in 1.0.

### Detailed Functional Breakdown

#### Container & Image Scanning Engine (Etapa 17)
- **Zero-Execution Architecture & OCI/Docker Parser**:
  - `ImageSource` abstraction with `LocalOCIArchiveSource` (implemented) and placeholders for daemon/registry sources.
  - OS package version strategies for `deb` / `apk` / `rpm` ecosystems in the shared Version Matcher.
  - Pure static archive extraction and layer inspection for Docker v1/v1.2/v2 and OCI Image specifications (`.tar`).
  - Zero-Execution Guarantee: strictly zero execution of containers, entrypoints, binaries, or container runtimes (`docker run`, `docker exec`, `docker build`, `podman run`).
  - No Docker daemon or socket dependency: runs completely standalone in rootless environments.
  - Layer stacking engine with deterministic whiteout resolution: standard whiteouts (`.wh.<file>`) and opaque whiteouts (`.wh..wh..opq`).
- **Operating System Package Discovery**:
  - Native static parser for Alpine Linux APK databases (`/lib/apk/db/installed`).
  - Native static parser for Debian / Ubuntu DPKG status files (`/var/lib/dpkg/status`).
  - Native static parser for Red Hat / CentOS / Fedora / Rocky RPM databases (`/var/lib/rpm/Packages`, SQLite `rpmdb.sqlite`).
  - Layer provenance attribution: every OS package is tagged with its layer index and layer digest.
- **Recursive Application Manifest Discovery**:
  - Traverses unpacked rootfs directories to discover application dependency manifests (`requirements.txt`, `pyproject.toml`, `package.json`, `package-lock.json`, `pom.xml`, `Cargo.lock`, `go.mod`).
  - Passes discovered manifests to existing ecosystem scanners, mapping application packages directly into the container component inventory.
- **Single Security Engine Integration**:
  - Directly feeds all extracted OS and application components to the canonical Vulnerability Catalog, Version Matcher, Conflict Resolver, Deterministic Risk Engine, and Policy Engine without duplicate matcher code.
- **Static Dockerfile AST Analysis**:
  - Pure Python AST lexer and parser for Dockerfiles without building workloads.
  - Multi-stage build resolution: stage naming (`AS <alias>`), runtime target identification, base image audit.
  - Detection of package manager commands (`apt-get`, `apk`, `yum`, `dnf`, `pip`, `npm`) and copied dependency manifests.
- **Database & Repositories**:
  - Alembic migration `i2e5f7a3b8c9` introducing `container_images` and `container_layers` tables, and adding `layer_index`, `layer_digest`, `package_type` to `detected_components`.
  - `ContainerImageRepository` with cascade deletes and eager layer relationship loading.
- **CLI Subcommands**:
  - `vuln-ai image scan <ARCHIVE.tar|Dockerfile>`: static scan of container archives or Dockerfiles with `--reference`, `--policy`, `--format`, `--output`, `--no-ai`, `--fail-on`.
  - Image inventory/detail via API (`GET /api/v1/images`) and frontend Container Images page.
- **REST API Endpoints**:
  - `/api/v1/images`: list scanned images (paginated).
  - `/api/v1/images/scan`: static container archive scanning.
  - `/api/v1/images/{id}`: image summary and metadata.
  - `/api/v1/images/{id}/layers`: layer details and build instructions.
  - `/api/v1/images/{id}/components`: detected OS & application packages.
  - `/api/v1/images/{id}/vulnerabilities`: correlated vulnerability findings.
  - `/api/v1/images/{id}/policy`: policy compliance evaluation.
  - `/api/v1/images/{id}/dependency-graph`: hierarchical component topology.
  - `/api/v1/container/dockerfile/scan`: static Dockerfile AST parsing.
- **React UI Security Console**:
  - `ContainerImagesPage`: summary metric cards, image inventory table, archive scan modal, and Dockerfile AST analyzer modal.
  - `ImageDetailPage`: 5 dedicated tabs (Overview, Layers, Components with OS/App filters, Findings with Risk & Applicability badges, and Dependency Graph topology).
  - Wired into navigation router, sidebar (`Images` with `Boxes` icon), and command menu.
- **Documentation**:
  - Created `docs/container-scanning.md`, `docs/dockerfile-scanning.md`, `docs/image-security.md`.
  - Updated `README.md`, `CHANGELOG.md`, `docs/api-contract.md`, `docs/cli.md`, `docs/ci-cd.md`.

#### Advanced Policy & Suppression Engine (Etapa 16)
- **Declarative Policy Domain & Conditions**:
  - Declarative policy rules with rich conditions: `severity`, `risk_level`, `applicability`, `dependency_type` (`DIRECT` vs `TRANSITIVE`), `scope` (`RUNTIME`, `DEV`), `ecosystem`, `package_name`, `package_version`, `vulnerability_id`, `source`, `has_kev_evidence`, `cvss_score` with comparator (`>=`, `>`, `==`, `<=`, `<`), `requires_human_review`, `conflict_detected`, `conflict_type`.
  - Action hierarchy: `BLOCK` > `REQUIRE_REVIEW` > `ACCEPT_RISK` > `ALLOW`.
  - Global thresholds: `fail_on` severities, `fail_on_review` security gate.
  - Safe YAML parser (`.vuln-ai.yaml`) enforcing 1MB file limit, forbidden arbitrary code execution, forbidden extra fields, duplicate rule ID rejection, and canonical terminology enforcement.
- **Suppression Lifecycles & Audit Engine**:
  - Lifecycle statuses: `ACTIVE` (grants CI exemption), `EXPIRED` (warns and fails CI), `DISABLED` (ignored).
  - Attributes: `id`, `project_id`, `match_criteria`, `reason`, `owner`, `reference`, `expires_at`, `created_by`, timestamps.
  - Injectable `Clock` (`SystemClock`, `FixedClock`) for deterministic testing of time-bound expiration.
  - Core Invariant: Technical findings are never deleted, hidden, or modified upon suppression.
- **Deterministic Evaluation Engine**:
  - Precedence order: Active suppression > Expired suppression warning > Rule action hierarchy > Global thresholds > Default action fallback.
  - Pure deterministic evaluation without AI hallucinations or non-deterministic heuristics.
- **Database & Repositories**:
  - Alembic migration `h1d4e6f2a7b8` introducing `policies`, `policy_rules`, `suppressions`, and `policy_evaluations` tables.
  - `PolicyRepository` and `SuppressionRepository` with cascade deletes and JSON serialization.
- **CLI Commands & Exit Code Semantics**:
  - `vuln-ai policy validate <FILE>`: schema, limit, and duplicate ID verification.
  - `vuln-ai policy check <FILE>`: rule inspector table.
  - `vuln-ai suppression list [--json]`: audit ledger of security exceptions.
  - `vuln-ai scan` with `--policy <FILE>`, `--no-policy`, `--show-policy`, `--show-suppressions`.
  - Deterministic exit codes: `0` (Success/Suppressed), `1` (Policy violation / expired suppression failure), `2` (CLI usage/parser error), `3` (Internal error).
- **REST API Endpoints**:
  - Policies: `GET /api/v1/policies`, `POST /api/v1/policies`, `GET /api/v1/policies/{id}`, `PUT /api/v1/policies/{id}`, `DELETE /api/v1/policies/{id}`, `POST /api/v1/policies/validate`.
  - Suppressions: `GET /api/v1/suppressions`, `POST /api/v1/suppressions`, `GET /api/v1/suppressions/{id}`, `PUT /api/v1/suppressions/{id}`, `DELETE /api/v1/suppressions/{id}`.
  - Scan Evaluation: `POST /api/v1/scans/{id}/policy/evaluate`, `GET /api/v1/scans/{id}/policy`.
- **Export Format Integration**:
  - SARIF 2.1.0: native `suppressions` objects and `policyStatus`, `policyRuleIds` properties.
  - CycloneDX 1.5: `vuln_ai:policy_status` and `vuln_ai:suppression_reason` properties.
  - SPDX 2.3: findings documented while preserving `NOASSERTION` licensing.
- **React UI Security Console**:
  - `PoliciesPage`: policy catalog, rule inspector, threshold overview, and interactive YAML validator.
  - `SuppressionsPage`: audit ledger with status badges (`ACTIVE`, `EXPIRED`, `DISABLED`), filter tabs, and expiration warnings.
  - `ScanDetailPage`: dedicated "Policy & Compliance Evaluation" card displaying Policy Decision vs Technical Risk, CI exit code, violation table, and applied suppressions.
  - App navigation: added `/policies` and `/suppressions` to router and sidebar.
- **Documentation**:
  - Created `docs/policy.md` and `docs/suppressions.md`.
  - Updated `docs/cli.md`, `docs/api-contract.md`, `docs/ci-cd.md`, `README.md`.
- **Canonical Export Model (`ExportScan`)**: Intermediate representation decoupling security analysis from serialization formats, ensuring the Core Engine is evaluated once and transformed into multiple export standards without re-evaluating risk, re-matching, or querying external feeds.
- **SARIF 2.1.0 Exporter**:
  - Conformance with OASIS SARIF 2.1.0 JSON standard.
  - Rule deduplication: 1 Rule per canonical vulnerability, N Results per affected component.
  - Deterministic level mapping from Risk Engine: `CRITICAL`/`HIGH` -> `error`, `MEDIUM` -> `warning`, `LOW`/`INFO` -> `note`.
  - Honest locations preserving real manifest and lockfile paths without artificial line/column ranges.
  - Enriched properties capturing applicability, review requirements, conflict summaries, and dependency paths.
- **CycloneDX 1.5 JSON SBOM Exporter**:
  - Conformance with CycloneDX 1.5 JSON BOM specification.
  - Package URLs (PURLs) generated across PyPI, npm (with URL-encoded scopes), and Cargo.
  - Dependency graph topology preserving directed edges, scopes, and provenance.
  - Vulnerability ratings and triage analysis states (`exploitable`, `in_triage`, `not_affected`, `false_positive`).
- **SPDX 2.3 JSON SBOM Exporter**:
  - Conformance with SPDX 2.3 JSON specification.
  - Application root package and component packages with sanitized SPDXIDs and PURL external references.
  - Honest license declarations using `NOASSERTION` without guessing or fabricating licenses.
  - Explicit package relationship mapping (`DESCRIBES`, `DEPENDS_ON`).
- **Export Service & Atomic Persistence**:
  - Safe, atomic file persistence via temporary files and `os.replace` preventing partial or corrupted export artifacts.
- **CLI Enhancements**:
  - Extended `vuln-ai scan` with `--format sarif|cyclonedx|spdx` and `--output <FILE>`.
  - Clean `stdout` machine-readable output and isolated `stderr` diagnostic logging.
  - Preserved exit code semantics (`0`, `1`, `2`, `3`).
- **REST API Endpoints**:
  - `GET /api/v1/scans/{id}/export/sarif` (`application/sarif+json`)
  - `GET /api/v1/scans/{id}/export/cyclonedx` (`application/vnd.cyclonedx+json`)
  - `GET /api/v1/scans/{id}/export/spdx` (`application/spdx+json`)
- **Web UI Integration**:
  - Direct export download actions in `ScanDetailPage` with error toasts.
- **Documentation**:
  - Comprehensive guide in `docs/export-formats.md` with CI/CD integration patterns (GitHub Actions, GitLab CI, Jenkins) and local-first privacy notice.

#### Extended Ecosystems & Lockfile Resolution (Etapa 14)
- **Dependency Graph Domain**: Formal `DependencyNode`, `DependencyEdge`, and `DependencyGraph` abstractions modeling complete dependency DAGs with breadth-first search path reconstruction.
- **Lockfile Intelligence & Precedence (`LOCKFILE > MANIFEST`)**:
  - Python: `poetry.lock` static parser extracting exact versions, groups, hashes, and dependency relations.
  - Node.js: `package-lock.json` parser supporting lockfile versions 1, 2, and 3, optional/peer dependencies, and nested multi-version `node_modules`.
  - pnpm: `pnpm-lock.yaml` safe static YAML parser supporting formats v5, v6, and v9.
  - Rust: `Cargo.lock` static TOML parser supporting workspace crates, crate versions, and multi-version dependencies.
- **Direct vs. Transitive Provenance**: Deterministic classification of direct vs. transitive dependencies with full path resolution (`dependency_path`) and parent relationship tracing.
- **Multi-Version Resolution**: Independent node identity (`ecosystem:name:version`) enabling distinct simultaneous versions of the same package (e.g. `lodash@3.x` and `lodash@4.x`) to be matched without collision.
- **Cycle & DoS Protection**: Breadth-first cycle protection with depth limits and Tarjan-style cycle detection preventing recursion explosions. Safe YAML deserialization rejecting unsafe custom loaders.
- **API Endpoints**: Added `GET /api/v1/scans/{scan_id}/dependencies` and `GET /api/v1/scans/{scan_id}/dependencies/graph`.
- **CLI & Output Integration**: Enhanced table and JSON outputs with direct/transitive counts, dependency edges, detected lockfiles, and table columns `Type` and `Origin`.
- **Frontend Intelligence**: Enhanced Components table with `Dependency Type`, `Scope`, and `Origin Source`, and dedicated `Dependency Intelligence & Graph Provenance` section in Match Details.


---

## [0.1.0] - 2026-10-02

Initial production-ready release of Local Vulnerability AI combining deterministic vulnerability matching, multi-source intelligence correlation, contextual local AI analysis, probabilistic decision support, and an operational Security Operations Center (SOC) web console.

### Added

#### Core Domain & Persistence (Etapa 1)
- Domain entities: `Project`, `Scan`, `DetectedComponent`, `Vulnerability`, `MatchResult`.
- Dependency manifest parsers for Python ecosystem (`requirements.txt`, `pyproject.toml`, `setup.py`, `Pipfile`).
- Asynchronous SQLite persistence engine configured with Write-Ahead Logging (`WAL`) mode and foreign key constraints.
- Alembic database migration management system.
- Initial CISA KEV catalog schema and local repository.

#### AI & Risk Intelligence Engine (Etapa 2)
- Provider-agnostic AI abstraction layer (`AIProvider`, `DecisionProvider`, `AIRegistry`).
- Local Ollama contextual narrative provider (`llama3.2`).
- SystemOne probabilistic decision provider for fast triage classification.
- Rule-based Deterministic Risk Engine producing auditable `RiskAssessment` objects with granular `rule_ids`, categorical `RiskLevel` (`LOW`, `MEDIUM`, `HIGH`, `CRITICAL`), and `requires_human_review` flags.
- Strict isolation guarantee: deterministic rules maintain ultimate authority; AI output serves strictly as supplementary decision support.

#### FastAPI REST API (Etapa 3)
- Versioned REST API under `/api/v1`.
- Endpoints for `Projects`, `Scans`, `Components`, `Vulnerabilities`, `Matches`, and `Sources`.
- Unversioned liveness (`/health`) and readiness (`/health/ready`) probes with database and AI availability diagnostics.
- Standardized error handling middleware with structured JSON payloads (`error.code`, `error.message`, `error.request_id`) and `X-Request-ID` propagation.
- Interactive OpenAPI documentation via Swagger UI (`/docs`) and ReDoc (`/redoc`).

#### Multi-Source Vulnerability Intelligence (Etapas 4, 5, 6)
- **OSV Integration (Etapa 4)**: Open Source Vulnerabilities ecosystem client, advisory range parsing (`introduced`, `fixed`, `limit`, `last_affected`), and alias cross-referencing.
- **NVD Integration (Etapa 5)**: National Vulnerability Database CVE 2.0 API client, CVSS metrics extraction, and CPE package mapping.
- **CISA KEV Integration (Etapa 6)**: Known Exploited Vulnerabilities catalog feed ingestion, active ransomware exploitation tracking, and remediation due dates.
- Canonical vulnerability deduplication preserving single identity across multiple sources.

#### Version-Aware Semantic Matching (Etapas 7 & 7.1)
- Ecosystem-specific version comparison strategies:
  - Python / PyPI: PEP 440 version semantics via `packaging`.
  - JavaScript / Rust / Go / NuGet: SemVer 2.0 semantics via `semver`.
  - Java / Maven: Maven version ordering specification.
- Event range evaluation supporting `[introduced, fixed)`, `[introduced, limit)`, `[introduced, last_affected]`, open ranges, and outside-range verifications.

#### Multi-Source Conflict Resolution (Etapa 9)
- Conflict detection engine identifying divergent applicability verdicts, discordant version boundaries, and mismatched severities across sources.
- Conservative resolution policy: if sources disagree on applicability, status automatically resolves to `REQUIRES_REVIEW` and triggers `requires_human_review = True` in the Risk Engine under rule `SOURCE_APPLICABILITY_CONFLICT`.
- Persistent structured evidence (`MatchEvidence`) and auditable discrepancy logs (`SourceConflict`).

#### Security Operations Frontend (Etapa 10)
- Operational SOC dashboard built with React 18, TypeScript, Vite, Tailwind CSS, and TanStack Query.
- Views: Dashboard, Projects, Scans, Components, Vulnerabilities, Matches, Sources, Settings.
- Flagship Match Detail view featuring `ConflictPanel`, `AIAnalysisCard`, `SystemOneCard`, and `AuditTrace`.
- Global keyboard navigation with `CommandMenu` (⌘K / Ctrl+K).
- Strict canonical security state indicators (`DETECTED`, `LIKELY_AFFECTED`, `LIKELY_NOT_AFFECTED`, `REQUIRES_REVIEW`, `UNKNOWN`). The forbidden state `VULNERABLE` is never displayed.

#### End-to-End Hardening & Integration (Etapa 11)
- Comprehensive E2E test suite (`backend/tests/e2e/test_end_to_end_scenarios.py`) validating complete flows from project creation to UI presentation.
- Elimination of $O(N)$ database queries in `ScanService` using eager loading with `selectinload`.
- Offline resilience: full scan and deterministic risk evaluation complete cleanly when Ollama or external sources are offline.
- Case-insensitive contract alignment between backend schemas and frontend TypeScript types.

#### Release Engineering & Developer Experience (Etapa 12)
- Comprehensive developer onboarding guides: `CONTRIBUTING.md`, `SECURITY.md`, `CHANGELOG.md`, `README.md`.
- Deep-dive technical specifications: `docs/sources.md`, `docs/version-matching.md`, `docs/conflict-resolution.md`, `docs/ai.md`, `docs/troubleshooting.md`, `docs/api-contract.md`, `docs/privacy.md`, `docs/development.md`.
- Continuous Integration workflow via GitHub Actions (`.github/workflows/ci.yml`) validating backend test coverage, linting, formatting, Alembic migration roundtrip, and frontend build.

#### CLI, Headless Scanning & CI/CD Integration (Etapa 13)
- Official command-line interface executable (`vuln-ai`) powered by Typer and Rich with console script entry point.
- Headless scanning (`vuln-ai scan <path>`) reusing core `ScanEngine` without requiring FastAPI or a web browser.
- Machine-readable JSON output (`--format json`) strictly isolated on `stdout` without ANSI code escape pollution.
- Deterministic exit codes: `0` (clean), `1` (threshold violated), `2` (usage/config error), `3` (internal failure).
- Policy enforcement options: `--fail-on [low|medium|high|critical]` and `--fail-on-review`.
- Report artifact generation via `--output <filepath>`.
- Lean execution mode (`--no-ai`) disabling LLMs for lightweight CI/CD agents while preserving deterministic risk evaluation.
- Catalog management subcommands: `vuln-ai sources list` and `vuln-ai sources sync`.
- System diagnostic check: `vuln-ai doctor` testing Python, SQLite schema, Alembic migration state, catalog volume, and local AI availability.
- Dedicated CLI test suite (`backend/tests/cli/`) validating command options, error handling, exit codes, and subprocess execution.

