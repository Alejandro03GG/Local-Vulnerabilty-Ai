# Contributing to Local Vulnerability AI

Thank you for your interest in contributing to **Local Vulnerability AI**. This project is an open-source, local-first platform for transparent, deterministic, and auditable vulnerability analysis.

Current release line: **v1.1.3**. Keep changes compatible with this line unless a PR explicitly documents a breaking change.

---

## Contributor journey

```text
Fork the repository
        ↓
Clone your fork
        ↓
Install backend + frontend
        ↓
Create a branch
        ↓
Make focused changes
        ↓
Add / update tests
        ↓
Run validation (tests, lint, format, build)
        ↓
Open a Pull Request using the template
```

Detailed setup and commands are below. Architecture deep-dives live in [`docs/`](docs/).

---

## 1. Code of Conduct & Development Principles

All contributions must adhere to these architectural principles:

1. **Deterministic Authority**: The Version-Aware Matcher, Conflict Resolver, and Risk Engine must remain 100% deterministic and rule-based. AI models (Ollama, SystemOne) are supplementary decision support only; they must never have final authority over vulnerability verdicts.
2. **Strict Privacy**: Never pass user source code, repository content, or credentials to AI providers. Only component metadata (package name, installed version, advisory ID) may be sent to local LLMs.
3. **Canonical Security States**: Use only canonical applicability states (`DETECTED`, `LIKELY_AFFECTED`, `LIKELY_NOT_AFFECTED`, `REQUIRES_REVIEW`, `UNKNOWN`). The status `VULNERABLE` is prohibited across all layers.
4. **Architectural Decoupling**: Maintain strict separation between layers:

   ```text
   Domain (core/models.py)
      ↓
   Application Services (api/services/)
      ↓
   Infrastructure (db/repositories.py, sources/, scanners/)
      ↓
   API / UI (api/routers/, frontend/src/)
   ```

   Domain models must never import from FastAPI, SQLAlchemy, or React.

---

## 2. Prerequisites

- **Python**: `>= 3.12` (3.12 recommended; matches CI)
- **Node.js**: `>= 18` (CI uses Node 20)
- **npm**: `>= 9` (prefer lockfile installs via `npm ci` when possible)
- **Git**
- Optional: [Ollama](https://ollama.ai/) with a local model (default docs mention `llama3.2`) for contextual AI. Scanning works without AI.

---

## 3. Clone & environment setup

```bash
# Fork on GitHub, then clone your fork
git clone https://github.com/<YOUR_USERNAME>/Local-Vulnerabilty-Ai.git
cd Local-Vulnerabilty-Ai

# Optional: add upstream
git remote add upstream https://github.com/Alejandro03GG/Local-Vulnerabilty-Ai.git
```

### Backend

```bash
cd backend
python3 -m venv .venv
source .venv/bin/activate   # Windows: .venv\Scripts\activate
pip install -e ".[dev]"
cp .env.example .env
alembic upgrade head
```

### Frontend

```bash
cd frontend
npm ci                      # or: npm install
cp .env.example .env
```

### Environment variables

| File | Required? | Notes |
| :--- | :--- | :--- |
| `backend/.env` | Recommended for local API | Copy from `backend/.env.example`. Defaults work for SQLite + local API. |
| `frontend/.env` | Recommended for UI | Copy from `frontend/.env.example`. Sets `VITE_API_BASE_URL`. |

- **Optional**: NVD API key (`VULN_AI_NVD__API_KEY`) improves NVD rate limits; leave unset for local/dev.
- **Optional**: AI / Ollama (`VULN_AI_AI__*`): disable or leave Ollama offline; scans continue without AI.
- Never commit `.env` files or real secrets. See [SECURITY.md](SECURITY.md).

More detail: [docs/development.md](docs/development.md), [docs/troubleshooting.md](docs/troubleshooting.md).

---

## 4. Running locally

### Terminal 1 — Backend (FastAPI)

```bash
cd backend
source .venv/bin/activate
uvicorn vuln_ai.api.main:app --reload --port 8000
```

- API: `http://localhost:8000`
- Swagger: `http://localhost:8000/docs`
- Health: `http://localhost:8000/health`

### Terminal 2 — Frontend (React)

```bash
cd frontend
npm run dev
```

- App: `http://localhost:5173` (Vite may pick `5174+` if busy; CORS origins are listed in `backend/.env.example`)

---

## 5. Quality gates (tests, lint, build)

These match [`.github/workflows/ci.yml`](.github/workflows/ci.yml). Run them before opening a PR.

### Backend (`backend/`, venv active)

```bash
pytest
pytest --cov=vuln_ai --cov-report=term-missing --cov-fail-under=95
ruff check src tests
ruff check --fix src tests          # optional autofix
ruff format --check src tests
ruff format src tests                 # optional format
alembic upgrade head
```

`mypy` is configured in `backend/pyproject.toml` but is **not** a CI gate today. You may run it locally for extra confidence; do not treat failures as a release blocker unless CI adopts it.

### Frontend (`frontend/`)

```bash
npm test
npm run typecheck
npm run lint
npm run lint:fix                   # optional
npm run format:check
npm run format                        # optional
npm run build
```

### Full pre-PR checklist

```bash
# Backend
cd backend
pytest --cov=vuln_ai --cov-report=term-missing --cov-fail-under=95
ruff check src tests
ruff format --check src tests
alembic upgrade head

# Frontend
cd ../frontend
npm run typecheck
npm run lint
npm run format:check
npm test
npm run build
```

---

## 6. Database migrations (Alembic)

When changing models in `backend/src/vuln_ai/db/models.py`:

```bash
cd backend
source .venv/bin/activate
alembic revision --autogenerate -m "describe_schema_change"
# Review backend/alembic/versions/...
alembic upgrade head
pytest tests/unit/test_alembic_migrations.py
```

---

## 7. Git workflow & Pull Requests

### Branch naming

- `feat/<short-name>` — new capability
- `fix/<short-name>` — bug fix
- `docs/<topic>` — documentation
- `test/<topic>` — tests only
- `chore/<topic>` — tooling / DX (no product behavior change)

### Commit messages

Prefer Conventional Commits:

- `feat(matcher): add Maven version comparator strategy`
- `fix(scan): prevent N+1 queries during summary generation`
- `docs(readme): clarify local-first privacy boundary`
- `test(sources): cover OSV sync idempotence`

### What a good PR contains

1. Clear description of **why** the change exists.
2. Focused diff (avoid unrelated refactors).
3. Tests for behavior changes (or a clear reason why not).
4. Docs / CHANGELOG updates when user-facing.
5. Completed [Pull Request template](.github/pull_request_template.md).
6. No secrets, credentials, or local DBs.

Security-sensitive areas (matching, sources, risk, policy, suppressions, AI prompts, network egress) need extra review attention — call them out in the PR **Security impact** section.

---

## 8. Adding tests

| Area | Where to look |
| :--- | :--- |
| Unit tests | `backend/tests/unit/` |
| CLI tests | `backend/tests/cli/` |
| E2E scenarios | `backend/tests/e2e/` |
| Fixtures / sample manifests | `backend/tests/fixtures/` |
| Frontend tests | `frontend/src/test/` |

Guidelines:

- Prefer deterministic fixtures over live network calls.
- For scanners/sources, add small lockfiles/manifests under `backend/tests/fixtures/`.
- Keep coverage ≥ 95% for backend (`--cov-fail-under=95`).
- Frontend: Vitest + Testing Library; run `npm test`.

---

## 9. Parts that need special care

Treat these as high-impact. Prefer small PRs with strong tests:

| Area | Path / docs | Why careful |
| :--- | :--- | :--- |
| Version matching | `backend/src/vuln_ai/matching/`, [docs/version-matching.md](docs/version-matching.md) | Wrong intervals = false positives/negatives |
| Conflict resolution | [docs/conflict-resolution.md](docs/conflict-resolution.md) | Cross-source disagreement handling |
| Risk Engine | `backend/src/vuln_ai/risk/`, [docs/ai_and_risk_architecture.md](docs/ai_and_risk_architecture.md) | Deterministic risk classifications |
| Policy Engine | `backend/src/vuln_ai/policy/`, [docs/policy.md](docs/policy.md) | Gate exit codes and CI integrations |
| Suppressions | [docs/suppressions.md](docs/suppressions.md) | Can silence real findings |
| Vulnerability sources | `backend/src/vuln_ai/sources/`, [docs/sources.md](docs/sources.md) | Catalog integrity / sync |
| Scanners | `backend/src/vuln_ai/scanners/` | Manifest/lockfile correctness |
| Container / image | `backend/src/vuln_ai/container/`, [docs/container-scanning.md](docs/container-scanning.md), [docs/image-security.md](docs/image-security.md) | Static-only; no container execution |
| AI / SystemOne | `backend/src/vuln_ai/ai/`, [docs/ai.md](docs/ai.md) | Metadata-only prompts; never authoritative |
| Exports | `backend/src/vuln_ai/export/`, [docs/export-formats.md](docs/export-formats.md) | SARIF / CycloneDX / SPDX consumers |

---

## Where can I contribute?

Concrete areas that match the **current** codebase (not a roadmap promise):

| Area | Examples | Start here |
| :--- | :--- | :--- |
| Package ecosystems / scanners | Improve Poetry, npm, pnpm, Cargo, uv, requirements discovery | `backend/src/vuln_ai/scanners/`, fixtures under `backend/tests/fixtures/` |
| Vulnerability sources | OSV / NVD / CISA KEV sync robustness, docs clarity | `backend/src/vuln_ai/sources/`, [docs/sources.md](docs/sources.md) |
| Version matching | Edge cases for PEP 440, SemVer, Maven, deb/apk/rpm | `backend/src/vuln_ai/matching/` |
| Vulnerability normalization | Alias merge, catalog upsert, applicability vocabulary | `backend/src/vuln_ai/db/`, core models |
| Container scanning | Static OCI/Docker archive & Dockerfile parsing (no runtime exec) | `backend/src/vuln_ai/container/` |
| Risk Engine | Deterministic risk scoring / classification tests | `backend/src/vuln_ai/risk/` |
| Policy Engine | Rule conditions, docs examples, CLI persistence | `backend/src/vuln_ai/policy/`, [docs/policy.md](docs/policy.md) |
| CLI | `scan`, `image`, `sources`, `policy`, `suppression`, `doctor` | `backend/src/vuln_ai/cli/`, [docs/cli.md](docs/cli.md) |
| REST API | Routers, contracts, OpenAPI alignment | `backend/src/vuln_ai/api/`, [docs/api.md](docs/api.md), [docs/api-contract.md](docs/api-contract.md) |
| Frontend | Console pages, badges, i18n EN/ES, UX polish | `frontend/src/`, [docs/frontend.md](docs/frontend.md) |
| Documentation | Fix gaps, clarify contributor paths, examples | `docs/`, `README.md`, this file |
| Tests | Coverage for edge cases, cleaner fixtures | `backend/tests/`, `frontend/src/test/` |
| Performance | Large lockfile / catalog sync paths (with benchmarks or fixtures) | scanners, repositories, sync services |
| Developer experience | Scripts, clearer errors, CI docs | [docs/development.md](docs/development.md), [docs/ci-cd.md](docs/ci-cd.md) |

Ideas intentionally out of scope for now are listed in [docs/future-work.md](docs/future-work.md) — prefer issues that improve the existing 1.1.x surface.

---

## Documentation map

| Topic | Doc |
| :--- | :--- |
| Architecture overview | [docs/architecture.md](docs/architecture.md) |
| Local development commands | [docs/development.md](docs/development.md) |
| CLI | [docs/cli.md](docs/cli.md) |
| API | [docs/api.md](docs/api.md) |
| Sources / matching / conflicts | [docs/sources.md](docs/sources.md), [docs/version-matching.md](docs/version-matching.md), [docs/conflict-resolution.md](docs/conflict-resolution.md) |
| Policy / suppressions | [docs/policy.md](docs/policy.md), [docs/suppressions.md](docs/suppressions.md) |
| AI & risk | [docs/ai.md](docs/ai.md), [docs/ai_and_risk_architecture.md](docs/ai_and_risk_architecture.md) |
| Security / privacy | [SECURITY.md](SECURITY.md), [docs/security.md](docs/security.md), [docs/privacy.md](docs/privacy.md) |
| Release process (maintainers) | [docs/release-checklist.md](docs/release-checklist.md) |

---

## Security reports

Do **not** open public issues for security vulnerabilities. Follow [SECURITY.md](SECURITY.md) (GitHub Private Vulnerability Reporting).

---

## Release process (maintainers)

Before tagging a release, complete [docs/release-checklist.md](docs/release-checklist.md). Contributors normally do **not** bump versions or create tags in feature PRs unless maintainers request it.
