# Development & Quality Verification Guide

This document compiles the exact, copy-pasteable commands for development, testing, linting, formatting, and migrations across both the backend and frontend.

---

## 1. Environment Setup

### 1.1 Backend Setup
```bash
cd backend
python3 -m venv .venv
source .venv/bin/activate       # On Windows: .venv\Scripts\activate
pip install -e ".[dev]"
cp .env.example .env
alembic upgrade head
```

### 1.2 Frontend Setup
```bash
cd frontend
npm install
cp .env.example .env
```

---

## 2. Running Local Services

### Start Backend Server
```bash
cd backend
source .venv/bin/activate
uvicorn vuln_ai.api.main:app --reload --port 8000
```
- Liveness check: `curl http://localhost:8000/health`
- Readiness check: `curl http://localhost:8000/health/ready`
- Swagger UI: `http://localhost:8000/docs`

### Start Frontend Server
```bash
cd frontend
npm run dev
```
- Web Application: `http://localhost:5173`

---

## 3. Backend Quality Commands

Execute from the `backend/` directory with `.venv` active:

### Run Test Suite
```bash
pytest
```

### Run Tests with Coverage (Enforces $\ge 95\%$ Threshold)
```bash
pytest --cov=vuln_ai --cov-report=term-missing --cov-fail-under=95
```

### Run E2E Integration Suite Only
```bash
pytest tests/e2e/test_end_to_end_scenarios.py -v
```

### Code Formatting & Linting (Ruff)
```bash
# Check for lint violations
ruff check src tests

# Auto-fix lint violations
ruff check --fix src tests

# Verify formatting without altering files
ruff format --check src tests

# Format files
ruff format src tests
```

### Database Migrations (Alembic)
```bash
# Apply pending migrations
alembic upgrade head

# Generate a new migration
alembic revision --autogenerate -m "migration_description"

# Verify migration roundtrip test
pytest tests/unit/test_alembic_migrations.py
```

### CLI Execution & Testing
```bash
# Display CLI help
vuln-ai --help

# Run diagnostic health check
vuln-ai doctor

# Scan current project with terminal table output
vuln-ai scan .

# Scan in CI mode (no AI, JSON output, fail on high/critical)
vuln-ai scan . --no-ai --format json --fail-on high

# Export to SARIF, CycloneDX, and SPDX
vuln-ai scan . --no-ai --format sarif --output results.sarif
vuln-ai scan . --no-ai --format cyclonedx --output sbom.cdx.json
vuln-ai scan . --no-ai --format spdx --output sbom.spdx.json

# Run CLI test suite
pytest tests/cli -v
```

---

## 4. Frontend Quality Commands

Execute from the `frontend/` directory:

### Run Unit & Integration Tests (Vitest)
```bash
npm test
```

### Type Checking (TypeScript)
```bash
npm run typecheck
```

### Linting (ESLint)
```bash
npm run lint

# Auto-fix
npm run lint:fix
```

### Formatting (Prettier)
```bash
# Verify formatting
npm run format:check

# Format files
npm run format
```

### Production Build
```bash
npm run build
```

---

## 5. Consolidated Full-Project Quality Gate

To verify the entire repository in a single pipeline run:

```bash
# Backend checks
cd backend
pytest --cov=vuln_ai --cov-report=term-missing --cov-fail-under=95
ruff check src tests
ruff format --check src tests
alembic upgrade head

# Frontend checks
cd ../frontend
npm run typecheck
npm run lint
npm run format:check
npm test
npm run build
```

---

## CI parity

GitHub Actions workflow [`.github/workflows/ci.yml`](../.github/workflows/ci.yml) runs on pushes to `main` / `release/**` and on pull requests to `main`.

| Job | Checks |
| :--- | :--- |
| Backend Quality Gates | `alembic` upgrade/check/roundtrip, `ruff check` + `ruff format --check`, CLI smoke (`vuln-ai --version`, `--help`, `doctor`), `pytest` with ≥95% coverage |
| Frontend Quality Gates | `npm ci`, `typecheck`, `eslint`, Prettier check, Vitest, production `build` |

`mypy` is configured in `backend/pyproject.toml` but is **not** currently enforced in CI. Prefer the commands above for PR readiness.

Contributor workflow details: [CONTRIBUTING.md](../CONTRIBUTING.md).

