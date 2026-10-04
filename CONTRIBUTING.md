# Contributing to Local Vulnerability AI

Thank you for your interest in contributing to **Local Vulnerability AI**! This project is an open-source, local-first platform designed to provide transparent, deterministic, and auditable vulnerability analysis.

---

## 1. Code of Conduct & Development Principles

To maintain high technical standards, all contributions must adhere to our core architectural principles:

1. **Deterministic Authority**: The Version-Aware Matcher, Conflict Resolver, and Risk Engine must remain 100% deterministic and rule-based. AI models (Ollama, SystemOne) serve strictly as supplementary decision support; they must never be given final authority over vulnerability verdicts.
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

## 2. Development Setup

### Prerequisites

- **Python**: `>= 3.12` (Python 3.12, 3.13, or 3.14)
- **Node.js**: `>= 18.0.0` (LTS recommended)
- **npm**: `>= 9.0.0`
- **Git**
- Optional: [Ollama](https://ollama.ai/) with `llama3.2` model installed locally for contextual AI analysis.

### Repository Setup

```bash
# Clone the repository
git clone https://github.com/Alejandro03GG/Local-Vulnerabilty-Ai.git
cd Local-Vulnerabilty-Ai

# 1. Backend environment setup
cd backend
python3 -m venv .venv
source .venv/bin/activate   # On Windows: .venv\Scripts\activate
pip install -e ".[dev]"
cp .env.example .env

# Run database migrations
alembic upgrade head

# 2. Frontend environment setup
cd ../frontend
npm install
cp .env.example .env
cd ..
```

---

## 3. Running Locally in Development

Run backend and frontend in separate terminals:

### Terminal 1 — Backend (FastAPI Gateway)
```bash
cd backend
source .venv/bin/activate
uvicorn vuln_ai.api.main:app --reload --port 8000
```
- API Base URL: `http://localhost:8000`
- Interactive Swagger UI: `http://localhost:8000/docs`
- Health check: `http://localhost:8000/health`

### Terminal 2 — Frontend (React Web Console)
```bash
cd frontend
npm run dev
```
- Web Application: `http://localhost:5173`

---

## 4. Quality Verification Commands

We enforce automated quality gates on both the backend and frontend.

### Backend Commands (run from `backend/` with `.venv` activated)

```bash
# Run all tests
pytest

# Run tests with code coverage (enforces >= 95% threshold)
pytest --cov=src --cov-report=term-missing --cov-fail-under=95

# Lint check with Ruff
ruff check src tests

# Auto-fix linting issues where possible
ruff check --fix src tests

# Check code formatting
ruff format --check src tests

# Format code with Ruff
ruff format src tests

# Verify database migrations
alembic upgrade head
```

### Frontend Commands (run from `frontend/`)

```bash
# Run unit and integration tests (Vitest + Testing Library)
npm test

# Run TypeScript static type checking
npm run typecheck

# Lint check with ESLint
npm run lint

# Auto-fix linting issues where possible
npm run lint:fix

# Check formatting with Prettier
npm run format:check

# Format code with Prettier
npm run format

# Compile production bundle
npm run build
```

---

## 5. Database Migrations (Alembic)

Whenever you modify models in `backend/src/vuln_ai/db/models.py`:

```bash
cd backend
source .venv/bin/activate

# Generate a new migration script
alembic revision --autogenerate -m "describe_schema_change"

# Review the generated file in backend/alembic/versions/
# Apply the migration locally
alembic upgrade head

# Verify that migrations roundtrip cleanly
pytest tests/unit/test_alembic_migrations.py
```

---

## 6. Git Workflow & Pull Requests

```text
Fork / branch
     ↓
  Install
     ↓
 Run tests
     ↓
 Run lint
     ↓
Make changes
     ↓
Run tests again
     ↓
Open Pull Request
```

### Branch Naming Convention
- `feat/feature-name` for new capabilities or tools.
- `fix/bug-description` for bug fixes.
- `docs/documentation-topic` for documentation updates.
- `refactor/component-name` for internal improvements without feature changes.

### Commit Message Guidelines
Follow conventional commit style:
- `feat(matcher): add Maven version comparator strategy`
- `fix(scan): prevent N+1 queries during summary generation`
- `docs(readme): clarify local-first privacy boundary`
- `test(e2e): add multi-source conflict agreement scenario`

### Before Opening a Pull Request

Verify the full checklist before pushing:

```bash
# 1. Backend Verification
cd backend
pytest --cov=src --cov-report=term-missing --cov-fail-under=95
ruff check src tests
ruff format --check src tests
alembic upgrade head

# 2. Frontend Verification
cd ../frontend
npm run typecheck
npm run lint
npm run format:check
npm test
npm run build
```

All quality gates must pass cleanly (`0` errors, `0` failed tests, `>= 95%` backend coverage).

## Release Process

Before tagging a release, complete [docs/release-checklist.md](docs/release-checklist.md).
