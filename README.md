# Local Vulnerability AI

> An open-source, local-first vulnerability analysis platform combining deterministic vulnerability matching with local AI analysis.

**Status: Phase 1, 2, and 3 Completed — Repository Prepared for Phase 4 (Frontend React + TypeScript)**

---

## What This Project Does

Local Vulnerability AI scans your software projects, identifies dependencies and components, and checks them against known vulnerability databases — starting with CISA KEV (Known Exploited Vulnerabilities).

The core philosophy:

> **Detect first using deterministic data and rules → analyze context with local LLM → evaluate probabilistic decisions with SystemOne → assess final audit-ready risk with deterministic rules.**

AI does NOT invent vulnerabilities or decide final risk arbitrarily. It provides transparent contextual analysis and probabilistic signals to a deterministic Risk Engine.

---

## Repository Architecture

```text
local-vulnerability-ai/
│
├── backend/                  # Python + FastAPI REST API + Core & AI Engine
│   ├── src/vuln_ai/          # Source code (core, ai, risk, db, api)
│   ├── tests/                # Test suite (unit, integration, api)
│   ├── alembic/              # Database schema migrations
│   ├── alembic.ini           # Alembic configuration
│   ├── pyproject.toml        # Backend dependencies and tool configurations
│   ├── .env.example          # Environment variables template
│   └── README.md             # Backend development guide
│
├── frontend/                 # React + TypeScript Web Console (Phase 4)
│   └── README.md             # Frontend roadmap and planned stack
│
├── docs/                     # Cross-project documentation
│   ├── architecture.md       # Overall system architecture
│   ├── api.md                # REST API specifications and contracts
│   ├── ai_and_risk_architecture.md # AI layer & Risk Engine architecture
│   └── frontend.md           # Frontend design system and UI specification
│
├── .gitignore                # Repository-wide gitignore
├── README.md                 # Main project documentation
└── LICENSE                   # MIT License
```

---

## Backend (Python + FastAPI)

All backend development, execution, and testing is performed inside the `backend/` directory.

### Quick Start

```bash
cd backend

# Create virtual environment and install dependencies
python3 -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"

# Run database migrations
alembic upgrade head

# Start FastAPI development server
uvicorn vuln_ai.api.main:app --reload
```

Interactive API documentation:
* Swagger UI: [http://127.0.0.1:8000/docs](http://127.0.0.1:8000/docs)
* ReDoc: [http://127.0.0.1:8000/redoc](http://127.0.0.1:8000/redoc)
* Health probe: [http://127.0.0.1:8000/health](http://127.0.0.1:8000/health)

### Running Backend Tests & Quality Checks

```bash
cd backend

# Run full test suite
pytest

# Run tests with coverage
pytest --cov=src/vuln_ai --cov-report=term-missing

# Lint & formatting checks with Ruff
ruff check .
ruff format --check .
```

For more details, see [backend/README.md](file:///Users/alejandro03hl/Desktop/Local%20Vulnerability%20AI/backend/README.md).

---

## Frontend (React + TypeScript)

The frontend will be developed during **Phase 4** in the `frontend/` directory.

Planned stack:
- React 18+ / 19
- TypeScript
- Vite
- Tailwind CSS
- shadcn/ui

For more details, see [frontend/README.md](file:///Users/alejandro03hl/Desktop/Local%20Vulnerability%20AI/frontend/README.md) and [docs/frontend.md](file:///Users/alejandro03hl/Desktop/Local%20Vulnerability%20AI/docs/frontend.md).

---

## Privacy & Security

- **Local-first**: All scanning and analysis runs locally on your machine.
- **No data leakage**: No project source code or proprietary dependency manifests are transmitted externally.
- **Local AI**: Enriched contextual evaluations use local models via Ollama (`llama3.2`, `systemone`).
- **Deterministic**: Threat data is sourced from CISA KEV and stored in an encrypted/local SQLite database with WAL.

---

## Roadmap

| Phase | Status | Description |
|---|---|---|
| Phase 1 | ✅ Completed | Core foundation: scanner, KEV source, matcher, repositories, SQLite WAL |
| Phase 2 | ✅ Completed | AI integration: Ollama chat, SystemOne decision models, Deterministic Risk Engine |
| Phase 3 | ✅ Completed | FastAPI REST API with endpoints for projects, scans, components, vulnerabilities, matches |
| Phase 4 | 🚀 Next | Frontend: React + TypeScript + Vite + Tailwind CSS + shadcn/ui Security Console |
| Phase 5 | 📋 Planned | CLI interface (Rich / Typer) |
| Phase 6 | 📋 Planned | Additional sources (NVD, OSV), scanners (Node, Docker, SBOM) |

---

## License

MIT — see [LICENSE](file:///Users/alejandro03hl/Desktop/Local%20Vulnerability%20AI/LICENSE).
# Local-Vulnerabilty-Ai
