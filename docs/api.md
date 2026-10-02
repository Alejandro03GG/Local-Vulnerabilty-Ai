# REST API Documentation — Local Vulnerability AI (Phase 3)

The REST API layer of **Local Vulnerability AI** exposes the local-first vulnerability scanning pipeline, catalog management, LLM contextual narratives, and deterministic risk evaluations through asynchronous HTTP endpoints built with **FastAPI**.

---

## 1. Architecture

The API strictly serves as an interface layer. Business logic, parsing, catalog matching, and risk rules reside entirely in the application services and Core engine.

```text
React / CLI / External Client
             │
             ▼
        FastAPI API (Routers & Dependencies)
             │
             ▼
     Application Services (api/services/)
             │
             ▼
        Core Engine (core/engine.py)
             │
      ┌──────┼──────────────┐
      ▼      ▼              ▼
   Scanner Matcher    AI / Risk Engine
      │      │              │
      └──────┼──────────────┘
             ▼
       Repositories (db/repositories.py)
             │
             ▼
      SQLite (Async SQLAlchemy with WAL)
```

---

## 2. API Versioning & Probes

* **Versioned Base URL**: `/api/v1`
* **Health Probes (Unversioned)**:
  * `GET /health`: Liveness probe.
  * `GET /health/ready`: Readiness probe verifying database connectivity.
* **Interactive Documentation**:
  * Swagger UI: `http://127.0.0.1:8000/docs`
  * ReDoc: `http://127.0.0.1:8000/redoc`
  * OpenAPI JSON: `http://127.0.0.1:8000/openapi.json`

---

## 3. Endpoints Overview

| Method | Path | Tag | Description |
|---|---|---|---|
| `GET` | `/health` | Health | Liveness check |
| `GET` | `/health/ready` | Health | Readiness check (database connectivity) |
| `GET` | `/api/v1/projects` | Projects | List registered projects (paginated) |
| `POST` | `/api/v1/projects` | Projects | Register a new project |
| `GET` | `/api/v1/projects/{project_id}` | Projects | Get project details |
| `PATCH` | `/api/v1/projects/{project_id}` | Projects | Update project metadata or path |
| `DELETE` | `/api/v1/projects/{project_id}` | Projects | Delete project and associated scans |
| `POST` | `/api/v1/projects/{project_id}/scans` | Scans | Trigger vulnerability scan on project |
| `GET` | `/api/v1/scans` | Scans | List scans (supports `?project_id=...`) |
| `GET` | `/api/v1/scans/{scan_id}` | Scans | Get scan details, metrics, and matches |
| `GET` | `/api/v1/projects/{project_id}/components` | Components | List detected components for project |
| `GET` | `/api/v1/components/{component_id}` | Components | Get component details |
| `GET` | `/api/v1/vulnerabilities` | Vulnerabilities | Query vulnerabilities (cve, source, vendor, product) |
| `GET` | `/api/v1/vulnerabilities/{vulnerability_id}` | Vulnerabilities | Get vulnerability catalog details |
| `GET` | `/api/v1/sources` | Sources | List vulnerability sources and sync statuses |
| `GET` | `/api/v1/sources/{source_id}/status` | Sources | Get source sync status |
| `POST` | `/api/v1/sources/{source_id}/sync` | Sources | Trigger sync of vulnerability catalog |
| `GET` | `/api/v1/matches/{match_id}` | Matches | Get full match details |
| `GET` | `/api/v1/matches/{match_id}/analysis` | AI | Get LLM contextual narrative |
| `GET` | `/api/v1/matches/{match_id}/decision` | AI | Get SystemOne probabilistic decision |
| `POST` | `/api/v1/matches/{match_id}/reanalyze` | AI | Re-evaluate match with AI & Risk Engine |
| `GET` | `/api/v1/matches/{match_id}/risk` | AI | Get deterministic risk assessment |

---

## 4. Request & Response Examples

### Register a Project

**Request**:
```http
POST /api/v1/projects HTTP/1.1
Content-Type: application/json

{
  "name": "my-web-app",
  "path": "/Users/developer/projects/my-web-app",
  "description": "Production e-commerce service"
}
```

**Response (201 Created)**:
```json
{
  "id": "e98e4d2a-c2bb-41a3-b4e6-d9229ef5e2df",
  "name": "my-web-app",
  "path": "/Users/developer/projects/my-web-app",
  "description": "Production e-commerce service",
  "created_at": "2026-10-01T20:00:00Z",
  "updated_at": "2026-10-01T20:00:00Z"
}
```

---

### Trigger a Scan

**Request**:
```http
POST /api/v1/projects/e98e4d2a-c2bb-41a3-b4e6-d9229ef5e2df/scans HTTP/1.1
Content-Type: application/json

{
  "run_ai": true
}
```

**Response (201 Created)**:
```json
{
  "id": "9b1deb4d-3b7d-4bad-9bdd-2b0d7b3dcb6d",
  "project_id": "e98e4d2a-c2bb-41a3-b4e6-d9229ef5e2df",
  "status": "completed",
  "components_found": 15,
  "vulnerabilities_found": 1150,
  "kev_matches": 1,
  "duration_seconds": 0.42,
  "started_at": "2026-10-01T20:05:00Z",
  "completed_at": "2026-10-01T20:05:00Z",
  "error": null,
  "summary": {
    "components": 15,
    "matches": 1,
    "kev_matches": 1,
    "requires_review": 1
  }
}
```

---

### Query Match Details

**Request**:
```http
GET /api/v1/matches/a581457f-2bbf-41a3-9b93-9d113df5e11a HTTP/1.1
```

**Response (200 OK)**:
```json
{
  "id": "a581457f-2bbf-41a3-9b93-9d113df5e11a",
  "scan_id": "9b1deb4d-3b7d-4bad-9bdd-2b0d7b3dcb6d",
  "component_id": "7ca643e2-8b4e-4f76-bc34-a6989432d431",
  "vulnerability_id": "3dc2bf02-98aa-46d7-ba17-74eb731f2a34",
  "match_type": "exact_name",
  "match_confidence": 1.0,
  "applicability": "detected",
  "evidence": [
    "Package name 'django' matches CISA KEV product 'django' exactly"
  ],
  "matched_at": "2026-10-01T20:05:00Z",
  "component": {
    "id": "7ca643e2-8b4e-4f76-bc34-a6989432d431",
    "project_id": "e98e4d2a-c2bb-41a3-b4e6-d9229ef5e2df",
    "name": "django",
    "version": "4.2.11",
    "version_type": "exact",
    "version_constraint": "==4.2.11",
    "source_file": "requirements.txt",
    "ecosystem": "pypi",
    "component_type": "framework",
    "detected_at": "2026-10-01T20:05:00Z"
  },
  "vulnerability": {
    "id": "3dc2bf02-98aa-46d7-ba17-74eb731f2a34",
    "cve_id": "CVE-2024-1000",
    "source_id": "d09a5cb4-6cf3-40f4-90aa-9a572ec56102",
    "vendor_project": "Django",
    "product": "Django",
    "vulnerability_name": "Django SQL Injection",
    "short_description": "SQL injection in admin interface",
    "required_action": "Apply vendor update",
    "date_added": "2024-01-15",
    "due_date": "2024-02-05",
    "known_ransomware_use": "Unknown",
    "cwes": ["CWE-89"],
    "notes": "",
    "synced_at": "2026-10-01T19:00:00Z"
  },
  "ai_analysis": {
    "provider": "ollama",
    "model": "llama3.2",
    "explanation": "Django 4.2.11 matches the product name in CISA KEV entry.",
    "evidence": ["Exact product name match", "Version declared in requirements.txt"],
    "contextual_findings": ["Web framework dependency", "Public exploitation noted in KEV"],
    "requires_human_review": true,
    "duration_seconds": 1.15,
    "tokens_used": 128,
    "analyzed_at": "2026-10-01T20:05:01Z"
  },
  "decision_result": {
    "provider": "ollama_systemone",
    "model": "tev1:4b",
    "responses": {
      "applicability": "yes",
      "exposure": "direct",
      "urgency": 0.85
    },
    "decision_probabilities": {
      "applicability": {"yes": 0.88, "no": 0.12},
      "exposure": {"direct": 0.80, "indirect": 0.15, "unknown": 0.05}
    },
    "applicability_probability": 0.88,
    "urgency_score": 0.85,
    "latency_seconds": 0.32,
    "timestamp": "2026-10-01T20:05:02Z"
  },
  "risk_assessment": {
    "status": "requires_review",
    "risk_level": "high",
    "certainty": 0.70,
    "rationale": "Component matches CISA KEV product. High applicability signals present; manual version verification required.",
    "recommended_action": "Verify if Django 4.2.11 is affected by CVE-2024-1000 and update if required.",
    "requires_human_review": true,
    "rule_ids": [
      "MATCH_COMPONENT_ONLY",
      "VERSION_DECLARED",
      "AI_APPLICABILITY_HIGH",
      "EXPOSURE_DIRECT",
      "URGENCY_HIGH"
    ],
    "assessed_at": "2026-10-01T20:05:02Z"
  }
}
```

---

## 5. Consistent Error Handling

All client and server errors return a standard JSON envelope with machine-readable codes:

```json
{
  "error": {
    "code": "PROJECT_NOT_FOUND",
    "message": "Project with ID 'e98e4d2a' not found",
    "details": {}
  }
}
```

### Standard HTTP Status Codes

| Status Code | Meaning | Example Error Code |
|---|---|---|
| `400 Bad Request` | Client request syntax invalid or execution failed | `BAD_REQUEST`, `SCAN_EXECUTION_FAILED` |
| `404 Not Found` | Target resource does not exist | `PROJECT_NOT_FOUND`, `MATCH_NOT_FOUND` |
| `409 Conflict` | Unique constraint violated | `PROJECT_ALREADY_EXISTS` |
| `422 Unprocessable Content` | Validation failure on body or query parameter | `VALIDATION_ERROR` |
| `500 Internal Server Error` | Unexpected server fault (stack trace redacted) | `INTERNAL_SERVER_ERROR` |
| `503 Service Unavailable` | Database or required external resource unreachable | `SERVICE_UNAVAILABLE` |

---

## 6. Running Locally

### Development Server

Start the API with hot reloading:

```bash
uvicorn vuln_ai.api.main:app --reload --host 127.0.0.1 --port 8000
```

### Environment Variables

Configure API settings via environment variables:

| Variable | Default | Description |
|---|---|---|
| `VULN_AI_API__HOST` | `127.0.0.1` | API server listen host |
| `VULN_AI_API__PORT` | `8000` | API server listen port |
| `VULN_AI_API__CORS_ORIGINS` | `["http://localhost:3000", ...]` | JSON list of allowed CORS origins |
| `VULN_AI_AI__ENABLED` | `true` | Toggle AI analysis pipeline globally |
| `VULN_AI_DATABASE__URL` | `sqlite+aiosqlite:///./vuln_ai.db` | SQLAlchemy database URL |

---

## 7. Running Tests

Execute the API and Core test suite:

```bash
# Run all tests
pytest

# Run tests with code coverage
pytest --cov=src/vuln_ai --cov-report=term-missing

# Lint & Format checks
ruff check .
ruff format --check .
```
