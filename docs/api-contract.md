# Backend ↔ Frontend API Contract

This document specifies the strict type and schema contract between the **FastAPI REST API** and the **React + TypeScript Web Console**.

---

## 1. Canonical Security States (`Applicability`)

The platform classifies applicability using five canonical verdicts. The status `VULNERABLE` is intentionally and strictly prohibited.

| Backend Enum (`Applicability`) | Serialized JSON Value | Frontend Type (`ApplicabilityType`) | UI Badge Text | Semantic Meaning |
| :--- | :--- | :--- | :--- | :--- |
| `Applicability.DETECTED` | `"detected"` | `'DETECTED' \| 'detected'` | `DETECTED` | Matched in catalog without conclusive version range bounds. |
| `Applicability.LIKELY_AFFECTED` | `"likely_affected"` | `'LIKELY_AFFECTED' \| 'likely_affected'` | `LIKELY_AFFECTED` | Corroborated within affected version range. |
| `Applicability.LIKELY_NOT_AFFECTED` | `"likely_not_affected"` | `'LIKELY_NOT_AFFECTED' \| 'likely_not_affected'` | `LIKELY_NOT_AFFECTED` | Proved outside declared affected version intervals. |
| `Applicability.REQUIRES_REVIEW` | `"requires_review"` | `'REQUIRES_REVIEW' \| 'requires_review'` | `REQUIRES_REVIEW` | Discrepancy between sources; human triage required. |
| `Applicability.UNKNOWN` | `"unknown"` | `'UNKNOWN' \| 'unknown'` | `UNKNOWN` | Insufficient evidence or unsupported packaging ecosystem. |

> **Implementation Note on Casing**:
> The backend defines domain string values in lowercase (`"likely_affected"`). The frontend accepts both lowercase API values and uppercase canonical constants, automatically normalizing via `.toUpperCase()` in presentation components.

---

## 2. Risk Posture (`RiskLevel` & `RiskStatus`)

| Backend Enum (`RiskLevel`) | Serialized Value | Frontend Type (`RiskLevel`) | UI Representation |
| :--- | :--- | :--- | :--- |
| `RiskLevel.CRITICAL` | `"critical"` / `"CRITICAL"` | `'CRITICAL' \| 'critical'` | Red / Flame Badge |
| `RiskLevel.HIGH` | `"high"` / `"HIGH"` | `'HIGH' \| 'high'` | Orange / Octagon Badge |
| `RiskLevel.MEDIUM` | `"medium"` / `"MEDIUM"` | `'MEDIUM' \| 'medium'` | Amber / Triangle Badge |
| `RiskLevel.LOW` | `"low"` / `"LOW"` | `'LOW' \| 'low'` | Blue / Info Badge |

---

## 3. Operational Lifecycles

### Scan Status (`ScanStatus`)
- Backend: `pending`, `running`, `completed`, `failed`.
- Frontend: `ScanStatus = 'pending' | 'running' | 'completed' | 'failed'`.
- Polling behavior: Frontend polls only during `pending` and `running` states (every 2.5s) and terminates immediately on `completed` or `failed`.

### Source Synchronization Status (`SourceStatus`)
- Backend: `active`, `syncing`, `error`, `disabled`, `never_synced`.
- Frontend: Identical mapping in `SourceStatusBadge`.

---

## 4. Standardized Pagination Envelope

All paginated collection endpoints return a uniform envelope:

```json
{
  "items": [ /* Array of resource objects */ ],
  "page": 1,
  "page_size": 20,
  "total": 42
}
```

- `page`: 1-based index (integer $\ge 1$).
- `page_size`: items per page (integer $\ge 1, \le 100$).
- `total`: total count of matching records across all pages.

---

## 5. Standardized Error Contract

All error responses from the API return structured JSON:

```json
{
  "error": {
    "code": "PROJECT_NOT_FOUND",
    "message": "Project with ID '0c54bb56-...' was not found",
    "request_id": "req-98f2a1b3-1727878800",
    "details": {}
  }
}
```

### Traceability & Request ID (`X-Request-ID`)
- The frontend `apiClient` generates a unique UUID `X-Request-ID` header on each HTTP call.
- The FastAPI middleware captures and propagates this header in response headers and inside the error body.
- When an operation fails in the UI, the error boundary renders the `request_id` for troubleshooting.

---

## 6. Dependency Graph & Component Schemas (Etapa 14)

### Component Representation (`ComponentResponse`)

Components detected via manifests and lockfiles include graph provenance attributes:

```json
{
  "id": "3fa85f64-5717-4562-b3fc-2c963f66afa6",
  "project_id": "0c54bb56-9a21-4f32-bb44-8d9e2a7b1c34",
  "name": "anyio",
  "version": "4.4.0",
  "version_type": "exact",
  "version_constraint": ">=4.0.0",
  "source_file": "/app/poetry.lock",
  "ecosystem": "pypi",
  "component_type": "library",
  "is_direct": false,
  "dependency_type": "transitive",
  "scope": "runtime",
  "manifest_source": "/app/pyproject.toml",
  "lockfile_source": "/app/poetry.lock",
  "parent_name": "starlette",
  "dependency_path": ["fastapi", "starlette", "anyio"],
  "detected_at": "2026-10-02T18:00:00Z"
}
```

### Endpoints

- `GET /api/v1/scans/{scan_id}/dependencies`: Returns array of `ComponentResponse` objects for a scan.
- `GET /api/v1/scans/{scan_id}/dependencies/graph`: Returns `DependencyGraphResponse` containing:
  - `project_id`: string
  - `direct_count`: integer
  - `transitive_count`: integer
  - `edges_count`: integer
  - `lockfiles_detected`: list of string
  - `manifests_detected`: list of string
  - `components`: list of `ComponentResponse`
  - `edges`: list of `DependencyEdgeResponse` (`parent_name`, `parent_version`, `child_name`, `child_version`, `scope`, `requirement`)

---

## 7. Security & Software Composition Export Endpoints (Etapa 15)

Endpoints allow downloading or streaming scan findings and software composition documents in industry-standard formats:

### Endpoints

| Endpoint | Method | Response Content-Type | Standard Conformance |
|---|---|---|---|
| `/api/v1/scans/{scan_id}/export/sarif` | `GET` | `application/sarif+json` | OASIS SARIF 2.1.0 |
| `/api/v1/scans/{scan_id}/export/cyclonedx` | `GET` | `application/vnd.cyclonedx+json` | CycloneDX 1.5 JSON |
| `/api/v1/scans/{scan_id}/export/spdx` | `GET` | `application/spdx+json` | SPDX 2.3 JSON |

### Error Contracts
- `404 Not Found`: Returns standard error envelope (`SCAN_NOT_FOUND`) if `scan_id` does not exist.
- `500 Internal Server Error`: Returns standard error envelope (`EXPORT_SERIALIZATION_ERROR`) if an unrecoverable serialization failure occurs.

---

## 8. Policy & Suppression Endpoints (Etapa 16)

REST API for declarative security policies, rule evaluations, and auditable suppressions:

### Endpoints

| Endpoint | Method | Description |
|---|---|---|
| `/api/v1/policies` | `GET` | List all registered security policies |
| `/api/v1/policies` | `POST` | Create a new declarative security policy |
| `/api/v1/policies/{policy_id}` | `GET` | Retrieve policy details, rules, and thresholds |
| `/api/v1/policies/{policy_id}` | `PUT` | Update policy rules, description, or thresholds |
| `/api/v1/policies/{policy_id}` | `DELETE` | Delete a security policy |
| `/api/v1/policies/validate` | `POST` | Validate YAML text or JSON schema without persisting |
| `/api/v1/suppressions` | `GET` | List all suppressions with optional `?project_id=` filter |
| `/api/v1/suppressions` | `POST` | Create a documented suppression exception |
| `/api/v1/suppressions/{suppression_id}` | `GET` | Retrieve suppression details and lifecycle status |
| `/api/v1/suppressions/{suppression_id}` | `PUT` | Update suppression justification, owner, or expiration |
| `/api/v1/suppressions/{suppression_id}` | `DELETE` | Remove a suppression |
| `/api/v1/scans/{scan_id}/policy/evaluate` | `POST` | Evaluate scan findings against stored or custom YAML policy |
| `/api/v1/scans/{scan_id}/policy` | `GET` | Retrieve stored policy compliance snapshot for a scan |

### Error Contracts
- `404 Not Found`: Returns `POLICY_NOT_FOUND` or `SUPPRESSION_NOT_FOUND` when target resource does not exist.
- `409 Conflict`: Returned on duplicate policy name registration.
- `422 Unprocessable Entity`: Returned when YAML policy syntax or condition schema fails validation.

---

## 9. Container & Image Scanning Endpoints (Etapa 17)

REST API for static container image archive inspection, layer extraction, OS & application package discovery, and Dockerfile AST analysis.

### Endpoints

| Endpoint | Method | Request Payload | Response Schema | Description |
|---|---|---|---|---|
| `/api/v1/images` | `GET` | Query params: `page`, `page_size` | `PaginatedResponse<ContainerImage>` | List scanned container images |
| `/api/v1/images/scan` | `POST` | `ContainerScanRequestPayload` | `ContainerImage` | Scan Docker/OCI archive (`.tar`) statically |
| `/api/v1/images/{image_id}` | `GET` | Path param: `image_id` | `ContainerImage` | Get container image metadata and summary |
| `/api/v1/images/{image_id}/layers` | `GET` | Path param: `image_id` | `ContainerLayer[]` | Get immutable filesystem layer list |
| `/api/v1/images/{image_id}/components` | `GET` | Path param: `image_id` | `ContainerComponent[]` | Get detected OS and application packages |
| `/api/v1/images/{image_id}/vulnerabilities`| `GET` | Path param: `image_id` | `Match[]` | Get matched vulnerabilities & risks |
| `/api/v1/images/{image_id}/policy` | `GET` | Path param: `image_id` | `PolicyEvaluationResponse` | Get policy evaluation compliance snapshot |
| `/api/v1/images/{image_id}/dependency-graph`| `GET` | Path param: `image_id` | Graph JSON (`nodes`, `edges`) | Get container dependency tree topology |
| `/api/v1/container/dockerfile/scan` | `POST` | `DockerfileScanPayload` | `DockerfileScanResult` | Perform static AST parsing on Dockerfile |

### Error Contracts
- `404 Not Found`: Returns `IMAGE_NOT_FOUND` when image ID does not exist.
- `400 Bad Request`: Returns `CONTAINER_SCAN_ERROR` if archive is invalid, malformed, or exceeds safety thresholds.
- `422 Unprocessable Entity`: Returns schema validation error if payload fails type checks.



