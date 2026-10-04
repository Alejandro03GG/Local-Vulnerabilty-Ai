# Stage 19.1 — Product Hardening

## 1. Objetivo

Corregir en el **repositorio principal** los problemas reales descubiertos en Stage 19 (`INFORME-GENERAL`), integrar branding + i18n EN/ES desarrollados en el clon de laboratorio, y demostrar las correcciones con regresiones focalizadas — sin reescritura arquitectónica ni release automático.

## 2. Estado inicial

Tras Stage 19 / v1.0.1 el producto principal:

- Fallaba al serializar findings sin CVE (HTTP 500 → “Scan Not Found” / “Failed to Load Matches”).
- Podía destruir batches de catálogo en upserts parciales y generar duplicados/aliases inconsistentes.
- `fail_on` HIGH castigaba findings `likely_not_affected`.
- No parseaba pnpm multi-documento ni `uv.lock`.
- No descubría manifests en monorepos de forma segura.
- Components UI llamaba un path API inexistente / incompleto.
- Dockerfile AST era analizable por CLI/API pero no persistía hacia Images UI.
- El branding EN/ES del lab no estaba en main.

## 3. Problemas encontrados

Fuente: hallazgos H1–H21 del informe Stage 19 (H20 = característica Juice Shop, no bug de producto).

## 4. Correcciones realizadas

### H17
`cve_id` nullable en schemas/serializers API; frontend usa identificador canónico (CVE → GHSA → RUSTSEC → OSV). Tests API GHSA-only / mixed.

### H1/H16
`upsert_vulnerabilities(..., prune_missing=False)` por defecto; seeds incrementales por ecosistema; aliases no duplican filas canónicas. Tests A–F + idempotencia.

### H2
KEV usa `prune_missing=True` solo en su source scope vía `source_service` / engine; batches vacíos no limpian catálogo.

### H13
Policy thresholds: severity advisory no dispara violation si applicability es `likely_not_affected`. Matriz HIGH × applicability cubierta.

### H21
`yaml.safe_load_all` en pnpm scanner; fixtures multi-documento + tests.

### H18
`UvLockScanner` registrado en CLI/API/container; fixtures y unit tests.

### H7
`discover_project_roots` + merge en `ScannerRegistry.scan_graph` con exclusiones, max depth, sin seguir symlinks. Tests monorepo / excludes / symlinks.

### H3
`GET /api/v1/components` (+ filtro `project_id`); FE client alineado; nested `/projects/{id}/components` conservado.

### H10
Risk engine: `LIKELY_NOT_AFFECTED` → `risk_level=UNKNOWN` (no infla LOW). Dashboard filtra no-aplicables de buckets de riesgo.

### H8
Extractor apt reconoce `package=version` y cadenas `apt-get update && apt-get install`.

### H9
Dockerfile AST se puede persistir como `ContainerImage` (`source_type=dockerfile`, `dockerfile_ast` en API/UI). Persist best-effort con rollback si DB no escribible. CLI también persiste cuando DB está lista.

### H12
`docs/policy.md` documenta suppressions con `owner` + `reference`; test de validación del fixture/schema.

### H14
Mensajes de threshold distinguen `trigger=risk` vs `advisory_severity` e incluyen applicability.

### H15
Con `-o/--output`, JSON/SARIF/CycloneDX/SPDX no se vuelcan a stdout; solo mensaje operacional en stderr.

### H19
Sin versión exacta → `UNKNOWN` (no affected inventado); tests `evaluate_component_ranges`.

## 5. Frontend

### Branding
Assets en `frontend/public/brand/`; favicon; sidebar icon (colapsado) / logo horizontal (expandido).

### EN/ES
Sistema `frontend/src/i18n/` con default EN, `localStorage`, switcher en Topbar y Settings; páginas/badges/intelligence traducidas; IDs técnicos sin traducir.

### API integration
Components client usa contrato canónico; ImageDetail muestra AST persistido.

### Null CVE handling
`lib/vulnerabilityId.ts` + tipos `cve_id?: string | null`.

## 6. Tests

Backend:
- total: **723**
- passed: **723**
- failed: **0**
- coverage: **95%** (TOTAL 9497 stmts, 500 miss)

Frontend:
- total: **45** (12 files)
- passed: **45**
- failed: **0**
- build: **OK** (`tsc && vite build`)

También: Ruff (imports organizados), Alembic `upgrade head` → `downgrade base` → `upgrade head` OK. Sin migración nueva requerida (H9 usa `metadata_json` existente).

## 7. Regresión Stage 19

| ID | Problema | Estado anterior | Corrección | Test | Estado |
|----|----------|-----------------|------------|------|--------|
| H1 | Upsert parcial destruye batches | Catálogo incompleto tras seed npm | `prune_missing=False` default | `test_h1_catalog_incremental_upsert` | FIXED |
| H2 | KEV corrompe/duplica | Prune agresivo / dups | Prune solo KEV + scope source | H1 suite (KEV cases) | FIXED |
| H3 | Components UI path ≠ API | Lista vacía | `GET /api/v1/components` | `test_h3_components_list` | FIXED |
| H4 | (ops/docs Stage 19) | N/A hardening producto | — | — | NOT_APPLICABLE |
| H5 | (ops/docs) | — | — | — | NOT_APPLICABLE |
| H6 | (ops/docs) | — | — | — | NOT_APPLICABLE |
| H7 | Sin escaneo monorepo | Solo raíz | Discovery recursivo seguro | `test_h7_monorepo_discovery` | FIXED |
| H8 | apt pinneado omitido | Packages pinned perdidos | Parser `name=ver` | `test_dockerfile_parser` H8 | FIXED |
| H9 | Dockerfile AST no persiste | Solo CLI/modal efímero | Persist image + FE panel | `test_h9_dockerfile_persist` | FIXED |
| H10 | LOW incluye LNA | Métricas engañosas | Risk UNKNOWN + dashboard filter | `test_h10_risk_buckets` | FIXED |
| H11 | (ops/docs) | — | — | — | NOT_APPLICABLE |
| H12 | Policy YAML docs desalineada | Ejemplos incompletos | Docs + validation test | `test_h12_policy_docs` | FIXED |
| H13 | fail_on castiga LNA | False CI fail | Skip severity si LNA | `test_h13_fail_on_applicability` | FIXED |
| H14 | Mensaje violation engañoso | `risk=LOW` confuso | Trigger explícito | policy engine + H13 | FIXED |
| H15 | `-o` imprime stdout | JSON duplicado | File-only export | `test_h15_export_stdout` | FIXED |
| H16 | Duplicados/aliases OSV | Catálogo inflado | Upsert canónico + aliases | H1 suite | FIXED |
| H17 | API 500 si cve_id null | Frontend roto | Nullable + canonical_id | `test_h17_null_cve_id` | FIXED |
| H18 | Sin scanner uv.lock | Versiones desconocidas | `UvLockScanner` | `test_uv_scanner` | FIXED |
| H19 | Sin versión → UNKNOWN/MEDIUM ambiguo | Matching engañoso | UNKNOWN explícito | `test_h19_unknown_version` | FIXED |
| H20 | Juice Shop lockfile | Comportamiento del repo fixture | No es bug producto | — | WONT_FIX |
| H21 | pnpm multi-doc | Parser falla | `safe_load_all` | `test_pnpm_scanner` | FIXED |

## 8. Migraciones DB

Ninguna migración Alembic nueva. H9 reutiliza `container_images.metadata_json`. Ciclo verificado: upgrade head / downgrade base / upgrade head.

## 9. Seguridad

- Sin Docker daemon / registry auth / ejecución de proyectos.
- Parsing YAML seguro (`safe_load_all`).
- IA no decide policy; thresholds respetan applicability.
- Persistencia Dockerfile best-effort; local-first intacto.

## 10. Limitaciones restantes

- Discovery monorepo: profundidad máxima 6; no sigue symlinks (intencional).
- Persist Dockerfile depende de DB inicializada; si falla, AST sigue devolviéndose sin `image_id`.
- Coverage de `uv_scanner` (~75%) inferior al resto; casos edge de sources TOML raros.
- Regresión OSS completa del harness Stage 19 (PyGoat, Juice Shop, etc.) no re-ejecutada end-to-end aquí; cubierta por tests unit/API/CLI equivalentes + suite completa 723.

## 11. Recomendación de versión

Estos cambios son **hardening post-1.0.1** con correcciones de bugs + scanners + UX i18n, compatibles hacia atrás.

**Recomendación: `1.0.2`** (patch) si el foco es estabilidad; **`1.1.0`** (minor) si se quiere destacar `uv.lock`, monorepo discovery e i18n como capacidades nuevas.

No se ha creado tag ni release automáticamente.

## 12. Veredicto

**STAGE 19.1 — PASS**

Criterios P0/P1 críticos (H17, H1, H16, H2, H13, H21, H18, H3) FIXED; H7 FIXED (no PARTIAL); H9 FIXED; suite backend 723/723; frontend 45/45 + build OK.
