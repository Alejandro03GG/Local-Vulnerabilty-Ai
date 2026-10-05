# Stage 19.2 — Post-Retest Hardening Report

## Objetivo

Demostrar robustez del **sync nativo OSV** (H16), ejecutar cobertura real multi-fuente KEV/NVD (H24) y documentar H20 como limitación de harness. Sin tag/release.

## H16 — Native OSV sync robustness (prioridad)

### Problema
El retest dependía de mitigaciones del harness (`seed_from_*` + purge/dedupe). El producto debe ser idempotente por sí mismo.

### Solución (producto)
- `OSVSource.sync()` limpia cache in-memory antes del probe.
- `SourceService.sync_source` upserta con `prune_missing=False` para OSV/NVD.
- Upsert: aliases case-insensitive, merge de orphans CVE↔GHSA, `record_count` = tamaño de catálogo.

### Prueba nativa (sin harness)
Suite `backend/tests/unit/test_h16_native_osv_sync.py` ejercita:

`ControllableOSVSource → SourceService.sync_source → upsert`

| Escenario | Resultado |
|-----------|-----------|
| Sync ×3 mismos registros | catálogo estable (3 filas), `record_count` no acumula |
| Mismos registros + aliases | sin identifiers duplicados |
| Batches parciales PyPI→npm→crates | 3 ecosistemas preservados |
| `prune_missing` en path OSV | **siempre False** |
| Fallo de sync | catálogo previo intacto, status `error` |
| Bridge alias orphan GHSA+CVE | colapsa a 1 fila |

### Evidencia
`pytest tests/unit/test_h16_native_osv_sync.py` → **6 passed**

**H16 = FIXED**

## H24 — Multi-source coverage (no bugfix)

### Causa del “never_synced”
La campaña previa solo sembró OSV; no se ejecutó sync KEV/NVD. No es un defecto demostrado del producto.

### Prueba real ejecutada
Orden: OSV → CISA KEV → NVD; cada una **dos veces**.

| Source | Sync1 | Sync2 | DB status | Records | Repeat estable |
|--------|-------|-------|-----------|---------|----------------|
| OSV | SUCCESS | SUCCESS | active | 8 | yes |
| CISA KEV | SUCCESS | SUCCESS | active | 1734 | yes |
| NVD | SUCCESS | SUCCESS | active | 5 | yes |

API `GET /api/v1/sources`: los tres `active` con los mismos conteos.  
CLI `vuln-ai sources list`: equivalente UI Sources.  
Aislamiento: KEV 1734 permanece tras OSV/NVD.

Nota: NVD/OSV sync del producto son **probes parciales** (diseño actual), no dump NVD completo.

**H24 = VERIFIED** (no FIXED — no había bug que corregir)

## H20 — Juice Shop lockfile

**WONT_FIX / HARNESS LIMITATION**

- Upstream Juice Shop: `package-lock=false`, sin `package-lock.json`.
- El harness puede generar un lock; eso no es responsabilidad del scanner npm.
- Documentado en `docs/cli.md` (Known Limitations) y este reporte.
- **Scanner npm no modificado.**

## Otros (contexto Stage 19.2)

| ID | Estado |
|----|--------|
| H11 | FIXED (fixture clean `requests==2.33.0`) |
| H12 | FIXED (docs YAML → `policy validate` exit 0) |
| H22 | FIXED (previo) |
| H23 | FIXED (previo) |

## Tests / gates (esta pasada)

- H16 native suite: **6 passed**
- H16 + catalog suite: **17 passed**
- H24 sync real + API/CLI: **VERIFIED**
- Sin commit / sin tag

## Riesgos residuales

- Sync NVD/OSV CLI = probe parcial.
- Proyectos npm sin lockfile no obtienen versiones exactas (limitación documentada H20).

## Release Candidate

**RELEASE READY**
