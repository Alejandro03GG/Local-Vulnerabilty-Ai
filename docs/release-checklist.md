# Release Checklist — Local Vulnerability AI

Use this checklist before tagging a release. Every item must be verified with fresh local evidence.

## Quality Gates

- [ ] Backend tests: `cd backend && pytest` — all PASS
- [ ] Backend coverage: `pytest --cov=vuln_ai --cov-fail-under=95` — ≥ 95%
- [ ] Ruff: `ruff check src tests` and `ruff format --check src tests` — PASS
- [ ] Alembic: `alembic upgrade head`, `alembic check`, `alembic downgrade base`, `alembic upgrade head` — PASS
- [ ] Frontend tests: `cd frontend && npm test` — all PASS
- [ ] TypeScript: `npm run typecheck` — PASS
- [ ] ESLint: `npm run lint` — PASS
- [ ] Prettier: `npm run format:check` — PASS
- [ ] Vite build: `npm run build` — PASS

## CLI / API / Product Smoke

- [ ] `vuln-ai --help`
- [ ] `vuln-ai version`
- [ ] `vuln-ai doctor`
- [ ] `vuln-ai image --help`
- [ ] `vuln-ai scan . --no-ai` (or a fixture project)
- [ ] `vuln-ai scan <fixture> --format json --no-ai` (stdout is pure JSON)
- [ ] `vuln-ai scan <fixture> --format sarif --no-ai`
- [ ] `vuln-ai image scan <fixture.tar> --no-ai`
- [ ] `vuln-ai policy validate` (sample policy)
- [ ] API health: `GET /health` returns OK
- [ ] Frontend production build serves without console errors on core routes

## Security

- [ ] No `docker run` / `docker exec` / `docker build` / `podman run` / `shell=True` in analysis path
- [ ] Container archive traversal / symlink / bomb controls still covered by tests
- [ ] Policy YAML uses `yaml.safe_load` + `extra="forbid"`
- [ ] No real secrets in source, fixtures, docs, or examples
- [ ] AI disabled path works (`--no-ai`); AI failure is non-fatal
- [ ] Dependency audit reviewed for unexpected egress

## Exports

- [ ] SARIF 2.1.0 structural validation tests PASS
- [ ] CycloneDX 1.5 structural validation tests PASS
- [ ] SPDX 2.3 structural validation tests PASS
- [ ] Container provenance properties present when scanning images

## Documentation & Packaging

- [ ] Version strings consistent (`vuln_ai.__version__`, `pyproject.toml`, `frontend/package.json`, docs examples)
- [ ] `CHANGELOG.md` has `## [X.Y.Z]` entry for this release
- [ ] `README.md` reflects real capabilities and known limitations
- [ ] `SECURITY.md` supported versions updated
- [ ] `LICENSE` present
- [ ] `CONTRIBUTING.md` setup steps work from a clean clone
- [ ] `docs/release-checklist.md` reviewed
- [ ] Known limitations documented (no registry auth, no K8s, no runtime monitoring, etc.)

## Clean Installation

- [ ] Fresh Python venv: `pip install -e ".[dev]"`, `alembic upgrade head`, `vuln-ai doctor`
- [ ] Fresh frontend: remove `node_modules`, `npm install`, `npm run build`
- [ ] CI workflow (`.github/workflows/ci.yml`) mirrors local gates

## Release Decision

- [ ] No open P0 blockers
- [ ] No unjustified P1 blockers
- [ ] Tag / package artifacts are reproducible from this checklist
