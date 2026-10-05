## Description

Summarize the change, motivation, and any linked issues.

## Type of change

- [ ] Bug fix
- [ ] New feature
- [ ] Documentation
- [ ] Refactor
- [ ] Security
- [ ] Tests
- [ ] Developer experience
- [ ] Breaking change (describe migration / compatibility impact)

## Testing

Commands you ran (adapt paths as needed):

```bash
# Backend
cd backend && pytest --cov=src --cov-report=term-missing --cov-fail-under=95
ruff check src tests && ruff format --check src tests

# Frontend
cd frontend && npm run typecheck && npm run lint && npm run format:check && npm test && npm run build
```

- [ ] Backend tests
- [ ] Frontend tests
- [ ] Lint (Ruff / ESLint)
- [ ] Format check (Ruff / Prettier)
- [ ] Frontend typecheck
- [ ] Frontend build
- [ ] Alembic / migrations checked (if schema changed)

## Security impact

Does this change affect any of the following?

- vulnerability detection
- vulnerability matching
- vulnerability sources / catalog sync
- risk calculation
- policies
- suppressions
- authentication / authorization
- secrets handling
- external network access
- AI prompts / metadata sent to local LLMs

- [ ] No
- [ ] Yes — explain below

<!-- If Yes: describe impact, mitigations, and test coverage. Do not paste secrets. -->

## Documentation

- [ ] Documentation updated (`docs/`, `README.md`, and/or `CHANGELOG.md`)
- [ ] No documentation changes required

## Checklist

- [ ] Tests added/updated when behavior changes
- [ ] Existing quality gates still pass locally
- [ ] No secrets, tokens, or `.env` files committed
- [ ] No unnecessary dependencies added
- [ ] CHANGELOG updated when user-facing
- [ ] Follows deterministic matcher / privacy principles in [CONTRIBUTING.md](../CONTRIBUTING.md)
