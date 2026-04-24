---
sidebar_position: 3
title: Testing Strategy
---

# Testing Strategy

## Backend

- **Runner**: `pytest` + `pytest-asyncio` (function-scoped async
  event loop; no session-wide loop — it breaks asyncpg).
- **Config**: `[tool.pytest.ini_options]` block in
  `pyproject.toml`. `asyncio_mode = "auto"` means every `async def
  test_*` runs automatically without a marker.
- **Isolation**: every test runs in a SAVEPOINT-per-test rollback
  via the `db_session` fixture in `tests/conftest.py`. This means
  tests can be re-run against a populated database without
  cleanup; they never commit.
- **Factories**: `seeded_user`, `seeded_admin` yield fully-hydrated
  User rows with `hashed_password="x" * 64`. Grab whichever matches
  the scope you need.
- **LLM mocking**: `mock_llm_client` monkeypatches
  `app.infrastructure.llm_client.get_llm_client` so tests never
  make network calls.

### Run locally

```bash
docker compose exec app poetry run pytest            # full suite
docker compose exec app poetry run pytest -xvs       # stop on first failure, verbose
docker compose exec app poetry run pytest tests/test_compliance_service.py -v
```

### Existing smoke tests

Under `tests/` today:

- `test_default_seed_service.py` — idempotency + "seed if empty"
  semantics for the 3 default frameworks.
- `test_compliance_service.py` — per-framework stats including the
  score drop as findings accumulate.
- `test_cost_estimation.py` — LiteLLM token-count + cost in a
  known plausible range for OpenAI / Anthropic / Google models,
  plus the admin-override path.
- `test_seed_endpoint.py` — `POST /admin/seed/defaults` rejects
  non-admins and returns the correct shape for admins.
- `test_ui_setup.py` — Playwright smoke of the setup wizard +
  first-user flow (heavy; excluded from CI pytest job because it
  needs the full stack up).

The goal is scaffolding + regression coverage of the
highest-leverage code paths, not broad coverage. New services
should ship with at least a smoke test that exercises the happy
path.

## Frontend

- **Unit / component**: not yet wired up. The main frontend gate is
  `npm run lint` (ESLint) + `npm run build` (`tsc -b && vite build`);
  type errors block CI.
- **Integration**: the Playwright test above covers the most
  valuable flow (first-user registration → setup wizard completion).

## CI

`.github/workflows/ci.yml` runs five jobs on every push:

1. **Backend lint** — `ruff check src` + `black --check src`.
2. **Frontend lint + build** — `npm run lint && npm run build` in
   `secure-code-ui/`.
3. **poetry.lock drift check** — fails if `poetry lock --check`
   sees the lockfile out of sync with `pyproject.toml`.
4. **Docker build (api + worker)** — full multi-stage build, no
   push. Validates the `Dockerfile` every PR.
5. **Backend tests (pytest)** — spins up a Postgres 16 service
   container, runs Alembic, then pytest.

All five must be green for a PR to merge.

## When to add a test

- **Fixing a bug**: add a test that reproduces it first.
- **Adding a scope-filter consumer**: test that admin (scope=None)
  and regular user (scope=[id, ...peers]) return the expected
  rows.
- **Adding an LLM agent**: use `mock_llm_client` so the test is
  deterministic; assert on the parsed Pydantic model.

When **not** to add a test:

- Pure CRUD endpoints with no business logic. The integration
  coverage from the router-level smoke is usually enough; add one
  only if the shape is complex or a future refactor is likely.
