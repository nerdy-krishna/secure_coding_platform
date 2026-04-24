---
sidebar_position: 2
title: Coding Standards
---

# Coding Standards

## Backend (Python)

- **Formatter**: `black` (line length default). Run
  `docker compose exec app poetry run black src` before committing,
  or configure your editor to run it on save.
- **Linter**: `ruff`. Targets + rules live in `pyproject.toml` under
  `[tool.ruff]`.
- **Type checker**: `mypy`. Strict-ish — see `pyproject.toml` for
  the exact config.
- **Typing**: prefer `Mapped[type]` in SQLAlchemy models; use
  `Optional[X]` or `X | None` consistently; don't mix the two in
  the same file.
- **Async everywhere**: every repository method is `async def`; every
  service method that needs a DB call is `async def`. Don't call
  async code from a sync `def` — use `asyncio.run` only at CLI
  entry points.

## Frontend (TypeScript + React)

- **Formatter**: the repo uses ESLint + default editor formatters —
  no separate Prettier gate, but please keep existing indentation /
  spacing conventions. `npm run lint` is the enforcement line.
- **Imports**: use absolute imports from `src/` via the Vite
  alias when reaching across feature slices; relative imports for
  same-folder files.
- **Components**: prefer function components + hooks. No class
  components.
- **State**: TanStack Query for server state, `useState` /
  `useReducer` for local; avoid adding Redux / Zustand unless
  multiple pages need to share non-trivial client-only state.

## Comments

Default to writing **no comments**. Only add one when the WHY is
non-obvious:

- A hidden constraint ("must run before the SystemConfigCache
  warmup").
- A subtle invariant ("outbox row + scan row must commit
  together").
- A workaround ("asyncpg panics without this — see upstream issue link").
- Behavior that would surprise a reader ("admin returns None here
  to mean 'skip filter', not 'empty result'").

**Never** write comments that describe WHAT the code does — good
naming handles that. Don't reference the current task / fix /
callers; those belong in the PR description, not the source.

## Naming

- Prefer full words over abbreviations (`configuration` > `cfg`).
- Functions: verb phrases (`get_visible_user_ids`, not
  `visible_user_ids_getter`).
- Classes: noun phrases in PascalCase.
- Booleans: prefix with `is_` / `has_` / `should_` when it aids
  reading.

## Error handling

- **Trust internal code + framework guarantees.** Don't wrap a
  SQLAlchemy session in a try/except just for "safety" — let
  unhandled exceptions propagate to the FastAPI error handler.
- **Validate at system boundaries**: user input, external APIs,
  filesystem interactions.
- Use `HTTPException` for HTTP-layer errors; use domain-specific
  exceptions for everything else.

## Tests

See [Testing Strategy](./testing-strategy.md).

## Migrations

- **Always** generate migrations via
  `alembic revision --autogenerate -m "message"` — don't hand-craft
  the file. Review the generated migration before committing.
- Alembic filenames are timestamp-slugged via `file_template` in
  `alembic.ini` — let Alembic generate the name.
