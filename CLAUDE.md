# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Stack

- **Backend:** Python 3.12, FastAPI, Poetry, SQLAlchemy (async) + Alembic, LangGraph, `fastapi-users` (JWT Bearer)
- **Worker:** separate container, consumes RabbitMQ via `pika` (blocking) and invokes the LangGraph workflow with an `AsyncPostgresSaver` checkpointer
- **Frontend:** React 18 + Vite + TypeScript, Ant Design, TanStack Query, React Router v7 (`secure-code-ui/`)
- **Infra:** Postgres 16, RabbitMQ, ChromaDB (RAG), Fluentd → Loki → Grafana, optional Let's Encrypt via certbot

## Common commands

Always run backend/worker commands inside Docker — the backend's `.env` assumes hostnames `db` and `rabbitmq` that only resolve inside the compose network.

```bash
# First-time or full rebuild
./setup.sh                                     # interactive; writes .env, starts stack, runs migrations
docker compose up -d --build                   # rebuild + start all services
docker compose logs -f app worker              # tail backend + worker

# Migrations (Alembic reads ALEMBIC_DATABASE_URL from .env; prepend_sys_path=src)
docker compose exec app alembic upgrade head
docker compose exec app alembic revision --autogenerate -m "msg"
docker compose exec app alembic downgrade -1

# Tests (pytest + pytest-asyncio; Playwright test in tests/ hits the running UI at http://localhost)
docker compose exec app poetry run pytest
docker compose exec app poetry run pytest tests/test_ui_setup.py::test_setup_flow -v

# Lint / format (dev deps: ruff, black, mypy)
docker compose exec app poetry run ruff check src
docker compose exec app poetry run black src
docker compose exec app poetry run mypy src

# Frontend (run from secure-code-ui/)
npm run dev        # Vite dev server on :5173 (add origin to ALLOWED_ORIGINS or CORS is blocked post-setup)
npm run build      # tsc -b && vite build
npm run lint       # eslint .
```

## Architecture

### Submission → Scan lifecycle (two-phase, user-approved)

The scan flow is deliberately **"audit-first, remediate-intelligently"** — the worker pauses mid-workflow for explicit cost approval. The full flow is documented in `.agent/scanning_flow.md`; the short version:

1. UI `POST /api/v1/scans` → `projects.py` router → `core/services/scan_service.py` dedupes files by hash, creates `Scan` + `ORIGINAL_SUBMISSION` snapshot, publishes `{scan_id}` to `code_submission_queue`.
2. `workers/consumer.py` picks up the message, builds a `WorkerState`, and calls the compiled LangGraph (`infrastructure/workflows/worker_graph.py`) with a Postgres checkpointer keyed on `scan_id`.
3. Graph path A (`QUEUED`): `retrieve_and_prepare_data` → builds `RepositoryMappingEngine` + `ContextBundlingEngine` dep graph → `estimate_cost` → status `PENDING_COST_APPROVAL` → **graph ENDs**.
4. User `POST /scans/{id}/approve` → publishes to `analysis_approved_queue` → worker re-enters the same thread_id → graph path B (`QUEUED_FOR_SCAN`): `triage_agents` → `dependency_aware_analysis_orchestrator` (topological order, per-file chunking + triaged specialized agents run in parallel under `CONCURRENT_LLM_LIMIT=5`) → `correlate_findings` → `save_results` → `run_impact_reporting` → `save_final_report`.
5. For `REMEDIATE` scans the orchestrator applies fixes incrementally and resolves conflicts via a merge agent, then writes a `POST_REMEDIATION` snapshot.

Status strings live at the top of `worker_graph.py`. Queue names live in `config/config.py` (`RABBITMQ_SUBMISSION_QUEUE`, `RABBITMQ_APPROVAL_QUEUE`, `RABBITMQ_REMEDIATION_QUEUE`).

### Backend layout (`src/app/`)

- `api/v1/routers/` — FastAPI routers; wired up in `main.py`. Admin endpoints are split by concern (`admin_agents`, `admin_frameworks`, `admin_prompts`, `admin_rag`, `admin_config`, `admin_users`, `llm_config`).
- `core/services/` — orchestration layer (scan, chat, admin, security standards, RAG preprocessor). Routers should delegate here rather than touching repos directly.
- `infrastructure/database/repositories/` — one repo per aggregate (scan, chat, user, framework, agent, prompt_template, llm_config, rag_job, system_config).
- `infrastructure/agents/` — LangGraph sub-graphs: `generic_specialized_agent` (the per-finding-type analyzer), `impact_reporting_agent`, `chat_agent`, `symbol_map_agent`.
- `infrastructure/workflows/worker_graph.py` — top-level LangGraph StateGraph; any change to nodes/edges must be reflected in `.agent/scanning_flow.md`.
- `shared/analysis_tools/` — `chunker.py` (semantic), `context_bundler.py` (dep graph), `repository_map.py` (tree-sitter symbol index).
- `core/config_cache.py` — `SystemConfigCache` is a process-local singleton populated at startup from `system_config` rows. It drives the dynamic CORS middleware, log level, and SMTP settings. When editing `system_config` at runtime, also update the cache or the change won't take effect until restart.

### Auth & setup mode

- First-run bootstrapping: `api/v1/routers/setup.py` owns `/api/v1/setup/*`. Until setup completes, `SystemConfigCache.is_setup_completed()` is false and the `DynamicCORSMiddleware` in `main.py` allows all origins. Once complete, allowed origins come from `security.allowed_origins` in the DB plus the `ALLOWED_ORIGINS` env var.
- Auth is `fastapi-users` with a JWT `BearerTransport`. There is a custom `/api/v1/auth/refresh` endpoint in `routers/refresh.py` (fastapi-users doesn't ship one for Bearer).
- The **first registered user becomes superuser**; superuser-only routes live under `/admin/*` both on the API and UI (`SuperuserRoutesWithLayout` in `secure-code-ui/src/app/App.tsx`).

### Frontend layout (`secure-code-ui/src/`)

Feature-sliced: `app/` (providers + routes), `pages/` (route views grouped by area: `auth`, `setup`, `account`, `admin`, `analysis`, `chat`, `submission`), `features/` (feature-scoped components), `shared/api/` (one service module per backend domain — all traffic goes through `apiClient.ts`), `widgets/` (layouts). The entire app is gated on `isSetupCompleted` — all four route guards in `App.tsx` redirect to `/setup` when false.

## Repository conventions

- `.agent/` is load-bearing operational docs. Per `.agent/agent_instructions.md`, keep `.agent/project_structure.md` and `.agent/scanning_flow.md` in sync when files move or the scan pipeline changes.
- Alembic filenames are timestamp-slugged via `file_template` in `alembic.ini` — let Alembic generate the name, don't hand-craft it. `prepend_sys_path = src` means `env.py` imports `app.infrastructure.database.models` directly.
- Every request gets an `X-Correlation-ID` (see `correlation_id_middleware` in `main.py`); log from `logging.getLogger(__name__)` and the ID is attached automatically via `correlation_id_var`.
- Secrets (API keys, SMTP passwords, LLM provider creds) are encrypted with the Fernet key in `ENCRYPTION_KEY` before being stored in `llm_configurations` / `system_config`. Don't write them plaintext.
