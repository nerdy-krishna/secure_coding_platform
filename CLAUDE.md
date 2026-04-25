# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Stack

- **Backend:** Python 3.12, FastAPI, Poetry, SQLAlchemy (async) + Alembic, **LangGraph 1.x + LangChain 1.x**, **LiteLLM** (cost / token), **Pydantic AI** (structured output retry), **FastMCP** (`/mcp` tool surface), `fastapi-users` (JWT Bearer)
- **Worker:** separate container, consumes RabbitMQ via `pika` (blocking) and invokes the LangGraph workflow with an `AsyncPostgresSaver` checkpointer
- **Frontend:** React 18 + Vite + TypeScript, Ant Design, TanStack Query, React Router v7 (`secure-code-ui/`)
- **Infra:** Postgres 16, RabbitMQ, ChromaDB (RAG, bundled ONNX embedder — no `sentence-transformers`), Fluentd → Loki → Grafana, optional Let's Encrypt via certbot

## Common commands

Always run backend/worker commands inside Docker — the backend's `.env` assumes hostnames `db` and `rabbitmq` that only resolve inside the compose network.

```bash
# First-time or full rebuild
./setup.sh                                     # interactive; writes .env, starts stack, runs migrations
docker compose up -d --build                   # rebuild + start all services
docker compose logs -f app worker              # tail backend + worker

# Migrations (Alembic reads ALEMBIC_DATABASE_URL from .env; prepend_sys_path=src)
# Note: env.py drives migrations via create_async_engine(), so the URL must use
# postgresql+asyncpg:// even though the Alembic CLI itself is sync.
docker compose exec app alembic upgrade head
docker compose exec app alembic revision --autogenerate -m "msg"
docker compose exec app alembic downgrade -1

# Tests (pytest + pytest-asyncio; rollback-per-test isolation via tests/conftest.py)
docker compose exec app pytest                                  # full suite (excludes Playwright e2e by default)
docker compose exec app pytest tests/test_compliance_service.py -v
docker compose exec app pytest tests/test_ui_setup.py::test_setup_flow -v   # Playwright; needs full stack

# Lint / format / type-check (run from host with python3, or use the container)
python3 -m ruff check src
python3 -m black src
python3 -m mypy src

# Frontend (run from secure-code-ui/)
npm run dev        # Vite dev server on :5173 (add origin to ALLOWED_ORIGINS or CORS is blocked post-setup)
npm run build      # tsc -b && vite build
npm run lint       # eslint .
```

## Architecture

### Submission → Scan lifecycle (two-phase, user-approved)

The scan flow is deliberately **"audit-first, remediate-intelligently"** — the worker pauses mid-workflow for explicit cost approval. The full flow is documented in `.agent/scanning_flow.md`; the short version:

1. UI `POST /api/v1/scans` → `projects.py` router → `core/services/scan_service.py` dedupes files by hash, creates `Scan` + `ORIGINAL_SUBMISSION` snapshot, **inserts a `scan_outbox` row in the same transaction** (the outbox sweeper publishes to `code_submission_queue` so the API never publishes inline).
2. `workers/consumer.py` picks up the message, builds a `WorkerState`, and calls the compiled LangGraph (`infrastructure/workflows/worker_graph.py`) with a Postgres checkpointer keyed on `scan_id`.
3. Audit path: `retrieve_and_prepare_data` → `RepositoryMappingEngine` + `ContextBundlingEngine` dep graph → `estimate_cost` (tokens via `litellm.token_counter`, price via `litellm.cost_per_token` with per-config admin override) → status `PENDING_COST_APPROVAL` → **native `interrupt()`** — graph pauses with full state in the checkpointer (I.1).
4. User `POST /scans/{id}/approve` → publishes to `analysis_approved_queue` → worker resumes the **same** LangGraph thread with `Command(resume=payload)` → **single-pass parallel analysis**: `analyze_files_parallel` runs every relevant agent against every file from the `ORIGINAL_SUBMISSION` snapshot in parallel (no topological ordering, no cross-file patch propagation). Concurrency is bounded by a single `asyncio.Semaphore(CONCURRENT_LLM_LIMIT=5)` over file × chunk × agent calls. Per-file dependency context is still injected via `build_dep_summary` (read from `repository_map`).
5. `correlate_findings` (groups duplicate findings by `(file_path, cwe, line_number)` into one `corroborating_agents` entry) → `consolidate_and_patch` (REMEDIATE-only: merges per-file `proposed_fixes` via `_run_merge_agent`, tree-sitter syntax-verifies, builds `final_file_map` for the `POST_REMEDIATION` snapshot) → `save_results` → `save_final_report` (writes the coarse 0–10 severity-bucket `risk_score` + `summary` JSON, sets `COMPLETED` / `REMEDIATION_COMPLETED`) → END.
6. Per-file agent triage happens **inside** `analyze_files_parallel` via `resolve_agents_for_file(file_path, all_relevant_agents)` (extension-based routing); there is no separate triage node.

Status strings live in `src/app/shared/lib/scan_status.py`. Queue names in `config/config.py`: `RABBITMQ_SUBMISSION_QUEUE`, `RABBITMQ_APPROVAL_QUEUE`, `RABBITMQ_REMEDIATION_QUEUE`.

The graph today does **not** generate impact-summary or SARIF reports — those nodes were removed in the 2026-04-26 cleanup. The `Scan.risk_score` heuristic (coarse 0–10 severity bucket) is independent from the Dashboard / Compliance weighted-findings score served by `dashboard_service._risk_score` and `compliance_service`. They tell different stories: per-scan severity intensity vs. weighted posture across the visibility scope.

### Backend layout (`src/app/`)

- `api/v1/routers/` — FastAPI routers; wired up in `main.py`.
  - User-facing: `projects.py`, `chat.py`, `compliance.py`, `dashboard.py`, `search.py`, `setup.py`, `refresh.py`.
  - Admin: `admin_agents`, `admin_frameworks`, `admin_prompts`, `admin_rag`, `admin_config`, `admin_users`, `admin_groups` (H.2), `admin_seed`, `admin_logs`, `admin`/`llm_config`.
- `api/mcp/server.py` — FastMCP server mounted at `/mcp`. Reuses JWT auth via a custom `TokenVerifier`. Tool surface: `sccap_submit_scan`, `sccap_get_scan_status`, `sccap_get_scan_result`, `sccap_approve_scan`, `sccap_apply_fixes`, `sccap_ask_advisor`.
- `api/v1/dependencies.py` — shared FastAPI deps. `get_visible_user_ids` is the H.2 scope helper (returns `None` for admins, `[user.id, ...peers]` for regular users); every list endpoint that could leak data takes it.
- `core/services/` — orchestration layer (scan, chat, admin, compliance, dashboard, search, security standards, RAG preprocessor, default seed). Routers delegate here rather than touching repos directly.
- `infrastructure/database/repositories/` — one repo per aggregate: `scan`, `scan_outbox`, `chat`, `user`, `framework`, `agent`, `prompt_template`, `llm_config`, `rag_job`, `system_config`, `user_group_repo`.
- `infrastructure/agents/` — LangGraph sub-graphs: `generic_specialized_agent` (the per-finding-type analyzer), `chat_agent`, `symbol_map_agent`. Structured output goes through `llm_client.generate_structured_output` which wraps Pydantic AI for per-call validation retry (I.3).
- `infrastructure/workflows/worker_graph.py` — top-level LangGraph StateGraph; any change to nodes/edges must be reflected in `.agent/scanning_flow.md`.
- `infrastructure/messaging/outbox_sweeper.py` — background task on the API that reads unpublished `scan_outbox` rows and publishes them to RabbitMQ with backoff. Closes the API-commit-then-publish-fail race.
- `shared/analysis_tools/` — `chunker.py` (semantic), `context_bundler.py` (dep graph), `repository_map.py` (tree-sitter symbol index).
- `shared/lib/scan_scope.py` — `visible_user_ids(user, repo)` returns `None` (admin) or `[user.id, ...peers]` (regular user).
- `shared/lib/cost_estimation.py` — LiteLLM-backed `count_tokens`, `estimate_cost_for_prompt`, `calculate_actual_cost`. Per-`LLMConfiguration` `input_cost_per_million` / `output_cost_per_million` overrides take precedence; zero falls back to the LiteLLM price map.
- `core/config_cache.py` — `SystemConfigCache` is a process-local singleton populated at startup from `system_config` rows. Drives the dynamic CORS middleware, log level, and SMTP settings. When editing `system_config` at runtime, also update the cache or the change won't take effect until restart.

### Auth, setup, and visibility scope

- First-run bootstrapping: `api/v1/routers/setup.py` owns `/api/v1/setup/*`. Until setup completes, `SystemConfigCache.is_setup_completed()` is false and the `DynamicCORSMiddleware` in `main.py` allows all origins. Once complete, allowed origins come from `security.allowed_origins` in the DB plus the `ALLOWED_ORIGINS` env var.
- Auth is `fastapi-users` with a JWT `BearerTransport`. Custom `/api/v1/auth/refresh` lives in `routers/refresh.py` (fastapi-users doesn't ship one for Bearer).
- The **first registered user becomes superuser**; superuser-only routes live under `/admin/*` both on the API and UI.
- **Visibility scope (H.2):** every list endpoint takes `visible_user_ids = Depends(get_visible_user_ids)`. Admins see everything (`None`); regular users see their own data plus peers from `user_group_memberships` (`[user.id, ...peers]`). Repositories translate this via `_scope_column(col, user_id, visible_user_ids)`.

### Frontend layout (`secure-code-ui/src/`)

Feature-sliced: `app/` (providers + routes), `pages/` (route views grouped by area: `auth`, `setup`, `account`, `admin`, `analysis`, `chat`, `compliance`, `submission`), `features/` (feature-scoped components), `shared/api/` (one service module per backend domain — all traffic goes through `apiClient.ts`), `widgets/` (layouts). The entire app is gated on `isSetupCompleted` — all four route guards in `App.tsx` redirect to `/setup` when false.

- **Roles** (H.3): `SccapRole = "user" | "admin"`. Legacy `dev` / `enterprise` localStorage values are migrated to `user` on read. The Tweaks role toggle is cosmetic only — `DashboardPage` routes off the real `user.is_superuser` to pick `UserDashboard` vs. `AdminSnapshot`.
- **TopNav** carries the global search combobox (`SearchCombobox.tsx`) — 250 ms debounce, TanStack Query, three sections (projects / scans / findings), arrow + Enter + Escape keyboard nav.
- **AdminSubNav** (`widgets/AdminSubNav.tsx`) is rendered by `DashboardLayout` on `/admin/*` and `/account/settings/llm`. It's the only way to navigate between admin surfaces, since the TopNav has a single Admin link.

## Repository conventions

- `.agent/` is load-bearing operational docs. Per `.agent/agent_instructions.md`, keep `.agent/project_structure.md` and `.agent/scanning_flow.md` in sync when files move or the scan pipeline changes.
- Alembic filenames are timestamp-slugged via `file_template` in `alembic.ini` — let Alembic generate the name, don't hand-craft it. `prepend_sys_path = src` means `env.py` imports `app.infrastructure.database.models` directly.
- Every request gets an `X-Correlation-ID` (see `correlation_id_middleware` in `main.py`); log from `logging.getLogger(__name__)` and the ID is attached automatically via `correlation_id_var`. The same id rides the worker message envelope so logs stitch across services.
- Secrets (LLM API keys, SMTP passwords) are Fernet-encrypted with `ENCRYPTION_KEY` before being stored in `llm_configurations` / `system_config`. Don't write them plaintext. `.env.example` deliberately does **not** include `OPENAI_API_KEY` / `GOOGLE_API_KEY` placeholders (H.0.2).
- `LITELLM_LOCAL_MODEL_COST_MAP=True` keeps cost lookups offline; recommended for restricted-egress deployments.
- Tests use `tests/conftest.py` fixtures with SAVEPOINT-per-test rollback (H.0.3). `pyproject.toml` has `addopts = "--ignore=tests/test_ui_setup.py"` so the Playwright e2e is opt-in. CI runs the rest against a Postgres 16 service container.
- New endpoints that list user-owned data: take `visible_user_ids = Depends(get_visible_user_ids)` and forward it through the service layer to the repository — never re-implement scope checks inline.
