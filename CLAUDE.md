# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Stack

- **Backend:** Python 3.12, FastAPI, Poetry, SQLAlchemy (async) + Alembic, **LangGraph 1.x + LangChain 1.x**, **LiteLLM** (cost / token), **Pydantic AI** (structured output retry), **FastMCP** (`/mcp` tool surface), `fastapi-users` (JWT Bearer)
- **Worker:** separate container, consumes RabbitMQ via `aio-pika` (async, `connect_robust`) and invokes the LangGraph workflow with an `AsyncPostgresSaver` checkpointer on a single asyncio event loop
- **Frontend:** React 18 + Vite + TypeScript, Ant Design, TanStack Query, React Router v7 (`secure-code-ui/`)
- **Infra:** Postgres 16, RabbitMQ, **Qdrant** (RAG vector store — ADR-008; embedder via `fastembed` `sentence-transformers/all-MiniLM-L6-v2`, no `chromadb` / `sentence-transformers` / `torch`), Fluentd → Loki → Grafana, optional Let's Encrypt via certbot
- **Observability (optional):** self-hosted **Langfuse v3** (web + worker + own Postgres + ClickHouse + Redis + MinIO) for per-LLM-call traces. Disabled by default; opt in via `LANGFUSE_ENABLED=true`. SDK lives in `infrastructure/observability/`

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

1. UI `POST /api/v1/scans` → `projects.py` router → `core/services/scan/submission.py:ScanSubmissionService` dedupes files by hash, creates `Scan` + `ORIGINAL_SUBMISSION` snapshot, **inserts a `scan_outbox` row in the same transaction** (the outbox sweeper publishes to `code_submission_queue` so the API never publishes inline). Approval / cancel / apply-fixes flows go through `core/services/scan/lifecycle.py:ScanLifecycleService`; read paths + scoped deletes go through `core/services/scan/query.py:ScanQueryService`.
2. `workers/consumer.py` picks up the message, builds a `WorkerState`, and calls the compiled LangGraph (`infrastructure/workflows/worker_graph.py`) with a Postgres checkpointer keyed on `scan_id`.
3. Audit path: `retrieve_and_prepare_data` → `RepositoryMappingEngine` + `ContextBundlingEngine` dep graph → **`deterministic_prescan`** (multi-scanner fan-out: Bandit + Semgrep CE + Gitleaks + **OSV-Scanner** subprocesses, no interrupt — seeds `WorkerState.findings` with `source="bandit"/"semgrep"/"gitleaks"/"osv"` findings and persists a CycloneDX BOM to `Scan.bom_cyclonedx` JSONB before any LLM call) → when findings are non-empty: **`pending_prescan_approval`** — graph pauses via native `interrupt()`, status `PENDING_PRESCAN_APPROVAL` — operator reviews findings on the scan-status page (`GET /scans/{id}/prescan-findings`) and resumes via `POST /scans/{id}/approve` with `{"kind":"prescan_approval","approved":true/false,"override_critical_secret":true/false}`; `approved=False` → terminal `user_decline` node (`STATUS_BLOCKED_USER_DECLINE`); `approved=True` with unacknowledged Critical Gitleaks → terminal `blocked_pre_llm` node (`STATUS_BLOCKED_PRE_LLM`); otherwise falls through → `estimate_cost` (tokens via `litellm.token_counter`, price via `litellm.cost_per_token` with per-config admin override) → status `PENDING_COST_APPROVAL` → **second native `interrupt()`** — graph pauses again (I.1). Scans parked at `PENDING_PRESCAN_APPROVAL` for >24 h are auto-declined to `BLOCKED_USER_DECLINE` by `prescan_approval_sweeper.py`. When prescan findings are empty the `pending_prescan_approval` gate is skipped and the graph proceeds directly to `estimate_cost`.
4. User `POST /scans/{id}/approve` with `{"kind":"cost_approval"}` (or empty body for backward compat) → publishes to `analysis_approved_queue` → worker resumes the **same** LangGraph thread with `Command(resume=payload)` → **single-pass parallel analysis**: `analyze_files_parallel` runs every relevant agent against every file from the `ORIGINAL_SUBMISSION` snapshot in parallel (no topological ordering, no cross-file patch propagation). Concurrency is bounded by a single `asyncio.Semaphore(CONCURRENT_LLM_LIMIT=5)` over file × chunk × agent calls. Per-file dependency context is still injected via `build_dep_summary` (read from `repository_map`).
5. `correlate_findings` (groups duplicate findings by `(file_path, cwe, line_number)` into one `corroborating_agents` entry) → `consolidate_and_patch` (REMEDIATE-only: merges per-file `proposed_fixes` via `_run_merge_agent`, tree-sitter syntax-verifies, builds `final_file_map` for the `POST_REMEDIATION` snapshot) → `save_results` → `save_final_report` (writes the CVSS-weighted 0–10 `risk_score` via `shared.lib.risk_score.compute_cvss_aggregate` + `summary` JSON, sets `COMPLETED` / `REMEDIATION_COMPLETED`) → END.
6. Per-file agent triage happens **inside** `analyze_files_parallel` via `resolve_agents_for_file(file_path, all_relevant_agents)` (extension-based routing); there is no separate triage node.

Status strings live in `src/app/shared/lib/scan_status.py` — includes `STATUS_PENDING_PRESCAN_APPROVAL` (graph paused at prescan-approval gate), `STATUS_BLOCKED_PRE_LLM` (operator declined Critical-secret override), and `STATUS_BLOCKED_USER_DECLINE` (operator clicked Stop on the prescan card or sweeper auto-declined after 24 h). Queue names in `config/config.py`: `RABBITMQ_SUBMISSION_QUEUE`, `RABBITMQ_APPROVAL_QUEUE`, `RABBITMQ_REMEDIATION_QUEUE`.

The graph today does **not** generate impact-summary or SARIF reports — those nodes were removed in the 2026-04-26 cleanup. The per-scan `Scan.risk_score` and the Dashboard / Compliance posture scores share a single underlying calculation (`shared.lib.risk_score.compute_cvss_aggregate`): the worker persists it as a 0–10 integer (intensity view) and `dashboard_service._risk_score` / `compliance_service._score_from_aggregate` map it to a 0–100 posture scale via `to_posture_score` (higher = healthier). Same math, two views.

### Backend layout (`src/app/`)

- `api/v1/routers/` — FastAPI routers; wired up in `main.py`.
  - User-facing: `projects.py`, `chat.py`, `compliance.py`, `dashboard.py`, `search.py`, `setup.py`, `refresh.py`.
  - Admin: `admin_agents`, `admin_frameworks`, `admin_prompts`, `admin_rag`, `admin_config`, `admin_users`, `admin_groups` (H.2), `admin_seed`, `admin_logs`, `admin_findings` (`GET /admin/findings` — cross-tenant findings list with source filter + cursor pagination, superuser-only), `admin`/`llm_config`.
- `api/mcp/server.py` — FastMCP server mounted at `/mcp`. Reuses JWT auth via a custom `TokenVerifier`. Tool surface: `sccap_submit_scan`, `sccap_get_scan_status`, `sccap_get_scan_result`, `sccap_approve_scan`, `sccap_apply_fixes`, `sccap_ask_advisor`.
- `api/v1/dependencies.py` — shared FastAPI deps. `get_visible_user_ids` is the H.2 scope helper (returns `None` for admins, `[user.id, ...peers]` for regular users); every list endpoint that could leak data takes it.
- `core/services/` — orchestration layer (scan, chat, admin, compliance, dashboard, search, security standards, RAG preprocessor, default seed). Routers delegate here rather than touching repos directly.
- `infrastructure/database/repositories/` — one repo per aggregate: `scan`, `scan_outbox`, `chat`, `user`, `framework`, `agent`, `prompt_template`, `llm_config`, `rag_job`, `system_config`, `user_group_repo`.
- `infrastructure/agents/` — LangGraph sub-graphs: `generic_specialized_agent` (the per-finding-type analyzer), `chat_agent`, `symbol_map_agent`. Structured output goes through `llm_client.generate_structured_output` which wraps Pydantic AI for per-call validation retry (I.3).
- `infrastructure/scanners/` — deterministic SAST wrappers invoked by `deterministic_prescan_node`: `staging.py` (sandbox + path sanitisation), `bandit_runner.py` (Bandit subprocess + Pydantic-allowlisted output, `source="bandit"`), `semgrep_runner.py` (Semgrep CE multi-language coverage, bundled `p/security-audit` rule pack, `source="semgrep"`), `gitleaks_runner.py` (secret-scan with strict `RuleID/File/StartLine/Description` allowlist + `--redact`, `source="gitleaks"`), `osv_runner.py` (OSV-Scanner dependency scan + CycloneDX BOM generation, returns `(List[VulnerabilityFinding], Optional[Dict])`, `source="osv"`), `registry.py` (per-file routing + minified-bundle detection). Non-empty prescan findings route to the `pending_prescan_approval` interrupt gate (ADR-009); Critical Gitleaks findings only reach `blocked_pre_llm` after the operator declines the override modal.
- `infrastructure/workflows/worker_graph.py` — top-level LangGraph StateGraph; any change to nodes/edges must be reflected in `.agent/scanning_flow.md`.
- `infrastructure/messaging/outbox_sweeper.py` — background task on the API that reads unpublished `scan_outbox` rows and publishes them to RabbitMQ with backoff. Closes the API-commit-then-publish-fail race.
- `infrastructure/messaging/prescan_approval_sweeper.py` — background task that auto-declines scans stuck at `PENDING_PRESCAN_APPROVAL` for >24 h: transitions to `BLOCKED_USER_DECLINE`, writes a `PRESCAN_AUTO_DECLINED` scan event, deletes the LangGraph checkpointer thread. Wired into `main.py` lifespan alongside the outbox sweeper.
- `shared/analysis_tools/` — `chunker.py` (semantic), `context_bundler.py` (dep graph), `repository_map.py` (tree-sitter symbol index).
- `shared/lib/scan_scope.py` — `visible_user_ids(user, repo)` returns `None` (admin) or `[user.id, ...peers]` (regular user).
- `shared/lib/cost_estimation.py` — LiteLLM-backed `count_tokens`, `estimate_cost_for_prompt`, `calculate_actual_cost`. Per-`LLMConfiguration` `input_cost_per_million` / `output_cost_per_million` overrides take precedence; zero falls back to the LiteLLM price map.
- `core/config_cache.py` — `SystemConfigCache` is a process-local singleton populated at startup from `system_config` rows. Drives the dynamic CORS middleware, log level, and SMTP settings. When editing `system_config` at runtime, also update the cache or the change won't take effect until restart.
- `infrastructure/observability/` — optional Langfuse v3 instrumentation. `mask.py` redacts secrets / high-entropy strings before any payload reaches Langfuse (G1, threats #2/#3). `langfuse_client.py` is a fail-open singleton — `get_langfuse()` / `get_langchain_handler()` return `None` when disabled or after init failure. Cost source of truth stays `cost_estimation.calculate_actual_cost`; LiteLLM `success_callback=["langfuse"]` is intentionally NOT enabled to avoid double-counting (G6). Two anchor points: `LLMClient.generate_structured_output` wraps Pydantic AI `agent.run` in `start_as_current_span`; `consumer.py:_run_workflow_for_scan` attaches the LangChain `CallbackHandler` to `RunnableConfig.callbacks` so every node becomes a child span. `trace_id` and `session_id` both equal `correlation_id_var.get()` so traces stitch with Loki by `X-Correlation-ID`.

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

## RAG vector store (Qdrant)

ADR-008 retired ChromaDB. The RAG layer runs on a single Qdrant container — see `src/app/infrastructure/rag/`:

- `base.py` defines the `VectorStore` Protocol; `factory.py.get_vector_store()` returns the singleton `QdrantStore`.
- `embedder.py` uses `fastembed.TextEmbedding("sentence-transformers/all-MiniLM-L6-v2")`; the ONNX bundle is pre-warmed in the Docker build at `FASTEMBED_CACHE_PATH=/opt/fastembed-cache` so air-gapped / restricted-egress deployments never reach HuggingFace at runtime. Vectors are byte-equivalent to the prior chromadb-bundled embedder (max per-dim diff ~6e-9).
- `qdrant_store.py` carries the Chroma-`where` → Qdrant-`Filter` translator covering `$eq` / `$ne` / `$in` / `$and` / `$or`; pinned by `tests/test_rag_qdrant_filter_translator.py`. Chroma string ids map to deterministic UUIDs via `uuid5`; the original id rides along in `payload._chroma_id` for round-trip.
- `rag_client.py` is a back-compat re-export shim (`get_rag_service` / `RAGService = VectorStore`) so historic call sites in routers / agents / scripts continue to work without churn.

The Qdrant container is SHA-pinned, attached to `scpnetwork` only, with no host port — operators use `docker compose exec qdrant ...` for diagnostics. **`QDRANT_API_KEY` is mandatory**: the `Settings` validator rejects empty AND the literal `.env.example` placeholder `change-me-qdrant-key`, so the application refuses to start until a real key is in `.env`.

Lifespan eager-builds the singleton at API startup (wrapped in try/except so a Qdrant outage at boot doesn't block startup; the next caller retries via the lazy path). Lifespan also logs a one-time WARN if `RAG_VECTOR_STORE` is still set in `.env` (the field was retired in ADR-008; remove the line).

**Bootstrap on a fresh deploy:** Qdrant collections start empty. Operators populate RAG content via the existing admin UI flows (`POST /api/v1/admin/rag/preprocess/...` for ASVS/proactive_controls/cheatsheets CSVs, etc.). Scans against an empty RAG path still complete — agents produce findings without RAG citations until content is ingested.

**Migration from PR1 dual-write:** the embedder is byte-equivalent so existing PR1-seeded Qdrant collections remain valid; no rebuild required. The `chroma_data` Docker volume is now orphaned — remove via `docker volume rm sccap_chroma_data` after pulling. **`setup.sh` auto-generates `QDRANT_API_KEY` on fresh installs** and replaces the `change-me-qdrant-key` placeholder in any pre-existing `.env` (operators upgrading from PR1 don't need to rotate the key manually); it also strips a retired `RAG_VECTOR_STORE=…` line if present.

## Evaluations (Promptfoo)

Prompt regressions for the agents are guarded by a Promptfoo eval suite under `evals/`. Run locally with `cd evals && npm ci && npm test` — the default provider is a deterministic JS mock (free, no LLM calls). The CI workflow at `.github/workflows/evals.yml` runs the same suite on every PR that touches `evals/**`, the canonical prompt seed (`src/app/core/services/default_seed_service.py`), or the agent modules. The CI gate is **warn-only** for now — the workflow uploads results as a build artifact but does NOT block merges; we'll flip to hard-block once we have ~2 weeks of stable baseline.

Prompt strings live in the seed (`default_seed_service._AUDIT_TEMPLATE` / `_REMEDIATION_TEMPLATE` / `_CHAT_TEMPLATE`) and are extracted into `evals/agents/*/prompts/*.txt` by `scripts/extract_eval_prompts.py`. CI runs `--check` on every PR; the build fails if the committed eval prompts drift from the canonical seed. Never hand-edit the extracted `.txt` files — re-run `--write` and commit instead.

Live evals against a real LLM (currently `gpt-4o-mini` via `OPENAI_API_KEY` in repo secrets) are opt-in only — they fire only on `workflow_dispatch` with `mode: live`. Cost is ~1–2¢ per click. PRs from forks cannot reach the secret because the live job is gated to manual dispatch (no `pull_request_target` is used).

**Coverage gap, explicit:** the eval suite catches **functional** regressions (prompt still produces the expected JSON shape and detects obvious vulnerabilities). It does **not** cover OWASP LLM Top-10 / Agentic Top-10 prompt-injection or jailbreak attacks — that's the redteam pack, deferred to a separate `/sccap` run. "We have evals" ≠ "we have injection coverage."

## Langfuse auth boundary (operators)

Langfuse runs its own NextAuth user model — **independent** of SCCAP fastapi-users JWT. Practical implications (threat-model G8 / threat #5):

- The SCCAP first-user bootstrap does NOT create a Langfuse user. Bring up `langfuse-web` once, then the seeded admin (`LANGFUSE_INIT_USER_EMAIL` / `LANGFUSE_INIT_USER_PASSWORD` from `.env`) invites people from the Langfuse UI.
- Offboarding a SCCAP user (deactivating their `users` row) does NOT revoke their Langfuse session. **Manual de-invite required** in the Langfuse UI; run alongside the SCCAP deactivation.
- `NEXTAUTH_SESSION_MAXAGE` (default 86400 = 24h) caps how long a stale session can read traces.
- Langfuse traces span all SCCAP tenants in the first iteration — **anyone with Langfuse UI access can read the prompt + completion of every scan**. Restrict admin invites to SCCAP superusers operationally. Per-tenant Langfuse projects are filed as a follow-up.
