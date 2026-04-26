# Project Structure

## Directory Tree

```
.
├── .agent/                 # Agent workflows and recovery data
├── .github/                # GitHub specific configurations
├── alembic/                # Database migrations (Versions & Env)
├── docker-compose.yml      # Service Orchestration
├── secure-code-ui/         # Frontend Application (React/Vite)
│   ├── Dockerfile
│   ├── src/
│   │   ├── app/            # App Providers & Styles
│   │   ├── features/       # Auth, Dashboard, Results, Submission
│   │   ├── pages/          # Route Views (Auth, Admin, Analysis)
│   │   ├── shared/         # API, Components, Hooks, Lib, Types
│   │   ├── main.tsx        # Entry Point
│   │   └── vite-env.d.ts
│   └── vite.config.ts
├── src/                    # Backend Application (FastAPI)
│   └── app/
│       ├── api/v1/         # Routers, Models, Dependencies
│       ├── core/           # Config, Logging, Schemas, Services
│       ├── infrastructure/ # Auth, DB, Agents, LLM Clients
│       ├── shared/         # Utility Libraries
│       ├── workers/        # Consumer (RabbitMQ)
│       └── main.py         # App Entry Point
├── evals/                  # Promptfoo eval harness (mock + live CI)
├── scripts/                # Repo-root operator scripts (e.g. extract_eval_prompts.py)
├── poetry.lock             # Backend Lock File
└── pyproject.toml          # Backend Project Config
```

## File Dictionary

### Root
- **docker-compose.yml**: Orchestration for App, DB, RabbitMQ, VectorDB, OpenSearch, Fluentd, and UI.
- **pyproject.toml**: Python backend dependencies and configuration.
- **alembic.ini**: Database migration configuration.
- **.env**: Environment variables for secrets and service configuration.
- **evals/**: Promptfoo regression suite (`promptfoo-eval-framework` run, 2026-04-26). One `agents/<agent>/promptfooconfig.yaml` per covered agent + a sandboxed `providers/mock.js` for free PR runs. Extracted prompt files (`agents/*/prompts/*.txt`) come from `default_seed_service.py` via `scripts/extract_eval_prompts.py` — CI runs `--check` on every PR. Live runs (`workflow_dispatch.mode=live`) hit `gpt-4o-mini` via `secrets.OPENAI_API_KEY`. Warn-only gate today; flip to hard-block in a follow-up. The OWASP LLM/Agentic Top-10 redteam pack is intentionally deferred — see `evals/README.md`.

### Backend (`src/app`)
- **main.py**: FastAPI application entry point, middleware, and router inclusion.
- **api/v1/**:
    - **routers/**: Endpoint definitions (auth, projects, chat, admin).
    - **models.py**: API-specific data models.
    - **dependencies.py**: Dependency injection (e.g., auth, db session).
- **core/**:
    - **config.py**: Application settings loading.
    - **logging_config.py**: Logging setup.
    - **schemas.py**: Pydantic models for request/response validation.
    - **services/**: Business logic (ScanService, ChatService, RAGService, SecurityStandardsService).
- **infrastructure/**:
    - **auth/**: Authentication backend (FastAPI Users, JWT).
    - **db/**: Database connection and session management.
    - **llm/**: Clients for LLM providers (OpenAI, Anthropic, etc.).
    - **rag/**: Vector store layer for retrieval-augmented generation (Qdrant only after ADR-008). `base.py` defines the `VectorStore` Protocol + `RAGQueryResult`. `qdrant_store.py` is the singleton impl: Chroma-`where` → Qdrant-`Filter` translator covering `$eq`/`$ne`/`$in`/`$and`/`$or`; deterministic `uuid5` mapping for Chroma-style string ids; init-error log redacts `QDRANT_API_KEY`. `embedder.py` wraps `fastembed.TextEmbedding("sentence-transformers/all-MiniLM-L6-v2")` (vectors byte-equivalent to the prior chromadb-bundled ONNX). `factory.py.get_vector_store()` returns the singleton; `rag_client.py` is a back-compat re-export shim (`get_rag_service` / `RAGService = VectorStore`) preserved to avoid churn at the historic call sites.
    - **agents/**: LangChain agents for specific tasks (Analysis, Remediation).
    - **scanners/**: Deterministic SAST wrappers invoked by the worker graph's `deterministic_prescan_node` — `staging.py` (sandbox the file tree, sanitize basenames), `bandit_runner.py` (Bandit subprocess + Pydantic-allowlisted output), `semgrep_runner.py` (Semgrep CE multi-language coverage with bundled `p/security-audit` rule pack), `gitleaks_runner.py` (secret-scan with strict `RuleID/File/StartLine/Description` allowlist + `--redact`), `osv_runner.py` (OSV-Scanner dependency scan + CycloneDX BOM generation, returns `(List[VulnerabilityFinding], Optional[Dict])`, `source="osv"`), `registry.py` (per-file routing + minified-bundle detection). All four runners share `_resolve_binary` for env-var / PATH / hardcoded-fallback discovery. Non-empty prescan findings route to the `pending_prescan_approval` interrupt gate (ADR-009); Critical Gitleaks findings only reach `blocked_pre_llm` after the operator declines the override modal.
    - **messaging/**: `outbox_sweeper.py` — background task that flushes unpublished `scan_outbox` rows to RabbitMQ. `prescan_approval_sweeper.py` — background task that auto-declines scans stuck at `PENDING_PRESCAN_APPROVAL` for >24 h (transitions to `BLOCKED_USER_DECLINE`, writes `PRESCAN_AUTO_DECLINED` scan event, deletes checkpointer thread). Both are wired into `main.py` lifespan.
    - **observability/**: Optional Langfuse v3 instrumentation (`langfuse-otel-observability` run, 2026-04-26). `mask.py` redacts provider-key patterns / `keyword=value` lines / ≥20-char high-entropy bare strings before any payload reaches Langfuse. `langfuse_client.py` exposes `get_langfuse()`, `get_langchain_handler()`, and `flush_langfuse()` — all fail-open (return `None` / no-op when `LANGFUSE_ENABLED=false`, when keys are missing, or after a latched init failure). `LLMClient.generate_structured_output` wraps Pydantic AI `agent.run` in `start_as_current_span`; `workers/consumer.py` attaches the LangChain CallbackHandler at the parent-trace anchor. `trace_id` / `session_id` both equal `correlation_id_var.get()`.
    - **repositories/**: Data access layer.
    - **workflows/**: LangGraph StateGraph package. `worker_graph.py` contains the StateGraph wiring, routing functions, `get_workflow()`, `close_workflow_resources()`, and back-compat re-exports. `state.py` holds the `WorkerState` / `RelevantAgent` TypedDicts. `nodes/` holds one module per node group: `retrieve.py`, `prescan.py`, `cost.py`, `analyze.py`, `correlate.py`, `consolidate.py`, `results.py`, `error.py`. The string names passed to `workflow.add_node(...)` are part of the LangGraph checkpointer's on-disk contract — in-flight scans key off them; never rename without a checkpointer migration.
- **workers/**:
    - **consumer.py**: Async RabbitMQ consumer (`aio-pika` `connect_robust`, single asyncio event loop). Subscribes to submission / approval / remediation queues with `prefetch_count=1`, runs an idempotency precheck, and `await`s the LangGraph workflow inline (no thread bridge). ACK on success; explicit `reject(requeue=False)` + DB status `FAILED` on poison/error. Resume-payload `kind` is validated against the scan's current gate status before invoking `Command(resume=...)` (M1 / G4). Terminal-scan checkpointer threads are deleted post-workflow via `_maybe_cleanup_checkpointer_thread`.
- **scripts/**: Operator-only admin scripts. NOT importable by routers / MCP tools (CI grep-check at `tests/test_scripts_isolation.py` enforces). Run via `docker compose exec app python -m app.scripts.<module>`. Includes `backfill_findings_source.py` (sets `findings.source = 'agent'` for legacy LLM-emitted rows). The repo-root `scripts/extract_eval_prompts.py` (different directory — top-level `scripts/`, not `app.scripts`) materialises the canonical prompt templates into `evals/agents/*/prompts/*.txt`; CI runs it in `--check` mode on every PR (drift gate).
- **shared/**:
    - **lib/**: Utility modules — `cost_estimation.py` (LiteLLM token + price), `scan_scope.py` (visibility-scope helper), `scan_status.py` (worker status constants), `risk_score.py` (unified CVSS-weighted risk aggregate shared by worker / dashboard / compliance), `agent_routing.py`, `files.py`, `git`, `encryption`.

### Frontend (`secure-code-ui`)
- **src/**:
    - **main.tsx**: React application entry point.
    - **app/**:
        - **App.tsx**: Main component structure.
        - **providers/**: Context providers (Auth, Theme).
        - **styles/**: Global CSS and theme definitions.
    - **features/**:
        - **auth/**: Login forms and logic.
        - **dashboard/**: Main dashboard widgets and layout.
        - **prescan-approval/**: Components for the prescan-approval gate. `PrescanReviewCard.tsx` lists deterministic findings (severity badge, source, file, line, CVE) with Continue / Stop buttons; `CriticalSecretOverrideModal.tsx` is a danger-styled modal that explicitly names the credential rule and the three downstream destinations (LLM provider, Langfuse, Loki) — shown only when a Critical Gitleaks finding is present.
        - **results-display/**: Scan results visualization (FileTree, CodeViewer).
        - **submission-history/**: List of past scans.
        - **submit-code/**: Forms for submitting code/repos.
    - **pages/**:
        - **auth/**: Login page.
        - **submission/**: Project submission flow.
        - **analysis/**: Analysis results view.
        - **admin/**: Administration panels.
    - **shared/**:
        - **api/**: Axios client and API service modules.
        - **components/**: Reusable UI components (Buttons, Cards).
        - **hooks/**: Custom React hooks (useAuth, useToast).
        - **lib/**: Utility functions (severityMappings, formatters). `safeUrl.ts` — `isSafeHttpUrl(u)` guard used when rendering attacker-controlled URLs (e.g. OSV finding `references` and CycloneDX BOM `externalReferences[].url`) as anchor links.
        - **types/**: TypeScript type definitions (API models).
- **Dockerfile**: Docker configuration for the frontend service.
- **vite.config.ts**: Vite build configuration.

## Detailed Scanning Workflow Trace

### 1. Initiation (API Layer)
**Trigger**: User submits a scan request via the UI.
- **File**: `src/app/api/v1/routers/projects.py`
  - **Function**: `create_scan`
  - **Action**: Receives form data (files, repo URL, config) and calls the service.

### 2. Service Layer & Queuing
- **File**: `src/app/core/services/scan_service.py`
  - **Function**: `_process_and_launch_scan` (called by `create_scan_from_*`)
  - **Action**:
    1.  Persists Project, Scan, and CodeSnapshot to DB via `ScanRepository.create_scan`, `ScanRepository.create_code_snapshot`.
    2.  Publishes a message to RabbitMQ (`settings.RABBITMQ_SUBMISSION_QUEUE`) containing the `scan_id`.

### 3. Worker Consumption
- **File**: `src/app/workers/consumer.py`
  - **Function**: `start_worker_consumer` → runs the asyncio event loop; registers `_handle_message` as the aio-pika consumer on the three durable queues (`prefetch_count=1`).
  - **Action**: On message receipt, `_handle_message` deserializes the `scan_id`, sets `correlation_id_var`, and `await`s `_run_workflow_for_scan` inline (no thread bridge, no `run_coroutine_threadsafe`). ACK on success; `reject(requeue=False)` + DB status `FAILED` on error.
  - **Function**: `_run_workflow_for_scan`
  - **Action**: Runs idempotency precheck, then `await`s `worker_workflow.ainvoke` (or `ainvoke(Command(resume=…))` for approval/remediation messages).

### 4. Workflow Execution (The Graph)
**Files**: `src/app/infrastructure/workflows/worker_graph.py` (StateGraph wiring, routing, `get_workflow()`, back-compat re-exports), `workflows/state.py` (`WorkerState` / `RelevantAgent` TypedDicts), `workflows/nodes/` (one module per node group). Source of truth for the trace shape lives in `.agent/scanning_flow.md` Phase 5; the node list below mirrors it.

#### Node A: `retrieve_and_prepare_data`
- **Goal**: Build context for the scan.
- **Action**: Fetches `Scan` from DB; runs `RepositoryMappingEngine.create_map` (tree-sitter symbol index) + `ContextBundlingEngine` (NetworkX dep graph); resolves the agent set from the selected frameworks.

#### Node B: `deterministic_prescan`
- **Goal**: Multi-scanner SAST fan-out (Bandit + Semgrep CE + Gitleaks subprocesses) before any LLM cost is incurred.
- **Action**: Seeds `WorkerState.findings` with `source="bandit"/"semgrep"/"gitleaks"` rows under a single `asyncio.Semaphore(CONCURRENT_SCANNER_LIMIT=5)`. Per-scanner failure is non-fatal. **A Critical Gitleaks finding short-circuits the graph to `blocked_pre_llm` (terminal)** — no LLM spend.

#### Node B-terminal: `blocked_pre_llm`
- **Goal**: Hard-stop on credential leak found pre-LLM.
- **Action**: Sets `Scan.status = STATUS_BLOCKED_PRE_LLM` and routes to END.

#### Node C: `estimate_cost` (interrupt)
- **Goal**: Token-count + price the upcoming LLM analysis; pause for user approval.
- **Action**: Counts tokens via `litellm.token_counter`, prices via `litellm.cost_per_token` (or per-`LLMConfiguration` admin override), persists, sets status `PENDING_COST_APPROVAL`, then native `interrupt()` — graph state is serialized into the Postgres checkpointer.

#### Node D: `analyze_files_parallel`
- **Goal**: Single-pass parallel LLM analysis.
- **Action**: Runs every relevant agent (resolved via `resolve_agents_for_file`) against every file from the `ORIGINAL_SUBMISSION` snapshot in parallel, bounded by `asyncio.Semaphore(CONCURRENT_LLM_LIMIT=5)`. Per-file dependency context injected via `build_dep_summary`. RAG retrieval inside this node goes through `app.infrastructure.rag.factory.get_vector_store()` (Qdrant after ADR-008).

#### Node E: `correlate_findings`
- **Goal**: Deduplicate.
- **Action**: Groups findings by `(file_path, cwe, line_number)`; merges duplicates into the highest-severity row with `corroborating_agents` populated.

#### Node F: `consolidate_and_patch` (REMEDIATE only)
- **Goal**: Merge and syntax-verify proposed fixes.
- **Action**: Groups `proposed_fixes` by file, resolves line-range conflicts via `_run_merge_agent` (**Reasoning LLM**), tree-sitter syntax-verifies patched content, builds `final_file_map` for the `POST_REMEDIATION` snapshot. No-op for AUDIT/SUGGEST.

#### Node G: `save_results`
- **Goal**: Persistence.
- **Action**: Bulk-inserts correlated findings; persists the `POST_REMEDIATION` snapshot for REMEDIATE scans.

#### Node H: `save_final_report`
- **Goal**: Finalize scan.
- **Action**: Computes the CVSS-weighted 0–10 `risk_score` via `app.shared.lib.risk_score.compute_cvss_aggregate`, persists `summary` JSON, sets final status `COMPLETED` / `REMEDIATION_COMPLETED`.

### 5. LLM Roles Summary
- **Utility LLM**: Used for symbol-mapping / lightweight calls (`SymbolMapAgent` and similar). Configured per-scan via `Scan.utility_llm_config_id`.
- **Reasoning LLM**: Used in `generic_specialized_agent.py` (Analysis), `worker_graph.py` (Conflict Merging via `_run_merge_agent`). Configured per-scan via `Scan.reasoning_llm_config_id`.

When `LANGFUSE_ENABLED=true`, every LLM call from both tiers becomes a child span under a per-scan parent trace in Langfuse. The parent trace `id` equals the `X-Correlation-ID` (= `correlation_id_var.get()`) so logs in Loki and traces in Langfuse cross-reference cleanly. SCCAP `cost_estimation.calculate_actual_cost` remains the authoritative cost source; LiteLLM's Langfuse `success_callback` is intentionally NOT enabled to avoid double-counting.

> The Fast LLM tier was removed in 2026-04-26 (`/sccap remove-fast-llm-tier`) — the slot was reserved but never wired. If a third tier is needed in future (e.g. dedicated triage / dep-summarization model), ship as a new feature with a fresh migration + admin UI.
