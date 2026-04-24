---
title: Architecture Overview
sidebar_position: 1
---

# Architecture Overview

SCCAP runs as a small compose stack: an API service, a worker, the
data stores the two share, and an observability pipeline.

```
┌──────────┐       ┌─────────┐       ┌─────────┐
│   UI     │  ◄─►  │   API   │  ◄─►  │ Postgres│
│ (Vite)   │       │(FastAPI)│       └─────────┘
└──────────┘       └────┬────┘       ┌─────────┐
                        │       ◄─►  │  Chroma │
                        ▼            └─────────┘
                   ┌─────────┐
                   │RabbitMQ │
                   └────┬────┘
                        │
                        ▼
                   ┌─────────┐       ┌────────────────────┐
                   │ Worker  │  ───► │ Fluentd → Loki →   │
                   │(LangGr.)│       │ Grafana            │
                   └─────────┘       └────────────────────┘
```

## Responsibilities

- **API (`app`)** — FastAPI routers under `src/app/api/v1/routers/`.
  Handles auth, admin CRUD, scan submissions, scan result lookups,
  chat sessions, and the MCP tool surface. Writes scan rows +
  outbox rows in a single transaction; never publishes to RabbitMQ
  inline.
- **Worker (`worker`)** — consumes `code_submission_queue`,
  `analysis_approved_queue`, and `remediation_trigger_queue` via
  the blocking `pika` client. Every message invokes the compiled
  LangGraph (`infrastructure/workflows/worker_graph.py`) keyed on
  `scan_id` via an `AsyncPostgresSaver` checkpointer.
- **Outbox sweeper** — a background task inside the API (see
  `src/app/infrastructure/messaging/outbox_sweeper.py`) periodically
  reads `scan_outbox` for unpublished rows and actually publishes them
  to RabbitMQ. This closes the race between "scan row committed" and
  "RabbitMQ publish failed."
- **Postgres** — authoritative store for everything SCCAP writes,
  including the LangGraph checkpoint tables (`checkpoints`,
  `checkpoint_writes`, `checkpoint_blobs`, `checkpoint_migrations`)
  managed by the Postgres checkpointer.
- **ChromaDB** — vector store for RAG. Uses the bundled ONNX
  embedder (lazy-downloaded on first use); framework-scoped via
  metadata filters.
- **Fluentd → Loki → Grafana** — structured log aggregation.

## Code layout (backend)

- `src/app/api/v1/routers/` — FastAPI routers; wired in `main.py`.
  Admin endpoints are split by concern (`admin_agents`,
  `admin_frameworks`, `admin_prompts`, `admin_rag`, `admin_config`,
  `admin_users`, `admin_groups`, `admin_seed`, `llm_config`).
- `src/app/core/services/` — orchestration layer. Routers delegate
  here rather than touching repositories directly.
- `src/app/infrastructure/database/repositories/` — one repository
  per aggregate: `scan_repo`, `chat_repo`, `user_repo`,
  `framework_repo`, `agent_repo`, `prompt_template_repo`,
  `llm_config_repo`, `rag_job_repo`, `system_config_repo`,
  `user_group_repo`.
- `src/app/infrastructure/agents/` — LangGraph sub-graphs
  (`generic_specialized_agent`, `impact_reporting_agent`,
  `chat_agent`, `symbol_map_agent`).
- `src/app/infrastructure/workflows/worker_graph.py` — the top-level
  LangGraph `StateGraph`. Any edit to nodes / edges must be reflected
  in `.agent/scanning_flow.md`.
- `src/app/shared/analysis_tools/` — `chunker.py` (semantic
  splitter), `context_bundler.py` (dependency graph), `repository_map.py`
  (tree-sitter symbol index).

## Cross-cutting services

- **`SystemConfigCache`** (`src/app/core/config_cache.py`) — a
  process-local singleton populated at startup from `system_config`
  rows. Drives the dynamic CORS middleware, log level, and SMTP
  settings. When editing `system_config` at runtime, the cache is
  also updated or the change won't take effect until restart.
- **`correlation_id_middleware`** — attaches an `X-Correlation-ID`
  to every inbound request and stores it in a `ContextVar` so all
  log entries automatically carry it.
- **`DynamicCORSMiddleware`** — allows all origins until setup
  completes, then tightens to
  `system_config['security.allowed_origins']` + env `ALLOWED_ORIGINS`.
- **`correlation_id_var`** — propagated into the worker via the
  message envelope; worker logs stitch across the boundary.

## Scan lifecycle (short form)

Full flow: see
[Architecture → Data Flow](./data-flow.md) or
[`.agent/scanning_flow.md`](https://github.com/nerdy-krishna/ai-secure-coding-compliance-platform/blob/main/.agent/scanning_flow.md)
for the canonical version.

1. UI `POST /api/v1/scans` → `projects.py` router →
   `scan_service.create_scan_from_*` dedupes files, creates `Scan` +
   `ORIGINAL_SUBMISSION` snapshot, writes an outbox row to
   `code_submission_queue`.
2. Worker picks up the message, builds a `WorkerState`, and calls the
   compiled LangGraph with the Postgres checkpointer.
3. Audit pass: `retrieve_and_prepare_data` → `RepositoryMappingEngine`
   + `ContextBundlingEngine` → `estimate_cost` → status
   `PENDING_COST_APPROVAL` → native `interrupt()` (graph pauses,
   state is checkpointed).
4. User approves: API publishes to `analysis_approved_queue`; worker
   resumes the same thread with `Command(resume=payload)`.
5. Deep analysis: `triage_agents` →
   `dependency_aware_analysis_orchestrator` (topological order,
   per-file chunking + triaged specialized agents, concurrent under
   `CONCURRENT_LLM_LIMIT=5`) → `correlate_findings` → `save_results`
   → `run_impact_reporting` → `save_final_report`.
6. For `REMEDIATE` scans the orchestrator applies fixes incrementally
   and resolves conflicts via a merge agent, then writes a
   `POST_REMEDIATION` snapshot.
