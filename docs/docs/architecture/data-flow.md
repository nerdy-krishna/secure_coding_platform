---
title: Data Flow
sidebar_position: 5
---

# Data Flow

This page is the narrative version of
[`.agent/scanning_flow.md`](https://github.com/nerdy-krishna/ai-secure-coding-compliance-platform/blob/main/.agent/scanning_flow.md).
Code references inside the repo — `worker_graph.py`,
`scan_service.py`, `consumer.py` — are authoritative; this page is a
pointer-heavy summary.

## Scan lifecycle

### 1. Submit (API)

- UI posts to `POST /api/v1/scans` with files / git URL / archive +
  framework selection + per-slot LLM ids.
- `projects.py` router → `scan_service.create_scan_from_uploads`
  (or `from_git` / `from_archive`) dedupes files by hash, creates
  the `Scan` row + an `ORIGINAL_SUBMISSION` code snapshot, and
  inserts a row into `scan_outbox` targeting
  `code_submission_queue`. All in one transaction.
- Response: `{ scan_id, project_id, message }`.

### 2. Outbox sweep

- `outbox_sweeper` (background task on the API) reads unpublished
  rows older than 30 s and publishes them to RabbitMQ with
  exponential backoff on `attempts`. If the broker is down when the
  API transaction commits, the scan is **still safely enqueued** —
  the sweeper catches it when RabbitMQ comes back.

### 3. Worker pickup

- `workers/consumer.py` pulls the message, builds a `WorkerState`,
  and invokes the compiled LangGraph with a Postgres-backed
  `AsyncPostgresSaver` checkpointer keyed on `scan_id`.
- Status transitions are written as `ScanEvent` rows so the UI can
  subscribe to `/scans/{id}/stream` (SSE) and paint a live progress
  rail.

### 4. Audit pass (LangGraph path A)

`retrieve_and_prepare_data` →
`RepositoryMappingEngine` + `ContextBundlingEngine` → `estimate_cost`:

- Tree-sitter builds a symbol index for every file.
- The dependency graph bundles import chains so specialized agents
  see the right cross-file context later.
- Cost estimation tokenizes the full prompt set with
  `litellm.token_counter` and prices it against
  `litellm.cost_per_token` (honoring any per-`LLMConfiguration`
  override).
- `cost_details` is persisted, status flips to
  `PENDING_COST_APPROVAL`, and the node calls **`interrupt()`** with
  the estimate payload. LangGraph serializes state into the
  checkpointer and **the graph pauses**.

### 5. User approves (or cancels)

- UI shows the estimate. The user:
  - **Approves** → API publishes to `analysis_approved_queue`; the
    worker invokes the same LangGraph thread with
    `Command(resume=payload)`. The graph continues from where it
    paused.
  - **Cancels** → `scan_service.cancel_scan` sets status
    `CANCELLED`; the checkpointer state is left in place so admins
    can inspect it.

### 6. Single-pass parallel analysis

`analyze_files_parallel`:

- Every relevant agent runs against every file from the
  `ORIGINAL_SUBMISSION` snapshot in parallel — **no topological
  ordering, no cross-file patch propagation**. The dependency graph
  is still consulted to inject per-file dependency context
  (symbol signatures from successors) into each chunk's prompt.
- Per-file agent triage happens inline via
  `resolve_agents_for_file(file_path, all_relevant_agents)` —
  extension-based routing.
- Files larger than `CHUNK_ONLY_IF_LARGER_THAN` (~150 000 chars) are
  split with `semantic_chunker`; small files run as a single chunk.
- Concurrency is bounded by a single
  `asyncio.Semaphore(CONCURRENT_LLM_LIMIT=5)` over the union of
  file × chunk × agent calls.
- No mid-graph DB writes. Findings + `proposed_fixes` flow through
  state to `consolidate_and_patch` and `save_results`.

`correlate_findings` groups duplicates by
`(file_path, CWE, line_number)` and merges agent corroborations.

### 7. Remediation (REMEDIATE only)

`consolidate_and_patch` runs after `correlate_findings`:

- Groups `proposed_fixes` by file.
- Detects line-range conflicts and runs `_run_merge_agent` to
  resolve overlaps.
- Tree-sitter syntax-verifies the patched content
  (`_verify_syntax_with_treesitter`).
- Builds `final_file_map` for the `POST_REMEDIATION` snapshot saved
  by `save_results_node`, so users can diff against the
  `ORIGINAL_SUBMISSION`.

For AUDIT it's a no-op. For SUGGEST the correlated findings keep
their embedded `fixes` field (so the UI shows suggested fixes) but
no `POST_REMEDIATION` snapshot is built.

### 8. Final report

`save_final_report`:

- Computes a coarse 0–10 `risk_score` from the highest non-zero
  severity bucket (`CRITICAL → 9+`, `HIGH → 7+`, `MEDIUM → 4+`,
  `LOW → 1+`).
- Persists the `summary` JSON.
- Sets final status `COMPLETED` or `REMEDIATION_COMPLETED`.

Note: this `Scan.risk_score` is **not** the same as the Dashboard /
Compliance posture score. The dashboard uses a weighted-findings
heuristic (`critical*15 + high*6 + medium*2 + low*1`, clamped to
[5, 100]) across the visibility scope.

## Chat (Advisor) flow

1. `POST /chat/sessions` creates a session with a title, LLM config
   id, optional project id, and framework list.
2. `POST /chat/sessions/{id}/ask` calls `chat_service.post_message_to_session`:
   - Persist the user message.
   - Load full history (or a summary, if the session has been
     compacted).
   - Call `chat_agent.generate_response` → RAG retrieval scoped to
     the session's frameworks via
     `rag_service.query_guidelines(where={"framework_name": {"$in": [...]}})`
     → LLM call → Pydantic AI validation.
   - Persist the assistant message + link to its `llm_interaction`
     row.
3. `GET /chat/sessions/{id}/context` aggregates the right-rail feed:
   session frameworks as knowledge sources, plus the top-severity
   findings + file paths from the linked project's latest terminal
   scan.

## Observability

Every step above writes at least one log line carrying the request's
`X-Correlation-ID`, and every LLM call writes an `llm_interaction`
row with the exact prompt_context + usage + cost. Scans can be
replayed via Admin → LLM Interactions; logs can be traced via
Grafana → Loki with the correlation id.

## Queue names

Wired from `src/app/config/config.py`:

- `RABBITMQ_SUBMISSION_QUEUE` → `code_submission_queue`
- `RABBITMQ_APPROVAL_QUEUE` → `analysis_approved_queue`
- `RABBITMQ_REMEDIATION_QUEUE` → `remediation_trigger_queue`

## Status strings

Canonical values live at the top of
`src/app/shared/lib/scan_status.py`:

`QUEUED`, `PENDING_COST_APPROVAL`, `QUEUED_FOR_SCAN`,
`ANALYZING_CONTEXT`, `RUNNING_AGENTS`, `GENERATING_REPORTS`,
`COMPLETED`, `REMEDIATION_COMPLETED`, `FAILED`, `CANCELLED`.

`ACTIVE_SCAN_STATUSES` and `COMPLETED_SCAN_STATUSES` tuples are
exported for the filters used across services. (The
`GENERATING_REPORTS` constant is preserved for tuple membership +
future re-introduction of an impact / SARIF reporting node, but no
node sets that status today.)
