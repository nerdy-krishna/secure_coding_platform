---
title: Agent System
sidebar_position: 2
---

# Agent System

SCCAP builds on **LangGraph 1.x** — every long-running workflow is a
compiled `StateGraph` whose state is persisted per scan in the
Postgres checkpointer. This gives us durable pauses (the cost
approval gate is a native `interrupt()` + `Command(resume=...)`),
clean step-level retries, and structured parallelism.

## Top-level graph

`src/app/infrastructure/workflows/worker_graph.py` defines the scan
`StateGraph`. The wired flow is:

```
retrieve_and_prepare_data
  → estimate_cost            (interrupt → resume via Command)
  → analyze_files_parallel
  → correlate_findings
  → consolidate_and_patch    (no-op for AUDIT / SUGGEST)
  → save_results
  → save_final_report → END
```

`handle_error` is reachable from every node via `should_continue`
conditional edges and sets status `FAILED`.

### Audit pass

`retrieve_and_prepare_data` → builds the `RepositoryMappingEngine` +
`ContextBundlingEngine` dependency graph → `estimate_cost` computes
projected token + dollar cost via LiteLLM, sets status to
`PENDING_COST_APPROVAL`, and calls `interrupt()`. The graph pauses
with full state in the checkpointer; the UI polls `/scans/{id}` or
streams `/scans/{id}/stream` for status changes.

### Single-pass parallel analysis

When the user approves, the worker resumes the **same** thread with
`Command(resume=...)` and execution falls through to
`analyze_files_parallel`. Key properties:

- **No topological ordering, no cross-file patch propagation.** Every
  agent sees the original code from the `ORIGINAL_SUBMISSION`
  snapshot.
- **Per-file agent triage is inline** via
  `resolve_agents_for_file(file_path, all_relevant_agents)` —
  extension-based routing, not a separate LLM triage node.
- **Per-file dependency context** is injected from the repository
  map: `build_dep_summary(file_path)` reads symbol signatures from
  successors in the dependency graph and prefixes each chunk with a
  `# --- [DEPENDENCY CONTEXT] ---` block.
- **Concurrency** is a single `asyncio.Semaphore(CONCURRENT_LLM_LIMIT)`
  (default 5) over the union of file × chunk × agent calls.
- **No mid-graph DB writes.** Findings + `proposed_fixes` flow through
  state to `consolidate_and_patch` and `save_results`.

### Correlation + remediation

`correlate_findings` groups duplicate findings by
`(file_path, CWE, line_number)` and merges agent corroborations.
`consolidate_and_patch` is REMEDIATE-only: groups `proposed_fixes`
by file, resolves line-range conflicts via `_run_merge_agent`,
tree-sitter syntax-verifies the patched content, and builds
`final_file_map` for the `POST_REMEDIATION` snapshot. AUDIT is a
no-op; SUGGEST keeps the embedded `fixes` field on each finding but
doesn't build a snapshot.

`save_results` persists everything; `save_final_report` writes the
coarse 0–10 severity-bucket `risk_score` and the `summary` JSON, and
sets the final status (`COMPLETED` or `REMEDIATION_COMPLETED`).

## Specialized agents

Specialized agents live under `src/app/infrastructure/agents/`:

- **`generic_specialized_agent`** — parameterized per finding type;
  the workhorse called by `analyze_files_parallel`. Takes a chunk +
  a finding-type prompt template, calls the LLM, returns a
  validated Pydantic model.
- **`chat_agent`** — one-shot LLM call used by the Advisor. Runs RAG
  retrieval scoped to the session's `frameworks`, injects the docs
  into the prompt, and returns a response + usage metadata.
- **`symbol_map_agent`** — builds the repo-map symbol index used by
  `ContextBundlingEngine`.

Impact-summary and SARIF generation were removed in the
2026-04-26 cleanup (the impact-reporting node was registered but
never wired into the graph). Re-introducing them is a future
work item; the existing `save_final_report` is the right insertion
point for an additional reporting node.

## Structured output with Pydantic AI

As of Phase I.3 every structured-output call routes through
`llm_client.generate_structured_output`, which wraps Pydantic AI:

- The call site declares a `ResponseModel` (a Pydantic class).
- Pydantic AI dispatches the LLM call, validates the response, and —
  if validation fails — retries with a typed error message inside the
  same call. The call site receives either a `parsed_output: Model` or
  an `error` field.
- On LangChain 1.x the underlying request uses
  `ChatModel.with_structured_output(ToolStrategy(Model))`. The
  provider-specific JSON-mode conditionals + regex fallbacks from the
  0.3.x era are gone.

## Token + cost accounting

`TokenUsageCallbackHandler` (in `src/app/infrastructure/llm_client.py`)
reads the standardized `response.usage_metadata` field added in
LangChain 1.x — one path for all providers, no per-provider
branches. Counts are persisted on every `llm_interaction` row.

Pre-call estimation and post-call exact cost both run through
LiteLLM; see
[Architecture → LLM Integration](./llm-integration.md) for the full
data flow.

## Observability of agents

Every LLM call writes one `llm_interaction` row with:

- `agent_name`
- `prompt_template_name` + `prompt_context` (JSONB — the exact
  variables fed to `.format(...)`)
- `raw_response` (full text) + `parsed_output` (structured, if valid)
- `input_tokens` / `output_tokens` / `total_tokens`
- `cost`
- `timestamp` (with the request's correlation id attached to every
  log line)

Admins can replay any step from Admin → LLM Interactions for a given
scan, which is invaluable for debugging agent drift.
