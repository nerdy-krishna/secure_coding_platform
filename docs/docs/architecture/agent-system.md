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
`StateGraph`. The main branches keyed on `scan.status`:

1. `QUEUED` → audit-and-estimate path
2. `QUEUED_FOR_SCAN` → deep-analysis path (resumed after approval)
3. `REMEDIATION_TRIGGERED` → remediation path

### Audit path

`retrieve_and_prepare_data` → builds the `RepositoryMappingEngine` +
`ContextBundlingEngine` dependency graph → `estimate_cost` computes
projected token + dollar cost and sets status to
`PENDING_COST_APPROVAL` → calls `interrupt()` → graph pauses with
full state in the checkpointer. The API remains free to poll
`/scans/{id}` or stream `/scans/{id}/stream` for status changes.

### Deep analysis path

`triage_agents` decides which specialized agents to run →
`dependency_aware_analysis_orchestrator` walks the dependency graph in
topological order. For each file it:

1. Chunks the file with `shared/analysis_tools/chunker.py` (semantic
   split; keeps function + class bodies intact).
2. Fans out chunks to the **triaged specialized agents** — the
   orchestrator bounds concurrency with a semaphore keyed on
   `CONCURRENT_LLM_LIMIT` (default 5) so LLM rate limits aren't
   blown during large scans.
3. Collects per-chunk findings, dedupes, correlates cross-file
   references, and streams results back into the graph state.

`correlate_findings` → `save_results` → `run_impact_reporting` →
`save_final_report` wraps up.

### Remediation path

Runs for `REMEDIATE`-type scans. The orchestrator applies fixes
**incrementally** (one finding at a time, not a big-bang patch) and
runs a dedicated merge agent to resolve conflicts when multiple fixes
touch the same file. The final patched tree is written as a
`POST_REMEDIATION` snapshot so users can diff against the
`ORIGINAL_SUBMISSION`.

## Specialized agents

Specialized agents live under `src/app/infrastructure/agents/`. The
important ones:

- **`generic_specialized_agent`** — parameterized per finding type;
  the workhorse called by the orchestrator. Takes a chunk + a
  finding-type prompt template, calls the LLM, returns a validated
  Pydantic model.
- **`impact_reporting_agent`** — takes the full list of findings and
  produces the executive summary's impact analysis (for the PDF +
  Admin views).
- **`chat_agent`** — one-shot LLM call used by the Advisor. Runs RAG
  retrieval scoped to the session's `frameworks`, injects the docs
  into the prompt, and returns a response + usage metadata.
- **`symbol_map_agent`** — builds the repo-map symbol index used by
  `ContextBundlingEngine`.

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
