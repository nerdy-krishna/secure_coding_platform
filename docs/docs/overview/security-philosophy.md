---
title: Security Philosophy
sidebar_position: 3
---

# Security Philosophy

SCCAP is built around one principle: **audit first, remediate
intelligently**. Every core design decision — the two-phase scan
workflow, the encrypted secret store, the scoped visibility filter,
the checkpointed workflow — follows from applying that principle to
both the scanned code and the scanning platform itself.

## Audit before you spend

Large-model calls are expensive and non-deterministic. SCCAP inserts a
mandatory checkpoint between "we've looked at your code" and "we've
run the deep analysis":

1. The API accepts a scan submission and enqueues a message on
   `code_submission_queue`.
2. The worker pulls the message and runs a cheap *audit* pass
   (`RepositoryMappingEngine` + `ContextBundlingEngine`) to build a
   symbol index and dependency graph.
3. An `estimate_cost` node computes the projected token + dollar cost
   for the deep analysis, persists it as `cost_details`, sets the scan
   status to `PENDING_COST_APPROVAL`, and calls LangGraph's native
   `interrupt()` — the workflow is now paused, with its state
   serialized into the Postgres checkpointer keyed on `scan_id`.
4. The UI shows the estimate. The user approves, cancels, or walks
   away.
5. On approve, the API publishes to `analysis_approved_queue`; the
   worker resumes the **same** LangGraph thread with
   `Command(resume=payload)` and runs the deep analysis.

Nothing expensive runs without an explicit human yes. Nothing is lost
if the worker restarts between the estimate and the approval.

## Trust but verify

SCCAP uses LLMs for **finding** vulnerabilities, not for **gating**
anything. Every LLM-driven decision is written into
`llm_interactions` (prompt context, parsed output, cost,
correlation id) so admins can replay every step via the Admin → Logs
viewer. Structured outputs go through Pydantic AI, which validates the
response against a typed model and retries on malformed JSON instead
of silently falling back to regex parsing.

## Scoped visibility by default

A regular user sees their own scans plus scans owned by anyone they
share a **User Group** with. Admins see everything. The filter is a
single helper (`scan_scope.visible_user_ids(user, repo)`) that returns
`None` for admins or `[user.id, ...peers]` for regular users. Every
list endpoint that could leak data takes this list and passes it
through to the repository layer — so the surface area of "could forget
to filter" is one helper, not dozens.

## Encrypted secrets

Every LLM API key and SMTP password is **Fernet-encrypted at rest**
with the installation's `ENCRYPTION_KEY`. The key never leaves the
container; neither the UI nor the logs ever surface a decrypted
secret.

- `llm_configurations.encrypted_api_key` — the provider credential
  admins enter in the `/admin/llm` settings page.
- `system_config` rows with `is_secret: true` — currently holds the
  SMTP password.

`.env.example` deliberately does **not** include `OPENAI_API_KEY` /
`GOOGLE_API_KEY` placeholders (H.0.2) — all provider credentials live
in the database, not on the filesystem.

## Correlated observability

Every request entering the API gets an `X-Correlation-ID`
(`correlation_id_middleware` in `main.py`). The ID is propagated via a
`ContextVar` and attached to every log entry, every LLM interaction
row, and every worker message so a single scan can be followed across
services in Grafana + Loki without grep-archaeology.

## Safe automation

The `DynamicCORSMiddleware` tightens once setup completes: before the
first superuser finishes `/setup`, it allows all origins (so the UI
can reach the API wherever the operator hosts it); after setup, it
only allows origins from the `security.allowed_origins` system_config
row plus `ALLOWED_ORIGINS` env. MCP tools reuse this same middleware
plus the same JWT auth — there's no separate "agent" auth surface to
misconfigure.
