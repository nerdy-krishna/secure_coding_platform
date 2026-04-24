---
sidebar_position: 8
title: Roadmap
---

# Roadmap

The short list of things we want to ship next, in rough priority
order. Nothing here is a promise — priorities shift as real users
push on the platform.

## Near-term

- **Test-validated remediation** — detect the project's test
  runner, apply each selected fix, run existing tests against the
  patched code, and roll back fixes that break tests. Replaces the
  "download the patched tree and run tests yourself" step. Tracked
  under
  [Unit Test Integration](./user-guide/unit-test-integration.md).
- **Postgres full-text search** — the global search today is
  per-column ILIKE (fast enough on small datasets, trivially
  extendable). Once someone hits a scale wall we'll swap in tsvector
  + trigram indexes.
- **Per-project stat rollups beyond the latest scan** — the
  Projects card currently reflects the latest terminal scan.
  Adding a rolling 30-day view is straightforward now that the
  scope filter is threaded through.
- **Additional MCP tools** — the v1 surface covers scan + advisor.
  Candidate extensions: compliance stats, RAG ingestion triggers,
  group membership queries (read-only). Admin-side tools stay
  REST-only.

## Medium-term

- **Finding lifecycle (acknowledge / dismiss / suppress)** — a
  formal state machine per finding. Today a finding is either
  open or applied-in-remediation; dismissing a false positive
  requires re-scanning. Needs a small schema migration + UI.
- **Keyboard-first Advisor** — the chat is mouse-friendly already;
  a single-keystroke shortcut overlay + Ctrl-K-style open would
  make it sticky for power users.
- **Finding-to-chat handoff** — "ask the Advisor about this
  finding" on the Results page, pre-populating the session context
  + the initial question.
- **Extended language coverage** for specialized agents — the
  Python / JavaScript / TypeScript / Go paths are mature; Ruby /
  C# / Rust / Kotlin need love.

## Longer-term

- **CI / CD integration** — a GitHub Action + GitLab CI template
  that submits a scan per PR and comments on new findings. Needs
  an API-token auth path (today the CLI assumes a user JWT).
- **Multi-tenant mode** — true org-level separation with billing
  aggregation, SSO, and org-level admin. The User Groups data
  model (H.2) is the first step; full multi-tenant adds a
  separate `Organization` layer above it.
- **Compliance evidence export** — per-framework PDF / CSV export
  with finding → control mapping for audit teams.

## Done recently (Phase G → H → I)

- User Groups + scan-scope filter (H.2).
- Live dashboard driven by `/dashboard/stats` (H.3).
- Per-project stats on Projects grid (H.4).
- Global search across projects / scans / findings (H.5).
- Advisor context rail backed by
  `/chat/sessions/{id}/context` (H.6).
- LangGraph 1.x + LangChain 1.x migration with native
  `interrupt()` + `Command(resume=...)` (I.1).
- LiteLLM-backed token counting + cost estimation with per-config
  admin override (I.2).
- Pydantic AI structured output with per-call validation retry
  (I.3).
- FastMCP server exposing scan + advisor workflow as MCP tools
  (I.4).

Anything you'd like bumped up the list? Open an issue or a
discussion.
