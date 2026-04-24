---
sidebar_position: 1
title: Guideline-backed Q&A
---

# Guideline-backed Q&A (Security Advisor)

The **Security Advisor** (`/advisor`) is a framework-scoped chat
interface backed by RAG retrieval + your project's actual findings.
Use it to ask questions about a specific vulnerability, get
framework mapping, or walk a teammate through a scan result.

## Creating a session

Click **New chat** in the left rail:

1. **Title** — short label, searchable later.
2. **LLM config** — pick any registered `LLMConfiguration`. The
   session stays on this model for its lifetime.
3. **Frameworks** — multi-select, drives the RAG retrieval filter
   for every turn in this session.
4. **Project** (optional) — link the session to a specific project
   so the right-hand context rail can surface the latest scan's
   findings + files.

Once created, the session appears in the left rail grouped by
Today / Yesterday / Older.

## Ask a question

Type in the composer and hit Enter. The backend:

1. Persists your message.
2. Loads session history.
3. Runs RAG retrieval scoped to the session's frameworks:
   `rag_service.query_guidelines(query_texts=[question], n_results=5,
   where={"framework_name": {"$in": frameworks}})`.
4. Feeds both the retrieved docs and the history into the
   `chat_agent` prompt.
5. Validates the response via Pydantic AI and persists the
   assistant's message.

Quick-reply chips under the composer are UX shortcuts for common
prompts ("Explain this finding", "Map findings to SOC 2",
"Summarize the scan"). They're not mock data — they're just
pre-canned question strings.

## The context rail

The right-hand rail is populated from
`GET /api/v1/chat/sessions/{session_id}/context`:

- **Knowledge sources** — the session's frameworks, labelled as
  type `framework`. Authoritative (set at session creation).
- **Referenced findings** — from the linked project's latest
  terminal scan, severity-ordered (critical → low), capped at 8.
  The right-rail tile shows the finding title + a severity swatch.
- **Referenced files** — distinct file paths from those findings,
  capped at 8.

The chat agent logs RAG-retrieval length (not the retrieved
documents themselves), so the rail uses the latest-scan rollup as a
faithful substitute until the agent starts recording per-turn
references.

## Session scope vs. visibility

A session is owned by the user who created it. The user's
visibility scope still applies when the rail pulls findings — if
the session is linked to a project you no longer have visibility
into, the rail silently shows empty lists.

## Deleting a session

The chevron next to a session in the left rail exposes **Delete**.
This removes the session, every message, and breaks the link to any
`llm_interactions` rows (the interactions themselves stay for
audit).
