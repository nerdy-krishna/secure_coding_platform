---
sidebar_position: 5
title: Updating Framework Knowledge
---

# Updating Framework Knowledge

Every framework's knowledge base lives in the `security_guidelines`
Chroma collection, tagged with `framework_name` metadata. Admins
can refresh a framework (replace its docs) or add new frameworks.
Both paths go through the same ingestion pipeline.

## Ingest modes

### CSV (ASVS-style frameworks)

1. Go to **Admin → Frameworks** → click the target framework →
   **Ingest docs** → **CSV**.
2. Upload a CSV with the columns:
   - `control_id`
   - `title`
   - `content`
   - `framework_name` (should match the framework's name)
3. Hit **Start ingestion**. A `rag_jobs` row tracks progress.
4. The pipeline chunks long `content` values, embeds each chunk,
   and writes to Chroma with the framework metadata intact.

### Git URL (Proactive Controls, Cheatsheets, most custom)

1. Go to **Admin → Frameworks** → click the target framework →
   **Ingest docs** → **Git URL**.
2. Paste a public Git URL (the repo where the framework's docs
   live).
3. Hit **Start ingestion**. `rag_preprocessor_service` clones the
   repo, walks markdown files, chunks them, embeds, and writes.

## What re-ingestion does

Re-ingesting a framework **replaces** its existing docs:

1. Delete every Chroma row tagged with that `framework_name`.
2. Insert the freshly ingested ones.
3. Bump the framework's `updated_at` column.

Result: it's idempotent. Re-running the same ingestion leaves the
collection in the same shape.

## Adding a brand-new framework

**Admin → Frameworks → New framework**:

1. Short lowercase `name` (becomes the metadata tag).
2. Description (shown on the framework card).
3. Optionally run ingestion now — or leave empty and ingest later.
4. Map the agents that should run when a scan picks this
   framework.

## Background job + status

Ingestion runs in-process for now (no separate worker container).
The UI shows a spinner + the `rag_jobs` row's progress percentage.
Large Git repos (hundreds of files) can take a couple of minutes.

## Sanity-checking

After ingestion, open **Admin → RAG** (or the framework card on the
Compliance page) to see the new document count. Start a chat
session scoped to the framework and ask a targeted question —
the Advisor should pull the fresh docs into the prompt.

## Removing a framework

Deleting a framework row from **Admin → Frameworks**:

- Removes the framework from the submit picker + Compliance grid.
- **Leaves** existing `scans.frameworks` tags in place (history
  survives).
- **Leaves** the Chroma docs — the orphan `framework_name` rows get
  filtered out of future retrievals since no session selects that
  framework anymore. Run **Admin → RAG → Prune orphans** to fully
  clean up.
