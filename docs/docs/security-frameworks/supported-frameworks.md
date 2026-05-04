---
sidebar_position: 2
title: Supported Frameworks
---

# Supported Frameworks

SCCAP ships with three baseline OWASP frameworks. The auto-seed
service (`default_seed_service.seed_defaults`) inserts them on a
fresh install; admins can re-seed them at any time via
**Admin → Frameworks → Restore defaults**.

## Defaults

### OWASP ASVS (`asvs`)

Application Security Verification Standard — the most comprehensive
of the three. Best for audit-style scans where you want every
control checked.

- **Ingestion mode**: CSV. The admin uploads a CSV with one row per
  requirement and the columns `control_id`, `title`, `content`,
  `framework_name`.
- **Typical use**: compliance reports, full-coverage audits.
- **RAG scope**: hundreds of rows; chunked into a few hundred
  vector-store entries.

### OWASP Proactive Controls (`proactive_controls`)

Developer-focused C1–C10 practices. Excellent chat context for the
Advisor.

- **Ingestion mode**: Git URL. The admin pastes the repo URL; the
  `rag_preprocessor_service` clones the tree, walks markdown, and
  chunks.
- **Typical use**: code-review guidance, secure-coding Q&A.

### OWASP Cheatsheets (`cheatsheets`)

Topic-specific guidance (SQL injection, XSS, JWT, session, etc.).
Great for on-demand retrieval in the Advisor.

- **Ingestion mode**: Git URL (same pipeline as Proactive Controls).
- **Typical use**: ad-hoc questions, snippet generation.

## Adding a custom framework

Admins navigate to **Admin → Frameworks → New framework**:

1. **Name** — short, lowercase, no spaces. Becomes the
   `framework_name` metadata on every RAG document + the
   `Scan.frameworks` tag used by the Compliance page.
2. **Description** — shown on the framework card.
3. **Ingestion** — pick CSV or Git URL. You can skip ingestion now
   and add docs later from **Admin → RAG**.
4. **Agent mapping** — check the agents that should run when a
   scan is tagged with this framework. The scan dispatcher
   respects this mapping per framework → finding-type combination.

## How frameworks interact with scans

At scan time, the submit UI shows every framework in the
`frameworks` table (defaults + custom) in the picker. The user's
selection goes into `Scan.frameworks` (JSONB array). The worker:

1. Passes the framework list into the `dependency_aware_analysis_orchestrator`.
2. The orchestrator dispatches each finding-type agent whose
   framework mapping includes at least one of the selected
   frameworks.
3. The chat agent, for sessions tied to the same project,
   retrieves RAG context scoped to the same frameworks.
4. The Compliance page aggregates `findings.scan_id → scans.frameworks`
   so every card reflects the right subset.

## Re-ingesting or removing a framework

- **Re-ingest**: re-upload the CSV or re-paste the Git URL. The
  existing framework documents are deleted from the Qdrant
  collection before the new ones land — it's idempotent.
- **Remove**: delete the framework row. Existing scans keep their
  tags (for historical rollup), but the framework disappears from
  the Compliance grid and the submit picker.

See
[Updating Framework Knowledge](../development/updating-framework-knowledge.md)
for the detailed step-by-step for re-ingestion.
