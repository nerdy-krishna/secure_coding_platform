---
sidebar_position: 4
title: Reporting
---

# Reporting

Every completed scan produces structured outputs you can read in
the UI and (in the case of remediation) download.

## Findings + summary (UI)

The [Results page](./code-analysis/understanding-results.md) is the
canonical view. It shows:

- Header: scan ID, project, status, created / completed timestamps,
  per-scan cost (sum of `llm_interactions.cost`).
- Summary strip: total findings grouped by severity + a coarse
  0–10 risk score.
- Per-file panels: every analyzed file gets a collapsible section
  with chunk-level findings, severity, CWE id, suggested fix (when
  the agent produced one), and external references.

## Raw findings (JSON)

For custom integrations, call
`GET /api/v1/scans/{scan_id}/result`. Response includes the full
`summary_report`, per-file findings bundle, cost details, and every
`ScanEvent` emitted during the run. See
[API → Results Endpoints](../api-reference/results-endpoints.md) for
the full shape.

## Patched codebase (remediation only)

When a remediation run completes (status
`REMEDIATION_COMPLETED`), a **Download patched codebase** button
appears on the Results header. It zips the `POST_REMEDIATION` code
snapshot for the scan and streams it as an attachment. Diff against
the `ORIGINAL_SUBMISSION` to review what the auto-fixer changed.

## Audit trail

Every LLM call made during a scan writes an `llm_interactions` row
— prompt context, raw response, parsed output, cost, token counts.
Admins can inspect the full trail from
**Admin → Scans → LLM Interactions** or via
`GET /api/v1/scans/{scan_id}/llm-interactions`.

## Removed in the 2026-04-26 cleanup

Earlier versions of SCCAP exported a SARIF 2.1 document and offered
an Executive Summary PDF download backed by an
`impact_reporting_agent`. The agent's node was registered in the
graph but never wired in, so neither artifact was actually being
produced. The endpoints + UI surfaces have been removed for now;
they'll come back as a focused feature when we have time to wire
the reporting node properly.
