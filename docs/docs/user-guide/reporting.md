---
sidebar_position: 4
title: Reporting
---

# Reporting

Every completed scan produces three downloadable artifacts. You can
grab them from the Results page header or (for external tooling)
hit the API endpoints directly.

## Executive Summary PDF

A stakeholder-ready summary rendered from
`create_executive_summary_html` then converted via
`generate_pdf_from_html`. Includes:

- Platform + project metadata
- Posture score + severity breakdown
- Top findings with short, non-technical descriptions
- Recommended priority order (from the `impact_reporting_agent`)

**Download**: Results page header → **Download Executive Summary**.
**API**: `GET /api/v1/scans/{scan_id}/executive-summary/download`.

## SARIF 2.1

The raw Static Analysis Results Interchange Format document the
scan produced. Portable across VS Code, Azure DevOps, GitHub
Advanced Security, and most security-tooling pipelines.

**Download**: Results page → **SARIF** tab → **Download SARIF**.
**API**: `GET /api/v1/scans/{scan_id}/sarif`.

## Impact report

A narrative summary produced by the `impact_reporting_agent`
covering what each cluster of findings means for the application,
which areas should be fixed first, and the business risk
implications. Available inline on the Results page under the
**Impact** tab.

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
