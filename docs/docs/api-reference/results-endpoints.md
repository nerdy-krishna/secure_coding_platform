---
sidebar_position: 4
title: Results Endpoints
---

# Results Endpoints

All paths are under `/api/v1` and require a Bearer token. These
endpoints read the outputs of a completed (or in-progress) scan;
they never mutate scan state.

## Paginated scan history for the caller

```http
GET /scans/history?page=1&page_size=10&search=<term>&sort_order=desc&status=<All|In Progress|Completed|FAILED|...>
```

Used by the History page and the dashboard's "recent scans" tile.
Scoped by H.2 visibility.

## Scans for a specific project

```http
GET /projects/{project_id}/scans?skip=0&limit=10
```

## Full scan result (JSON)

```http
GET /scans/{scan_id}/result
```

Returns `AnalysisResultDetailResponse`: the parsed `summary_report`,
the per-file findings bundle, `cost_details`, and the list of
`ScanEvent` rows emitted while running.

Use this for the Results page. SARIF + PDF endpoints below are more
appropriate for external tooling.

## SARIF download

```http
GET /scans/{scan_id}/sarif
```

Returns the SARIF 2.1 document the scan produced as application/json.
Importable into VS Code, Azure DevOps, GitHub Advanced Security, etc.

## Executive summary PDF

```http
GET /scans/{scan_id}/executive-summary/download
```

Renders the scan's executive summary HTML (via `create_executive_summary_html`)
into a stakeholder-ready PDF and streams it as
`attachment; filename=executive-summary-<scan_id>.pdf`.

## LLM interactions for a scan

```http
GET /scans/{scan_id}/llm-interactions
```

Returns every `llm_interactions` row tied to the scan: agent name,
prompt template, prompt context (JSONB), full raw response, parsed
output, cost, token counts, timestamp. Intended for admins debugging
agent drift — regular users only see interactions for their own
scans.

## Delete

```http
DELETE /scans/{scan_id}                     # superuser only
DELETE /projects/{project_id}               # superuser only
```

Deletes the scan (or the project + all child scans) including every
finding, snapshot, and LLM-interaction row.

## Error shapes

The backend uses FastAPI's default problem-JSON shape:

```json
{ "detail": "Scan not found or not authorized." }
```

Authorization failures return `404` rather than `403` for scans the
user can't see — the existence of a scan shouldn't leak across the
scope boundary.
