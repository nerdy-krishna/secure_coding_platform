---
sidebar_position: 2
title: Dashboard
---

# Dashboard

The Dashboard is the first page SCCAP loads after login. It shows a
live rollup of everything in the caller's visibility scope: your own
scans plus scans belonging to anyone you share a group with.
Superusers see a platform-wide variant ("Admin snapshot").

Data comes from a single endpoint: `GET /api/v1/dashboard/stats`.

## Hero

- **Risk ring** — weighted-findings posture score from 5 to 100.
  Lower is worse. The same heuristic drives the Compliance page and
  Projects cards so the numbers agree across surfaces.
- **Headline** — dynamic: "N scans in progress", "all caught up", or
  "no scans this month yet — start one" depending on state.
- **Sub-line** — scans-this-month count, total open findings,
  monthly spend in USD. Monthly spend is the sum of
  `llm_interactions.cost` for the current month across the visibility
  scope.
- **Primary CTAs** — "New scan" routes to the Submit page;
  "View projects" to the Projects grid.

## Metric tiles (4)

1. **Scans / month** — count for the current calendar month + a
   14-day sparkline (the raw per-day counts behind the sparkline
   also drive the ticker under the card).
2. **In progress** — scans currently in any of the active statuses
   (`QUEUED`, `QUEUED_FOR_SCAN`, `ANALYZING_CONTEXT`,
   `RUNNING_AGENTS`, `GENERATING_REPORTS`, `PENDING_COST_APPROVAL`).
3. **Open critical** — critical findings not yet remediated; the
   delta line shows high-severity count.
4. **Fixes ready** — findings with an AI-suggested fix that haven't
   been applied yet. Click through to the Results page to apply.

## Two-column section

- **Recent scans** (2/3 width) — the 5 most recent scans by created
  time. Rows are clickable when the scan is in a terminal state.
- **Findings by severity** (1/3 width) — stacked SevBar across
  critical / high / medium / low / informational with a legend +
  count per bucket.
- **Advisor teaser** — deep-links to the Security Advisor page.

## Admin snapshot

Superusers see the same metrics but platform-wide (no scope filter).
The Admin snapshot adds:

- A **platform-wide** severity bar (larger legend).
- Deep links to **Admin → Groups** and **Admin → Users** from the
  hero strip so managing shared visibility is one click away.

## Drilling in

- Click any recent-scans row for the terminal Results page.
- Hover the risk ring for the scoring methodology.
- Use the global search combobox in the top nav to jump to a
  specific finding, scan, or project regardless of pagination.

## Troubleshooting

- **"Loading…" that never resolves**: check the browser devtools
  Network tab — a 401 means your token expired; the
  `apiClient.ts` auto-refresh should kick in within a second.
- **Score stuck at 100**: no open findings yet. Submit a scan to
  populate the ring.
- **Empty scan trend**: you have no scans in the last 14 days. The
  sparkline baseline renders as a flat zero line.
