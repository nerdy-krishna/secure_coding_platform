---
sidebar_position: 2
title: Understanding Results
---

# Understanding Results

The **Results** page (`/analysis/results/{scan_id}`) opens when a
scan reaches a terminal state. It's the main place users read
findings, decide what to remediate, and export downstream artifacts.

## Layout

- **Header** — scan ID, project name, final status, created/completed
  timestamps, cost (sum of `llm_interactions.cost` for this scan),
  and a link to the LLM-interactions log.
- **Summary strip** — total findings grouped by severity; coarse
  0–10 risk score on the scan row (separate from the Dashboard /
  Compliance weighted-findings posture).
- **Per-file panels** — every analyzed file gets a collapsible
  section. Expand to see chunk-level findings in context, with:
  - Title + severity chip
  - Description
  - Affected line range (when available)
  - CWE id
  - Corroborating agents (the agent names that flagged this
    finding; high-confidence findings are corroborated by multiple)
  - Suggested fix (if the agent produced one)
  - External references (links to ASVS, Cheatsheets, CWE, etc.)

## Severity vs. confidence

Findings carry **both** a severity (Critical / High / Medium / Low /
Informational) and a confidence (High / Medium / Low). The risk
score uses severity weights; the UI surfaces confidence inline so
reviewers can prioritize triage.

## Reports that aren't shipped today

Earlier versions of SCCAP rendered an Impact tab (narrative summary
from the `impact_reporting_agent`), exported a SARIF 2.1 document,
and offered an Executive Summary PDF download. **All three were
removed in the 2026-04-26 cleanup** — the impact-reporting node
was registered but never wired into the graph, so the surfaces
were rendering empty. They'll come back as a future feature.
For now the Results page is the authoritative view of every scan.

## Related links

- [Managing Findings + Remediation](./managing-findings.md) — apply
  fixes from the Results page.
- [API → Results Endpoints](../../api-reference/results-endpoints.md)
  for the JSON shapes.
