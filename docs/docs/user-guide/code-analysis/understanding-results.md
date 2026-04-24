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
  primary download CTAs (PDF, SARIF).
- **Summary strip** — total findings grouped by severity; posture
  score using the same weighted-findings heuristic as the Dashboard.
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

## Impact report

The Impact tab on the Results page renders the
`impact_reporting_agent` output: a narrative summary + recommended
priority order, suitable for dropping into a PR review.

## SARIF

The SARIF tab renders the raw SARIF 2.1 document, and the "Download
SARIF" button exports it for use in VS Code, Azure DevOps, or GitHub
Advanced Security. The same data powers the finding list; SARIF is
just a portable serialization.

## Executive summary

"Download Executive Summary" renders the stakeholder-ready PDF
(`create_executive_summary_html` → `generate_pdf_from_html`). It's
designed for sharing with non-developers and deliberately omits
per-chunk reasoning.

## Related links

- [Managing Findings + Remediation](./managing-findings.md) — apply
  fixes from the Results page.
- [API → Results Endpoints](../../api-reference/results-endpoints.md)
  for the JSON shapes.
