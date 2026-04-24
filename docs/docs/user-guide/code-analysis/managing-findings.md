---
sidebar_position: 3
title: Managing Findings
---

# Managing Findings

Once a scan reaches `COMPLETED`, the Results page surfaces findings
that are candidates for remediation. SCCAP supports selective,
incremental fix application — you control which findings are
applied, and a merge agent resolves conflicts between overlapping
fixes.

## Selecting findings

Each finding row has a checkbox. Tick the ones you want applied
(only findings that the agent actually produced a suggested fix for
can be selected — others render greyed out).

## Apply fixes

Click **Apply selected fixes** to trigger the remediation run:

1. The UI calls `POST /scans/{scan_id}/apply-fixes` with the list of
   finding ids.
2. The worker enqueues a remediation message. A fresh LangGraph
   thread starts, statused `REMEDIATION_TRIGGERED` → incremental
   application → merge → `REMEDIATION_COMPLETED`.
3. The Results page reloads once the final status flips; each
   applied finding shows a green "fix applied" chip.

## Downloading the patched tree

When the remediation run completes, the header gains a
**Download patched codebase** button. It zips the
`POST_REMEDIATION` code snapshot and streams it to the browser.
Diff the zip contents against your working copy to review what
changed.

## Dismissing / suppressing findings

SCCAP treats every finding as "open" unless a remediation applied
the associated fix. There is no dedicated "dismiss" state in this
release — false positives stay in the result. Two workarounds:

- Re-run the scan against a narrower file set to exclude the
  problematic area.
- Rely on the finding's confidence score during triage.

Formal finding lifecycle (acknowledged / dismissed / suppressed) is
on the [roadmap](../../roadmap.md).

## Re-scanning after a fix

Once you've applied your chosen fixes + integrated the patched tree
into your own repo, submit a fresh scan under the same project name.
The Projects grid shows the new posture side-by-side with the
previous run; the trend delta is visible on the card.

## Admin visibility

When scoped visibility is set up (H.2 user groups), any admin or
group peer can see and apply fixes on a scan they can see. The
`apply-fixes` endpoint doesn't require admin — the owning or
group-member user can drive it.
