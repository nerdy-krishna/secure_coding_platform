"""`verify_patches` worker-graph node (§3.9).

Runs Semgrep against the POST_REMEDIATION snapshot for `REMEDIATE`
scans and marks each Semgrep-derived, fix-applied finding as
`fix_verified=True` (the original detection no longer fires) or
`fix_verified=False` (still detected at the same file). Other finding
sources (Bandit / Gitleaks / OSV / LLM-agent) are out of scope for
v1 verification — Semgrep is the only deterministic scanner with
both a stable rule signature AND wide language coverage that can be
replayed without per-language tooling.

The string name registered via `workflow.add_node("verify_patches", ...)`
is part of the LangGraph checkpointer's on-disk contract — do not rename.
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List

from app.core.schemas import VulnerabilityFinding
from app.infrastructure.database import AsyncSessionLocal
from app.infrastructure.database.repositories.scan_repo import ScanRepository
from app.infrastructure.scanners.semgrep_runner import run_semgrep
from app.infrastructure.scanners.staging import stage_files
from app.infrastructure.workflows.state import WorkerState

logger = logging.getLogger(__name__)


def _build_signature(file_path: str, cwe: str | None, line_number: int) -> str:
    """Match key for finding pre/post Semgrep runs.

    Same shape consolidate_and_patch and correlate_findings already use
    — `(file_path, cwe, line_number)`. Slight tolerance for line drift
    is handled in `_still_detected` below by matching on file+cwe only
    (line numbers shift after a patch).
    """
    return f"{file_path}|{cwe or 'CWE-Unknown'}|{line_number}"


def _still_detected(
    finding: VulnerabilityFinding,
    post_findings: List[VulnerabilityFinding],
) -> bool:
    """Does any post-remediation Semgrep finding match the original?

    Match on `(file_path, cwe)` rather than `(file_path, cwe, line)`
    because applying a fix can shift line numbers in the file. A
    Semgrep rule firing for the same CWE in the same file is the
    conservative signal: the fix didn't close the rule's detection.
    """
    for pf in post_findings:
        if pf.file_path == finding.file_path and pf.cwe == finding.cwe:
            return True
    return False


async def verify_patches_node(state: WorkerState) -> Dict[str, Any]:
    """Re-run Semgrep over the patched files; mark each Semgrep-derived
    fix as verified / unverified.

    No-op for non-REMEDIATE scans, scans with no patched files, or
    scans where no Semgrep findings were applied. Failures are
    non-fatal: any exception logs a WARN and the node returns ``{}`` —
    leaving `fix_verified=NULL` on every finding (the schema default,
    interpreted by the UI as "not verified").
    """
    scan_id = state["scan_id"]
    scan_type = state["scan_type"]
    findings = list(state.get("findings") or [])
    patched_files = state.get("patched_files") or {}

    if scan_type != "REMEDIATE":
        return {}
    if not patched_files:
        logger.info("verify_patches: scan_id=%s no patched files; skipping", scan_id)
        return {}

    # Filter to Semgrep-emitted findings that were actually applied.
    # Bandit / Gitleaks / OSV / LLM-agent findings stay at
    # `fix_verified=NULL` since this node can't replay their detection.
    applied_semgrep = [
        f for f in findings if (f.source == "semgrep") and f.is_applied_in_remediation
    ]
    if not applied_semgrep:
        logger.info(
            "verify_patches: scan_id=%s no applied semgrep findings; skipping",
            scan_id,
        )
        return {}

    # Restrict the re-scan to files that were actually patched. Other
    # files in the scan would also be in the POST_REMEDIATION snapshot
    # but they're identical to the originals, so re-scanning them just
    # burns CPU.
    files_to_rescan = {path: content for path, content in patched_files.items()}
    if not files_to_rescan:
        return {}

    # Re-stage + re-run Semgrep, swallow any subprocess error so the
    # scan still completes (verifier failure must not block remediation
    # results).
    try:
        with stage_files(files_to_rescan) as (staged_dir, original_paths):
            post_findings: List[VulnerabilityFinding] = await run_semgrep(
                staged_dir, original_paths
            )
    except Exception as exc:  # noqa: BLE001
        logger.warning(
            "verify_patches: scan_id=%s semgrep replay failed: %s; "
            "leaving fix_verified=NULL on all findings",
            scan_id,
            exc,
        )
        return {}

    verified = 0
    unverified = 0
    rescan_paths = set(files_to_rescan.keys())
    for f in findings:
        if f.source != "semgrep":
            continue
        if not f.is_applied_in_remediation:
            continue
        if f.file_path not in rescan_paths:
            # Patched file map didn't include this file — defensive,
            # shouldn't happen given the applied-flag is set inside
            # consolidate_and_patch only for files we patched.
            continue
        if _still_detected(f, post_findings):
            f.fix_verified = False
            unverified += 1
        else:
            f.fix_verified = True
            verified += 1

    logger.info(
        "verify_patches: scan_id=%s applied=%d verified=%d unverified=%d",
        scan_id,
        len(applied_semgrep),
        verified,
        unverified,
    )

    # Emit a ScanEvent so the SSE stream + scan-events log show the
    # verification step happened. Saving findings with the new
    # `fix_verified` column is handled in `save_results_node` (single
    # save site) — we just mutate the in-memory finding objects here.
    async with AsyncSessionLocal() as db:
        repo = ScanRepository(db)
        await repo.create_scan_event(
            scan_id=scan_id,
            stage_name="PATCH_VERIFICATION",
            status="COMPLETED",
        )

    return {"findings": findings}
