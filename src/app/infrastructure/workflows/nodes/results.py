"""Terminal save nodes for the worker graph.

Two nodes: `save_results_node` writes findings + the post-remediation
snapshot; `save_final_report_node` writes the summary blob and the
0–10 risk score and flips the scan to `COMPLETED` /
`REMEDIATION_COMPLETED`.

The string names registered via `workflow.add_node(...)` are part of
the LangGraph checkpointer's on-disk contract — do not rename.
"""

from __future__ import annotations

import logging
from typing import Any, Dict

from app.infrastructure.database import AsyncSessionLocal
from app.infrastructure.database.repositories.scan_repo import ScanRepository
from app.infrastructure.workflows.state import WorkerState
from app.shared.lib.risk_score import compute_cvss_aggregate
from app.shared.lib.scan_status import (
    STATUS_COMPLETED,
    STATUS_REMEDIATION_COMPLETED,
)

logger = logging.getLogger(__name__)


async def save_results_node(state: WorkerState) -> Dict[str, Any]:
    scan_id = state["scan_id"]
    scan_type = state["scan_type"]
    findings = state.get("findings", [])
    final_file_map = state.get("final_file_map")

    logger.info(f"Saving final results for scan {scan_id}.")
    async with AsyncSessionLocal() as db:
        repo = ScanRepository(db)

        if findings:
            if scan_type in ("AUDIT", "SUGGEST"):
                # For these modes, we do a bulk insert of new, correlated findings
                await repo.save_findings(scan_id, findings)
            else:  # For REMEDIATE, we update the existing findings with correlation data
                await repo.update_correlated_findings(findings)

        if scan_type == "REMEDIATE" and final_file_map:
            logger.info(f"Saving POST_REMEDIATION snapshot for scan {scan_id}.")
            await repo.create_code_snapshot(
                scan_id=scan_id,
                file_map=final_file_map,
                snapshot_type="POST_REMEDIATION",
            )

    return {}


async def save_final_report_node(state: WorkerState) -> Dict[str, Any]:
    scan_id, findings = state["scan_id"], state.get("findings", [])
    logger.info(f"Saving final reports and risk score for scan {scan_id}.")
    severity_map = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFORMATIONAL": 0}
    for f in findings:
        sev = (f.severity or "LOW").upper()
        if sev in severity_map:
            severity_map[sev] += 1
    aggregate = compute_cvss_aggregate(findings, scan_id=scan_id)
    final_risk_score = min(10, int(round(aggregate)))

    summary_data = {
        "summary": {
            "total_findings_count": len(findings),
            "files_analyzed_count": len(set(f.file_path for f in findings)),
            "severity_counts": severity_map,
        },
        "overall_risk_score": {"score": final_risk_score, "severity": "High"},
    }
    final_status = (
        STATUS_REMEDIATION_COMPLETED
        if state.get("scan_type") == "REMEDIATE"
        else STATUS_COMPLETED
    )
    await ScanRepository(AsyncSessionLocal()).save_final_reports_and_status(
        scan_id=scan_id,
        status=final_status,
        summary=summary_data,
        risk_score=final_risk_score,
    )
    return {}
