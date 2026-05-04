"""`correlate_findings` worker-graph node.

The string name registered via `workflow.add_node("correlate_findings", ...)`
is part of the LangGraph checkpointer's on-disk contract — do not rename.
"""

from __future__ import annotations

from typing import Any, Dict, List

from app.core.schemas import VulnerabilityFinding
from app.infrastructure.workflows.state import WorkerState


async def correlate_findings_node(state: WorkerState) -> Dict[str, Any]:
    """
    Merges findings for the same vulnerability from different agents into a single, higher-confidence finding.
    """
    findings = state.get("findings", [])
    if not findings:
        return {"findings": []}

    # Group findings by a signature: file, CWE, and line number
    finding_groups: Dict[str, List[VulnerabilityFinding]] = {}
    for finding in findings:
        signature = f"{finding.file_path}|{finding.cwe}|{finding.line_number}"
        if signature not in finding_groups:
            finding_groups[signature] = []
        finding_groups[signature].append(finding)

    correlated_findings: List[VulnerabilityFinding] = []
    for signature, group in finding_groups.items():
        # Collect all agents from the group, checking both agent_name and existing corroborating_agents
        all_agents = set()
        for f in group:
            if f.agent_name:
                all_agents.add(f.agent_name)
            if f.corroborating_agents:
                all_agents.update(f.corroborating_agents)

        sorted_agents = sorted(list(all_agents))

        if len(group) == 1:
            # If only one finding exists, presume it's the "group"
            final_finding = group[0]
            # Ensure corroborating_agents is populated with all known agents for this finding
            if sorted_agents:
                final_finding.corroborating_agents = sorted_agents
            elif final_finding.agent_name:
                final_finding.corroborating_agents = [final_finding.agent_name]

            correlated_findings.append(final_finding)
        else:
            # If multiple agents found it, merge them
            # Use the finding from the group with the highest severity as the base
            base_finding = max(
                group,
                key=lambda f: {"High": 3, "Medium": 2, "Low": 1}.get(f.severity, 0),
            )

            # Create a new merged finding
            merged_finding = base_finding.model_copy(deep=True)
            merged_finding.confidence = (
                "High"  # Confidence is high due to corroboration
            )
            merged_finding.corroborating_agents = sorted_agents

            # FIX: Preserve the 'is_applied_in_remediation' flag from the group.
            if any(f.is_applied_in_remediation for f in group):
                merged_finding.is_applied_in_remediation = True

            # You could potentially merge descriptions or other fields here if needed
            correlated_findings.append(merged_finding)

    # Stage-event audit trail — CORRELATING marker so the timeline
    # shows this phase ran. Wrapped so a logging-side issue can't
    # corrupt the workflow return value.
    try:
        from app.infrastructure.database import AsyncSessionLocal
        from app.infrastructure.database.repositories.scan_repo import (
            ScanRepository,
        )

        scan_id = state["scan_id"]
        async with AsyncSessionLocal() as db:
            await ScanRepository(db).create_scan_event(
                scan_id=scan_id,
                stage_name="CORRELATING",
                status="COMPLETED",
                details={"finding_count": len(correlated_findings)},
            )
    except Exception as _e:
        import logging as _logging

        _logging.getLogger(__name__).warning("CORRELATING event emit failed: %s", _e)

    return {"findings": correlated_findings}
