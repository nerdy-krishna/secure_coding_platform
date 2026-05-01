"""`analyze_files_parallel` worker-graph node.

Runs every relevant agent against every file in parallel (bounded by
``CONCURRENT_LLM_LIMIT``) and returns the union of findings + the raw
per-file fix proposals for downstream consolidation.

The string name registered via `workflow.add_node("analyze_files_parallel", ...)`
is part of the LangGraph checkpointer's on-disk contract — do not rename.
"""

from __future__ import annotations

import asyncio
import logging
from typing import Any, Dict, List, cast

import networkx as nx

from app.core.schemas import (
    CodeChunk,
    FixResult,
    SpecializedAgentState,
    VulnerabilityFinding,
)
from app.infrastructure.agents.generic_specialized_agent import (
    build_generic_specialized_agent_graph,
)
from app.infrastructure.workflows.nodes.cost import CHUNK_ONLY_IF_LARGER_THAN
from app.infrastructure.workflows.state import WorkerState
from app.shared.analysis_tools.chunker import semantic_chunker
from app.shared.lib.agent_routing import resolve_agents_for_file

logger = logging.getLogger(__name__)

CONCURRENT_LLM_LIMIT = 5


async def analyze_files_parallel_node(state: WorkerState) -> Dict[str, Any]:
    """Single-pass analysis: every agent runs against the original code.

    Replaces the old iterative `dependency_aware_analysis_orchestrator`
    (D.5 decision, F.5.2). Key differences:
      - All files are analyzed in parallel (bounded by CONCURRENT_LLM_LIMIT).
        No topological ordering; no cross-file patch propagation — all agents
        see `live_codebase` (the ORIGINAL_SUBMISSION snapshot content).
      - No mid-graph DB writes: findings and proposed fixes collect into
        returned state. Consolidation + patch + snapshot persistence happen
        once in `consolidate_and_patch_node` and `save_results_node`.
      - The dependency graph is still used to build the per-file `dep_summary`
        that enriches each agent's prompt, since that summary is sourced from
        the repository map (stable regardless of processing order).
    """
    scan_id, scan_type = state["scan_id"], state["scan_type"]
    logger.info(
        "Starting single-pass analysis for scan %s in %r mode.", scan_id, scan_type
    )

    # --- REVISED GUARD CLAUSE BLOCK ---
    live_codebase = state.get("live_codebase")
    if not live_codebase:
        return {"error_message": "Orchestrator is missing 'live_codebase'."}

    repository_map = state.get("repository_map")
    if not repository_map:
        return {"error_message": "Orchestrator is missing 'repository_map'."}

    graph_data = state.get("dependency_graph")
    if not graph_data:
        return {"error_message": "Orchestrator is missing 'dependency_graph'."}
    dependency_graph = nx.node_link_graph(graph_data)  # Deserialize the graph

    all_relevant_agents = state.get("all_relevant_agents", {})
    if not all_relevant_agents:
        return {"error_message": "Orchestrator is missing 'all_relevant_agents'."}

    reasoning_llm_id = state.get("reasoning_llm_config_id")
    if not reasoning_llm_id:
        return {"error_message": "Orchestrator is missing 'reasoning_llm_config_id'."}
    # --- END REVISED GUARD CLAUSE BLOCK ---

    generic_agent_graph = build_generic_specialized_agent_graph()
    semaphore = asyncio.Semaphore(CONCURRENT_LLM_LIMIT)

    def build_dep_summary(file_path: str) -> str:
        """Per-file dependency context. Pure read from repository_map; safe to
        compute concurrently across files."""
        if file_path not in dependency_graph:
            return ""
        dep_parts: List[str] = []
        for dep_path in dependency_graph.successors(file_path):
            dep_file_summary = repository_map.files.get(dep_path)
            if dep_file_summary and dep_file_summary.symbols:
                symbol_sigs = [
                    f"  - {s.type} {s.name} (line {s.line_number})"
                    for s in dep_file_summary.symbols[:15]
                ]
                dep_parts.append(f"# File: {dep_path}\n" + "\n".join(symbol_sigs))
        if not dep_parts:
            return ""
        return (
            "# --- [DEPENDENCY CONTEXT: symbols from imported files] ---\n"
            + "\n".join(dep_parts)
            + "\n# --- [END DEPENDENCY CONTEXT] ---\n\n"
        )

    def chunk_file(file_path: str, file_content: str) -> List[CodeChunk]:
        file_summary = repository_map.files.get(file_path)
        if not file_summary:
            return []
        token_count = len(file_content) / 4
        if token_count > CHUNK_ONLY_IF_LARGER_THAN:
            logger.info(
                "%s is a large file, applying chunking.",
                file_path,
                extra={"scan_id": str(scan_id)},
            )
            return semantic_chunker(file_content, file_summary)
        return [
            {
                "symbol_name": file_path,
                "code": file_content,
                "start_line": 1,
                "end_line": len(file_content.splitlines()),
            }
        ]

    async def run_agent_with_sem(coro):
        async with semaphore:
            return await coro

    async def analyze_one_file(
        file_path: str,
    ) -> Dict[str, List[Any]]:
        file_content = live_codebase.get(file_path)
        if not file_content:
            return {"findings": [], "fixes": []}

        chunks = chunk_file(file_path, file_content)
        if not chunks:
            return {"findings": [], "fixes": []}

        relevant_agents = resolve_agents_for_file(file_path, all_relevant_agents)
        if not relevant_agents:
            return {"findings": [], "fixes": []}

        dep_summary = build_dep_summary(file_path)

        file_findings: List[VulnerabilityFinding] = []
        file_fixes: List[FixResult] = []

        # Verified-findings prompt prefix (B4): pass the per-file
        # SAST scanner findings into the agent so it can avoid
        # re-flagging issues the deterministic scanners already found.
        prior_findings_all = state.get("findings") or []
        per_file_scanner_findings = [
            f
            for f in prior_findings_all
            if getattr(f, "source", None) in ("bandit", "semgrep", "gitleaks")
            and f.file_path == file_path
        ]

        for chunk in chunks:
            enriched_code = (
                f"{dep_summary}{chunk['code']}" if dep_summary else chunk["code"]
            )
            tasks = []
            for agent in relevant_agents:
                initial_agent_state: SpecializedAgentState = {
                    "scan_id": scan_id,
                    "llm_config_id": reasoning_llm_id,
                    "filename": file_path,
                    "code_snippet": enriched_code,
                    "file_content_for_verification": file_content,
                    "workflow_mode": (
                        "remediate"
                        if scan_type in ("REMEDIATE", "SUGGEST")
                        else "audit"
                    ),
                    "findings": [],
                    "fixes": [],
                    "error": None,
                    "prescan_findings_for_file": per_file_scanner_findings,
                }
                tasks.append(
                    run_agent_with_sem(
                        generic_agent_graph.ainvoke(
                            initial_agent_state,
                            config={"configurable": cast(dict, agent)},
                        )
                    )
                )

            agent_results = await asyncio.gather(*tasks, return_exceptions=True)
            for r in agent_results:
                if isinstance(r, BaseException) or r is None:
                    continue
                file_findings.extend(r.get("findings", []))
                # The agent returns `fixes` as a separate list of FixResult
                # objects; collect them directly for the terminal consolidation.
                file_fixes.extend(r.get("fixes", []))

        # §3.10b: emit a `FILE_ANALYZED` ScanEvent so the SSE stream
        # can surface per-file progress mid-scan. The event carries
        # the file path and the count of agent-emitted findings; the
        # frontend ScanRunningPage uses these to render a per-file
        # progress widget without waiting for the whole scan to
        # complete. Wrapped in try/except so a logging-side error
        # never aborts the scan flow.
        try:
            from app.infrastructure.database import (
                AsyncSessionLocal as _AsyncSessionLocal,
            )
            from app.infrastructure.database.repositories.scan_repo import (
                ScanRepository as _ScanRepository,
            )

            async with _AsyncSessionLocal() as _db:
                await _ScanRepository(_db).create_scan_event(
                    scan_id=scan_id,
                    stage_name="FILE_ANALYZED",
                    status="COMPLETED",
                    details={
                        "file_path": file_path,
                        "findings_count": len(file_findings),
                        "fixes_count": len(file_fixes),
                    },
                )
        except Exception as e:
            logger.warning("FILE_ANALYZED event emit failed for %s: %s", file_path, e)

        return {"findings": file_findings, "fixes": file_fixes}

    # All files analyzed in parallel. Concurrency across files is bounded
    # inside each run_agent_with_sem invocation (the same semaphore gates
    # agent calls regardless of which file they belong to).
    file_tasks = [analyze_one_file(fp) for fp in live_codebase.keys()]
    file_results = await asyncio.gather(*file_tasks, return_exceptions=True)

    all_scan_findings: List[VulnerabilityFinding] = []
    all_proposed_fixes: List[FixResult] = []
    for r in file_results:
        if isinstance(r, BaseException):
            logger.error(
                "File analysis task failed for scan %s: %s", scan_id, r, exc_info=r
            )
            continue
        all_scan_findings.extend(r.get("findings", []))
        all_proposed_fixes.extend(r.get("fixes", []))

    # Carry forward any findings already on state (e.g. deterministic
    # SAST findings from the prescan node) so they survive to
    # `correlate_findings_node` (which dedupes by (file_path, cwe,
    # line_number)) and on to `save_results_node`.
    prior_findings = state.get("findings") or []

    logger.info(
        "Single-pass analysis complete for scan %s: %d agent findings, %d prior findings, %d proposed fixes.",
        scan_id,
        len(all_scan_findings),
        len(prior_findings),
        len(all_proposed_fixes),
    )

    return {
        "findings": prior_findings + all_scan_findings,
        "proposed_fixes": all_proposed_fixes,
    }
