# src/app/infrastructure/workflows/worker_graph.py
import asyncio
import logging
import psycopg
import uuid
import networkx as nx
from typing import Any, Dict, List, Optional, TypedDict, cast

from langgraph.checkpoint.postgres.aio import AsyncPostgresSaver
from langgraph.graph import END, StateGraph
from langgraph.pregel import Pregel
from langgraph.types import interrupt
from sqlalchemy import select
from sqlalchemy.orm import selectinload

from app.config.config import settings
from app.core.schemas import (
    FixResult,
    FixSuggestion,
    SpecializedAgentState,
    VulnerabilityFinding,
    CodeChunk,
    MergedFixResponse,
)
from app.infrastructure.database import AsyncSessionLocal
from app.infrastructure.database.models import CweOwaspMapping
from app.infrastructure.agents.generic_specialized_agent import (
    build_generic_specialized_agent_graph,
)
from app.infrastructure.database import models as db_models
from app.infrastructure.database.repositories.llm_config_repo import LLMConfigRepository
from app.infrastructure.database.repositories.scan_repo import ScanRepository
from app.infrastructure.llm_client import get_llm_client
from app.shared.analysis_tools.context_bundler import ContextBundlingEngine
from app.shared.analysis_tools.repository_map import RepositoryMappingEngine

try:
    from tree_sitter_languages import get_parser as ts_get_parser

    HAS_TREE_SITTER = True
except ImportError:
    HAS_TREE_SITTER = False
from app.shared.analysis_tools.chunker import semantic_chunker
from app.shared.lib.agent_routing import resolve_agents_for_file
from app.shared.lib.files import get_language_from_filename
from app.shared.lib import cost_estimation
from app.shared.lib.risk_score import compute_cvss_aggregate

logger = logging.getLogger(__name__)

CONCURRENT_LLM_LIMIT = 5
# Files under this token size are passed whole to the analysis agents; only
# truly huge files (lockfiles, generated bundles, etc.) fall through to the
# semantic chunker. With 200k-context models + Anthropic prompt caching this
# is almost always cheaper than chunking, since chunking re-sends the same
# guidelines / dependency context per chunk.
CHUNK_ONLY_IF_LARGER_THAN = 150_000

# --- Status Constants ---
# Re-exported from the shared module so downstream callers can continue to
# import them from worker_graph if they already do, while the canonical
# definitions live in app.shared.lib.scan_status.
from app.shared.lib.scan_status import (  # noqa: E402
    STATUS_ANALYZING_CONTEXT,
    STATUS_COMPLETED,
    STATUS_FAILED,
    STATUS_PENDING_APPROVAL,
    STATUS_QUEUED_FOR_SCAN,
    STATUS_REMEDIATION_COMPLETED,
)


class RelevantAgent(TypedDict):
    name: str
    description: str
    domain_query: Dict[str, Any]


class WorkerState(TypedDict):
    """The updated, three-tier state for the workflow."""

    scan_id: uuid.UUID
    scan_type: str
    current_scan_status: Optional[str]
    utility_llm_config_id: Optional[uuid.UUID]
    fast_llm_config_id: Optional[uuid.UUID]
    reasoning_llm_config_id: Optional[uuid.UUID]
    files: Optional[Dict[str, str]]
    initial_file_map: Optional[Dict[str, str]]
    final_file_map: Optional[Dict[str, str]]
    repository_map: Optional[Any]
    dependency_graph: Optional[Any]
    all_relevant_agents: Dict[str, RelevantAgent]
    live_codebase: Optional[Dict[str, str]]
    findings: List[VulnerabilityFinding]
    # Raw per-agent fix proposals collected by analyze_files_parallel_node and
    # consumed by consolidate_and_patch_node. Carries (finding, suggestion)
    # pairs before correlation; the correlated findings live in `findings`.
    proposed_fixes: Optional[List[FixResult]]
    agent_results: Optional[List[Dict[str, Any]]]
    error_message: Optional[str]


# --- WORKFLOW NODES ---


async def retrieve_and_prepare_data_node(state: WorkerState) -> Dict[str, Any]:
    """
    Node to retrieve all initial data, create the repo map, and dependency graph.
    """
    scan_id = state["scan_id"]
    logger.info(f"Entering node to retrieve and prepare data for scan {scan_id}.")
    try:
        async with AsyncSessionLocal() as db:
            repo = ScanRepository(db)

            # --- FETCH SCAN FIRST to get its status ---
            scan = await repo.get_scan_with_details(scan_id)
            if not scan:
                return {"error_message": f"Scan with ID {scan_id} not found."}

            # Capture the status before updating the DB
            current_status = scan.status

            # Now, update the status to show progress
            await repo.update_status(scan_id, STATUS_ANALYZING_CONTEXT)

            original_snapshot = next(
                (s for s in scan.snapshots if s.snapshot_type == "ORIGINAL_SUBMISSION"),
                None,
            )
            if not original_snapshot:
                return {
                    "error_message": f"Original code snapshot not found for scan {scan_id}."
                }

            files_map = await repo.get_source_files_by_hashes(
                list(original_snapshot.file_map.values())
            )
            files = {
                path: files_map.get(h, "")
                for path, h in original_snapshot.file_map.items()
            }

            # Create Repo Map
            mapping_engine = RepositoryMappingEngine()
            repository_map = mapping_engine.create_map(files)
            logger.info(f"DEBUG: repository_map content: {repository_map.model_dump()}")

            # Create Dependency Graph
            bundling_engine = ContextBundlingEngine(repository_map, files)
            dependency_graph = bundling_engine.graph
            logger.info(
                f"DEBUG: dependency_graph content: {nx.node_link_data(dependency_graph)}"
            )

            # Determine Relevant Agents
            framework_details = await db.execute(
                select(db_models.Framework)
                .options(selectinload(db_models.Framework.agents))
                .where(db_models.Framework.name.in_(scan.frameworks or []))
            )
            # Store full agent details for the triage step
            all_relevant_agents = {
                agent.name: RelevantAgent(
                    name=agent.name,
                    description=agent.description,
                    domain_query=agent.domain_query,
                )
                for framework in framework_details.scalars().all()
                for agent in framework.agents
            }

            # --- FIX: Add this block to explicitly save the artifacts ---
            serialized_graph = nx.node_link_data(dependency_graph)
            await repo.update_scan_artifacts(
                scan_id,
                {
                    "repository_map": repository_map.model_dump(),
                    "dependency_graph": serialized_graph,
                },
            )
            # --- End of FIX ---

            return {
                "scan_type": scan.scan_type,
                "current_scan_status": current_status,
                "utility_llm_config_id": scan.utility_llm_config_id,
                "fast_llm_config_id": scan.fast_llm_config_id,
                "reasoning_llm_config_id": scan.reasoning_llm_config_id,
                "files": files,
                "initial_file_map": original_snapshot.file_map,
                "live_codebase": files.copy(),
                "repository_map": repository_map,
                "dependency_graph": nx.node_link_data(dependency_graph),
                "findings": [],
                "all_relevant_agents": all_relevant_agents,
            }
    except Exception as e:
        logger.error(f"Error preparing data for scan {scan_id}: {e}", exc_info=True)
        return {"error_message": str(e)}


def _verify_syntax_with_treesitter(full_code: str, filename: str) -> bool:
    """Quick syntax check using tree-sitter. Returns True if code parses without errors."""
    if not HAS_TREE_SITTER:
        return True  # Skip check if tree-sitter not available

    lang_map = {
        ".py": "python",
        ".js": "javascript",
        ".ts": "typescript",
        ".java": "java",
        ".go": "go",
        ".rb": "ruby",
        ".rs": "rust",
        ".c": "c",
        ".cpp": "cpp",
        ".cs": "c_sharp",
        ".php": "php",
        ".swift": "swift",
        ".kt": "kotlin",
    }
    ext = "." + filename.rsplit(".", 1)[-1].lower() if "." in filename else ""
    lang = lang_map.get(ext)
    if not lang:
        return True  # Unknown language, skip check

    try:
        parser = ts_get_parser(lang)
        tree = parser.parse(full_code.encode("utf-8"))
        return not tree.root_node.has_error
    except Exception as e:
        logger.warning(f"Tree-sitter syntax check failed for {filename}: {e}")
        return True  # Don't block on tree-sitter errors


async def _run_merge_agent(
    reasoning_llm_config_id: uuid.UUID,
    code_block: str,
    conflicting_fixes: List[FixResult],
    code_to_search_in: str,
) -> Optional[FixResult]:
    """
    Invokes an LLM to merge multiple conflicting fix suggestions into a single, superior fix.
    Includes verification, syntax checking, and retry logic.
    """
    llm_client = await get_llm_client(reasoning_llm_config_id)
    if not llm_client:
        return None

    logger.info(f"DEBUG: _run_merge_agent code_block:\n{code_block}")
    logger.info(
        f"DEBUG: _run_merge_agent conflicting_fixes: {[fix.model_dump() for fix in conflicting_fixes]}"
    )
    logger.info(
        f"DEBUG: _run_merge_agent code_to_search_in (first 500 chars): {code_to_search_in[:500]}"
    )

    # Use the highest-priority finding as the basis for the merged finding metadata
    winner = conflicting_fixes[0]
    filename = winner.finding.file_path or ""

    suggestions_str = ""
    for i, fix in enumerate(conflicting_fixes):
        suggestions_str += f"--- Suggestion {i + 1} (Severity: {fix.finding.severity}, CWE: {fix.finding.cwe}) ---\n"
        suggestions_str += f"Description: {fix.finding.description}\n"
        suggestions_str += f"Fix:\n```\n{fix.suggestion.code}\n```\n\n"

    prompt = f"""
You are an expert security engineer. Your task is to merge multiple suggested fixes into a single, cohesive, and secure block of code.

RULES:
1. The final code must address ALL the identified vulnerabilities if possible.
2. If fixes are mutually exclusive, prioritize the change that resolves the highest severity vulnerability.
3. PRESERVE all existing comments unless they pose a security risk (e.g., hardcoded secrets).
4. Produce the most optimized, idiomatic code possible — do not just concatenate fixes.
5. Ensure any imports or dependencies referenced in the fix already exist in the file context.
6. Do NOT introduce new vulnerabilities (e.g., removing error handling, weakening validation).
7. The merged code MUST be syntactically valid and ready to compile/run.

ORIGINAL VULNERABLE CODE BLOCK:

{code_block}

CONFLICTING SUGGESTIONS:
{suggestions_str}

Respond ONLY with a valid JSON object conforming to the MergedFixResponse schema.
The `merged_code` you provide must be a surgical, drop-in replacement for the ORIGINAL VULNERABLE CODE BLOCK. It must ONLY contain the specific lines that are changing. Do not include surrounding, unchanged code like function definitions or block delimiters.
Crucially, the `original_snippet_for_replacement` field in your JSON response MUST be an EXACT, character-for-character copy of the 'ORIGINAL VULNERABLE CODE BLOCK' provided above.
The `merged_code` field should contain ONLY the final, corrected code that will replace the original block. DO NOT include the original code in the `merged_code` field.
"""
    # Single-shot merge. The old 3-attempt retry loop was weak-model scaffolding;
    # a modern reasoning model that fails once is very unlikely to succeed on
    # attempt 3, and the retries wasted tokens + latency. On failure we fall
    # back to the highest-priority fix and surface the unmerged group as
    # NEEDS_MANUAL_REVIEW via the caller's fallback path.
    response = await llm_client.generate_structured_output(prompt, MergedFixResponse)

    if not (
        response.parsed_output
        and isinstance(response.parsed_output, MergedFixResponse)
        and response.parsed_output.original_snippet_for_replacement in code_to_search_in
    ):
        logger.warning(
            f"Merge agent did not produce a verifiable snippet for {filename}. "
            f"Conflicts: {len(conflicting_fixes)} fixes, CWEs: "
            f"{[f.finding.cwe for f in conflicting_fixes]}. "
            f"Falling back to highest priority fix."
        )
        return None

    merged_code = response.parsed_output.merged_code
    original_snippet = response.parsed_output.original_snippet_for_replacement

    # No-op guard: the merged code must actually change something.
    if merged_code.strip() == original_snippet.strip():
        logger.warning(
            f"Merge agent returned a fix identical to the original for {filename}. "
            f"Falling back to highest priority fix."
        )
        return None

    # Syntax check before committing to a replacement.
    candidate_code = code_to_search_in.replace(original_snippet, merged_code, 1)
    if not _verify_syntax_with_treesitter(candidate_code, filename):
        logger.warning(
            f"Merge agent produced syntactically invalid code for {filename}. "
            f"Falling back to highest priority fix."
        )
        return None

    # Build the merged FixResult carrying the explanation from each input fix.
    merged_finding = winner.finding.model_copy(deep=True)
    conflicts_summary = "The following conflicting suggestions were considered:\n"
    for i, fix in enumerate(conflicting_fixes):
        conflicts_summary += (
            f"- Suggestion {i + 1} (CWE: {fix.finding.cwe}, "
            f"Severity: {fix.finding.severity}): {fix.finding.remediation}\n"
        )
    final_explanation = (
        f"{conflicts_summary}\nMerge Reasoning:\n{response.parsed_output.explanation}"
    )
    merged_finding.description = final_explanation

    merged_suggestion = FixSuggestion(
        description=final_explanation,
        original_snippet=original_snippet,
        code=merged_code,
    )
    logger.info(f"Merge agent succeeded for {filename} with syntax-verified code.")
    return FixResult(finding=merged_finding, suggestion=merged_suggestion)


async def estimate_cost_node(state: WorkerState) -> Dict[str, Any]:
    """
    Performs a dry run of the analysis to generate a highly accurate cost estimate.
    """
    scan_id = state["scan_id"]
    logger.info(f"Performing cost estimation dry run for scan {scan_id}.")

    # --- REVISED GUARD CLAUSE BLOCK ---
    repository_map = state.get("repository_map")
    if not repository_map:
        return {"error_message": "Cost estimation missing 'repository_map'."}

    dependency_graph_data = state.get("dependency_graph")
    if not dependency_graph_data:
        return {"error_message": "Cost estimation missing 'dependency_graph'."}

    reasoning_llm_config_id = state.get("reasoning_llm_config_id")
    if not reasoning_llm_config_id:
        return {"error_message": "Cost estimation missing 'reasoning_llm_config_id'."}

    live_codebase = state.get("live_codebase")
    if not live_codebase:
        return {"error_message": "Cost estimation missing 'live_codebase'."}

    all_relevant_agents = state.get("all_relevant_agents")
    if not all_relevant_agents:
        return {"error_message": "Cost estimation missing 'all_relevant_agents'."}
    # --- END REVISED GUARD CLAUSE BLOCK ---

    try:
        dependency_graph = nx.node_link_graph(dependency_graph_data)
        processing_order = list(nx.topological_sort(dependency_graph))
    except nx.NetworkXUnfeasible:
        processing_order = sorted(list(live_codebase.keys()))

    total_input_tokens = 0
    async with AsyncSessionLocal() as db:
        llm_config = await LLMConfigRepository(db).get_by_id_with_decrypted_key(
            reasoning_llm_config_id
        )
        if not llm_config:
            return {
                "error_message": f"LLM Config {reasoning_llm_config_id} not found for cost estimation."
            }

        for file_path in processing_order:
            file_content = live_codebase[file_path]
            file_summary = repository_map.files.get(file_path)
            if not file_summary:
                continue

            chunks: List[CodeChunk] = []
            if (len(file_content) / 4) > CHUNK_ONLY_IF_LARGER_THAN:
                chunks = semantic_chunker(file_content, file_summary)
            else:
                chunks = [
                    {
                        "symbol_name": file_path,
                        "code": file_content,
                        "start_line": 1,
                        "end_line": 1,
                    }
                ]

            for chunk in chunks:
                # In a dry run, we estimate based on all potentially relevant agents.
                for _ in all_relevant_agents:
                    total_input_tokens += await cost_estimation.count_tokens(
                        chunk["code"], llm_config
                    )

    cost_details = cost_estimation.estimate_cost_for_prompt(
        llm_config, total_input_tokens
    )

    async with AsyncSessionLocal() as db:
        await ScanRepository(db).update_cost_and_status(
            scan_id, STATUS_PENDING_APPROVAL, cost_details
        )

    # Native LangGraph human-in-the-loop gate. The checkpointer persists
    # state here; execution resumes from this point when the approval
    # handler calls ainvoke(Command(resume=...)) on the same thread_id.
    # The resume payload lands as the return value of interrupt().
    approval_payload = interrupt(
        {
            "scan_id": str(scan_id),
            "estimated_cost": cost_details,
        }
    )

    logger.info(
        "Cost-approval gate resumed for scan %s with payload: %s",
        scan_id,
        approval_payload,
    )
    return {"current_scan_status": STATUS_QUEUED_FOR_SCAN}


async def _resolve_file_fix_conflicts(
    file_fixes: List[FixResult],
    file_content: str,
    reasoning_llm_config_id: uuid.UUID,
    owasp_rank_map: Dict[str, int],
    scan_id: uuid.UUID,
) -> List[FixResult]:
    """Given all proposed fixes for one file, return the non-overlapping set to apply.

    Extracted from the old `consolidation_node` (per-file loop) so the new
    single-pass `consolidate_and_patch_node` can call it over files in parallel
    after the analyze step has collected every fix against original content.

    Low-confidence and snippet-less fixes are dropped. Overlapping fixes are
    sent to the merge agent; non-overlapping fixes pass through unchanged.
    """
    if not file_fixes:
        return []

    sorted_fixes = sorted(file_fixes, key=lambda f: f.finding.line_number)
    fixes_to_apply: List[FixResult] = []
    confidence_map = {"High": 3, "Medium": 2, "Low": 1}

    i = 0
    while i < len(sorted_fixes):
        current_fix = sorted_fixes[i]

        if (current_fix.finding.confidence or "Medium").capitalize() == "Low":
            i += 1
            continue

        start_line = current_fix.finding.line_number
        if not current_fix.suggestion.original_snippet:
            i += 1
            continue
        end_line = (
            start_line + len(current_fix.suggestion.original_snippet.splitlines()) - 1
        )

        conflict_group = [current_fix]
        conflict_window_end_line = end_line
        j = i + 1
        while j < len(sorted_fixes):
            next_fix = sorted_fixes[j]
            if next_fix.finding.line_number <= conflict_window_end_line:
                if (
                    next_fix.finding.confidence or "Medium"
                ).capitalize() != "Low" and next_fix.suggestion.original_snippet:
                    conflict_group.append(next_fix)
                    conflict_window_end_line = max(
                        conflict_window_end_line,
                        next_fix.finding.line_number
                        + len(next_fix.suggestion.original_snippet.splitlines())
                        - 1,
                    )
                j += 1
            else:
                break

        winner: Optional[FixResult] = None
        if len(conflict_group) > 1:
            logger.info(
                f"Resolving conflict among {len(conflict_group)} fixes via Merge Agent for scan {scan_id}."
            )
            conflict_group.sort(
                key=lambda f: (
                    f.finding.cvss_score or 0,
                    owasp_rank_map.get(f.finding.cwe, 99),
                    confidence_map.get(
                        (f.finding.confidence or "Medium").capitalize(), 0
                    ),
                ),
                reverse=True,
            )
            if file_content:
                min_line = min(f.finding.line_number for f in conflict_group)
                max_line = max(
                    f.finding.line_number
                    + len(f.suggestion.original_snippet.splitlines())
                    - 1
                    for f in conflict_group
                )
                code_lines = file_content.splitlines(keepends=True)
                original_block = "".join(code_lines[min_line - 1 : max_line])

                winner = await _run_merge_agent(
                    reasoning_llm_config_id,
                    original_block,
                    conflict_group,
                    file_content,
                )

            # Fall back to highest-priority if merge agent fails or context missing.
            if not winner:
                winner = conflict_group[0]
        else:
            winner = current_fix

        if winner:
            winner.finding.is_applied_in_remediation = True
            fixes_to_apply.append(winner)

        i = j

    return fixes_to_apply


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
        f"Starting single-pass analysis for scan {scan_id} in '{scan_type}' mode."
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

    utility_llm_config_id = state.get("utility_llm_config_id")
    if not utility_llm_config_id:
        return {"error_message": "Orchestrator is missing 'utility_llm_config_id'."}

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
                f"{file_path} is a large file, applying chunking.",
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
                f"File analysis task failed for scan {scan_id}: {r}", exc_info=r
            )
            continue
        all_scan_findings.extend(r.get("findings", []))
        all_proposed_fixes.extend(r.get("fixes", []))

    logger.info(
        f"Single-pass analysis complete for scan {scan_id}: "
        f"{len(all_scan_findings)} findings, {len(all_proposed_fixes)} proposed fixes."
    )

    return {
        "findings": all_scan_findings,
        "proposed_fixes": all_proposed_fixes,
    }


async def consolidate_and_patch_node(state: WorkerState) -> Dict[str, Any]:
    """Terminal consolidation for REMEDIATE scans.

    Runs after `correlate_findings`. Groups the `proposed_fixes` collected by
    the single-pass analyzer by file, resolves per-file conflicts (line-range
    overlap detection + merge agent), applies the resolved fixes to the
    ORIGINAL file content in one pass, and builds the final file_map for the
    POST_REMEDIATION snapshot saved by `save_results_node`.

    For AUDIT mode this is a no-op. For SUGGEST mode we keep the correlated
    findings with their embedded `fixes` field (so the UI shows suggested
    fixes) but do not build a POST_REMEDIATION snapshot.
    """
    scan_id = state["scan_id"]
    scan_type = state["scan_type"]

    if scan_type != "REMEDIATE":
        return {}

    proposed_fixes = state.get("proposed_fixes") or []
    if not proposed_fixes:
        return {}

    reasoning_llm_id = state.get("reasoning_llm_config_id")
    if not reasoning_llm_id:
        return {
            "error_message": "consolidate_and_patch requires reasoning_llm_config_id."
        }

    live_codebase = state.get("live_codebase") or {}
    initial_file_map = state.get("initial_file_map") or {}

    # Group proposed fixes by file (they can only conflict within a file).
    fixes_by_file: Dict[str, List[FixResult]] = {}
    for fix in proposed_fixes:
        fp = fix.finding.file_path or ""
        if not fp:
            continue
        fixes_by_file.setdefault(fp, []).append(fix)

    # Pre-compute the OWASP rank map once for all files' conflict resolution.
    async with AsyncSessionLocal() as session:
        cwe_ids = list({f.finding.cwe for f in proposed_fixes if f.finding.cwe})
        owasp_rank_map: Dict[str, int] = {}
        if cwe_ids:
            stmt = select(CweOwaspMapping).where(CweOwaspMapping.cwe_id.in_(cwe_ids))
            result = await session.execute(stmt)
            owasp_rank_map = {
                mapping.cwe_id: mapping.owasp_rank for mapping in result.scalars().all()
            }

    final_file_map = dict(initial_file_map)
    applied_signatures: set[str] = set()

    # Patch + persist per file. The loop is sequential to keep the merge-agent
    # calls under our rate limiter's natural flow; parallelizing here would
    # require threading the semaphore through and the cost/latency win is
    # small vs. the analysis phase's many-agents-per-file parallelism.
    async with AsyncSessionLocal() as db:
        repo = ScanRepository(db)
        for file_path, file_fixes in fixes_by_file.items():
            file_content = live_codebase.get(file_path)
            if not file_content:
                continue

            resolved = await _resolve_file_fix_conflicts(
                file_fixes,
                file_content,
                reasoning_llm_id,
                owasp_rank_map,
                scan_id,
            )
            if not resolved:
                continue

            # Apply fixes in line-number order against the ORIGINAL content
            # (single pass — not iterative cross-file). Each fix's
            # original_snippet is expected to match the original file; if a
            # second fix's snippet already got replaced by an earlier one,
            # the merge agent should have been involved.
            patched_content = file_content
            for fix in sorted(resolved, key=lambda f: f.finding.line_number):
                snippet = fix.suggestion.original_snippet
                if snippet and snippet in patched_content:
                    patched_content = patched_content.replace(
                        snippet, fix.suggestion.code, 1
                    )
                    applied_signatures.add(
                        f"{file_path}|{fix.finding.cwe}|{fix.finding.line_number}"
                    )

            new_hashes = await repo.get_or_create_source_files(
                [
                    {
                        "path": file_path,
                        "content": patched_content,
                        "language": get_language_from_filename(file_path),
                    }
                ]
            )
            final_file_map[file_path] = new_hashes[0]

    # Propagate the applied flag onto the post-correlation findings so the
    # UI and downstream reporting can distinguish applied vs. dropped fixes.
    findings = list(state.get("findings", []))
    for f in findings:
        sig = f"{f.file_path}|{f.cwe}|{f.line_number}"
        if sig in applied_signatures:
            f.is_applied_in_remediation = True

    logger.info(
        f"consolidate_and_patch for scan {scan_id}: "
        f"patched {len(applied_signatures)} findings across "
        f"{len([p for p in final_file_map if p in fixes_by_file])} files."
    )

    return {"findings": findings, "final_file_map": final_file_map}


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

    return {"findings": correlated_findings}


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


async def handle_error_node(state: WorkerState) -> Dict[str, Any]:
    error = state.get("error_message", "An unknown error occurred.")
    scan_id = state["scan_id"]
    logger.error(
        f"Workflow for scan {scan_id} failed: {error}", extra={"error_message": error}
    )
    await ScanRepository(AsyncSessionLocal()).update_status(scan_id, STATUS_FAILED)
    return {}


# --- FINAL WORKFLOW WIRING ---
workflow = StateGraph(WorkerState)

# Define all nodes
workflow.add_node("retrieve_and_prepare_data", retrieve_and_prepare_data_node)
workflow.add_node("estimate_cost", estimate_cost_node)
workflow.add_node("analyze_files_parallel", analyze_files_parallel_node)
workflow.add_node("correlate_findings", correlate_findings_node)
workflow.add_node("consolidate_and_patch", consolidate_and_patch_node)
workflow.add_node("save_results", save_results_node)
workflow.add_node("save_final_report", save_final_report_node)
workflow.add_node("handle_error", handle_error_node)

# Build the graph
workflow.set_entry_point("retrieve_and_prepare_data")


def should_continue(state: WorkerState) -> str:
    return "handle_error" if state.get("error_message") else "continue"


def _route_after_retrieve(state: WorkerState) -> str:
    """Retrieval either fails early or proceeds to the cost-approval gate."""
    return "handle_error" if state.get("error_message") else "estimate_cost"


workflow.add_conditional_edges(
    "retrieve_and_prepare_data",
    _route_after_retrieve,
    {
        "estimate_cost": "estimate_cost",
        "handle_error": "handle_error",
    },
)

# estimate_cost_node calls interrupt(); the graph pauses there, persists
# state in the checkpointer, and yields. On approval, the worker calls
# ainvoke(Command(resume=...)) and execution continues directly to
# analyze_files_parallel. No DB-status-based routing — the graph shape
# encodes the pause/resume contract.
workflow.add_conditional_edges(
    "estimate_cost",
    should_continue,
    {"continue": "analyze_files_parallel", "handle_error": "handle_error"},
)

workflow.add_conditional_edges(
    "analyze_files_parallel",
    should_continue,
    {"continue": "correlate_findings", "handle_error": "handle_error"},
)
workflow.add_conditional_edges(
    "correlate_findings",
    should_continue,
    {"continue": "consolidate_and_patch", "handle_error": "handle_error"},
)
workflow.add_conditional_edges(
    "consolidate_and_patch",
    should_continue,
    {"continue": "save_results", "handle_error": "handle_error"},
)
workflow.add_conditional_edges(
    "save_results",
    should_continue,
    {"continue": "save_final_report", "handle_error": "handle_error"},
)
workflow.add_edge("save_final_report", END)
workflow.add_edge("handle_error", END)


_workflow: Optional[Pregel] = None
_checkpointer_conn: Optional[psycopg.AsyncConnection] = None


async def get_workflow() -> Pregel:
    global _workflow, _checkpointer_conn
    if _workflow is not None:
        return _workflow
    if not settings.ASYNC_DATABASE_URL:
        raise ValueError("ASYNC_DATABASE_URL must be configured.")
    if _checkpointer_conn is None or _checkpointer_conn.closed:
        logger.info("Creating new psycopg async connection for checkpointer...")
        try:
            conn_url = settings.ASYNC_DATABASE_URL.replace(
                "postgresql+asyncpg://", "postgresql://"
            )
            _checkpointer_conn = await psycopg.AsyncConnection.connect(conn_url)
        except Exception as e:
            logger.error(
                f"Failed to create psycopg async connection for checkpointer: {e}",
                exc_info=True,
            )
            raise
    checkpointer = AsyncPostgresSaver(conn=_checkpointer_conn)  # type: ignore
    _workflow = workflow.compile(checkpointer=checkpointer)
    logger.info("Main worker workflow compiled and ready with PostgreSQL checkpointer.")
    return _workflow


async def close_workflow_resources():
    global _checkpointer_conn
    if _checkpointer_conn and not _checkpointer_conn.closed:
        logger.info("Closing checkpointer database connection.")
        await _checkpointer_conn.close()
        _checkpointer_conn = None
