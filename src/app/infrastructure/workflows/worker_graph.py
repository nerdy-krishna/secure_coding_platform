# src/app/infrastructure/workflows/worker_graph.py
import asyncio
import logging
import psycopg
import uuid
import networkx as nx
from typing import Any, Dict, List, Optional, TypedDict, cast

from langchain_core.runnables import RunnableConfig
from langgraph.checkpoint.postgres.aio import AsyncPostgresSaver
from langgraph.graph import END, StateGraph
from langgraph.pregel import Pregel
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.orm import selectinload

from app.config.config import settings
from app.core.schemas import FixResult, FixSuggestion, SpecializedAgentState, VulnerabilityFinding, CodeChunk, MergedFixResponse
from app.infrastructure.database import AsyncSessionLocal
from app.infrastructure.database.models import CweOwaspMapping
from app.infrastructure.agents.generic_specialized_agent import build_generic_specialized_agent_graph
from app.infrastructure.agents.impact_reporting_agent import ImpactReportingAgentState, build_impact_reporting_agent_graph
from app.infrastructure.agents.symbol_map_agent import generate_symbol_map
from app.infrastructure.database import AsyncSessionLocal
from app.infrastructure.database import models as db_models
from app.infrastructure.database.repositories.llm_config_repo import LLMConfigRepository
from app.infrastructure.database.repositories.scan_repo import ScanRepository
from app.infrastructure.llm_client import get_llm_client
from app.shared.analysis_tools.context_bundler import ContextBundlingEngine
from app.shared.analysis_tools.repository_map import RepositoryMappingEngine
from app.shared.analysis_tools.chunker import semantic_chunker
from app.shared.lib.files import get_language_from_filename
from app.shared.lib import cost_estimation

logger = logging.getLogger(__name__)

CONCURRENT_LLM_LIMIT = 5
CHUNK_TOKEN_THRESHOLD = 4000

# --- Status Constants ---
STATUS_PENDING_APPROVAL = "PENDING_COST_APPROVAL"
STATUS_QUEUED = "QUEUED"
STATUS_QUEUED_FOR_SCAN = "QUEUED_FOR_SCAN"
STATUS_ANALYZING_CONTEXT = "ANALYZING_CONTEXT"
STATUS_RUNNING_AGENTS = "RUNNING_AGENTS"
STATUS_GENERATING_REPORTS = "GENERATING_REPORTS"
STATUS_REMEDIATION_COMPLETED = "REMEDIATION_COMPLETED"
STATUS_COMPLETED = "COMPLETED"

class RelevantAgent(TypedDict):
    name: str
    description: str
    domain_query: Dict[str, Any]

class TriageResult(BaseModel):
    relevant_agent_names: List[str] = Field(description="A list of the names of the agents that are relevant for analyzing the given file.")

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
    triaged_agents_per_file: Dict[str, List[RelevantAgent]]
    live_codebase: Optional[Dict[str, str]]
    findings: List[VulnerabilityFinding]
    agent_results: Optional[List[Dict[str, Any]]]
    impact_report: Optional[Dict[str, Any]]
    sarif_report: Optional[Dict[str, Any]]
    error_message: Optional[str]

# --- WORKFLOW NODES ---

async def retrieve_and_prepare_data_node(state: WorkerState) -> Dict[str, Any]:
    """
    Node to retrieve all initial data, create the repo map, and dependency graph.
    """
    scan_id = state['scan_id']
    logger.info(f"Entering node to retrieve and prepare data for scan {scan_id}.")
    try:
        async with AsyncSessionLocal() as db:
            repo = ScanRepository(db)
            
            # --- FETCH SCAN FIRST to get its status ---
            scan = await repo.get_scan_with_details(scan_id)
            if not scan: return {"error_message": f"Scan with ID {scan_id} not found."}
            
            # Capture the status before updating the DB
            current_status = scan.status

            # Now, update the status to show progress
            await repo.update_status(scan_id, STATUS_ANALYZING_CONTEXT)

            original_snapshot = next((s for s in scan.snapshots if s.snapshot_type == "ORIGINAL_SUBMISSION"), None)
            if not original_snapshot: return {"error_message": f"Original code snapshot not found for scan {scan_id}."}

            files_map = await repo.get_source_files_by_hashes(list(original_snapshot.file_map.values()))
            files = {path: files_map.get(h, "") for path, h in original_snapshot.file_map.items()}

            # Create Repo Map
            mapping_engine = RepositoryMappingEngine()
            repository_map = mapping_engine.create_map(files)
            logger.info(f"DEBUG: repository_map content: {repository_map.model_dump()}")

            # Create Dependency Graph
            bundling_engine = ContextBundlingEngine(repository_map, files)
            dependency_graph = bundling_engine.graph 
            logger.info(f"DEBUG: dependency_graph content: {nx.node_link_data(dependency_graph)}")

            # Determine Relevant Agents
            framework_details = await db.execute(
                select(db_models.Framework).options(selectinload(db_models.Framework.agents)).where(db_models.Framework.name.in_(scan.frameworks or []))
            )
            # Store full agent details for the triage step
            all_relevant_agents = {agent.name: RelevantAgent(name=agent.name, description=agent.description, domain_query=agent.domain_query) for framework in framework_details.scalars().all() for agent in framework.agents}

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
                "triaged_agents_per_file": {}, # To be populated by triage node
                "findings": [],
                "all_relevant_agents": all_relevant_agents, # Temp field for triage
            }
    except Exception as e:
        logger.error(f"Error preparing data for scan {scan_id}: {e}", exc_info=True)
        return {"error_message": str(e)}


async def _run_merge_agent(
    reasoning_llm_config_id: uuid.UUID,
    code_block: str,
    conflicting_fixes: List[FixResult],
    code_to_search_in: str,
) -> Optional[FixResult]:
    """
    Invokes an LLM to merge multiple conflicting fix suggestions into a single, superior fix.
    Includes verification and retry logic.
    """
    llm_client = await get_llm_client(reasoning_llm_config_id)
    if not llm_client:
        return None

    logger.info(f"DEBUG: _run_merge_agent code_block:\n{code_block}")
    logger.info(f"DEBUG: _run_merge_agent conflicting_fixes: {[fix.model_dump() for fix in conflicting_fixes]}")
    logger.info(f"DEBUG: _run_merge_agent code_to_search_in (first 500 chars): {code_to_search_in[:500]}")

    # Use the highest-priority finding as the basis for the merged finding metadata
    winner = conflicting_fixes[0]

    suggestions_str = ""
    for i, fix in enumerate(conflicting_fixes):
        suggestions_str += f"--- Suggestion {i+1} (Severity: {fix.finding.severity}, CWE: {fix.finding.cwe}) ---\n"
        suggestions_str += f"Description: {fix.finding.description}\n"
        suggestions_str += f"Fix:\n```\n{fix.suggestion.code}\n```\n\n"

    prompt = f"""
You are an expert security engineer. Your task is to merge multiple suggested fixes into a single, cohesive, and secure block of code.
The final code must address ALL the identified vulnerabilities if possible.
If fixes are mutually exclusive, prioritize the change that resolves the highest severity vulnerability.

ORIGINAL VULNERABLE CODE BLOCK:

{code_block}

CONFLICTING SUGGESTIONS:
{suggestions_str}

Respond ONLY with a valid JSON object conforming to the MergedFixResponse schema.
The `merged_code` you provide must be a surgical, drop-in replacement for the ORIGINAL VULNERABLE CODE BLOCK. It must ONLY contain the specific lines that are changing. Do not include surrounding, unchanged code like function definitions or block delimiters.
Crucially, the `original_snippet_for_replacement` field in your JSON response MUST be an EXACT, character-for-character copy of the 'ORIGINAL VULNERABLE CODE BLOCK' provided above.
The `merged_code` field should contain ONLY the final, corrected code that will replace the original block. DO NOT include the original code in the `merged_code` field.
"""
    for attempt in range(3): # 1 initial try + 2 retries
        response = await llm_client.generate_structured_output(prompt, MergedFixResponse)
        
        if (
            response.parsed_output and 
            isinstance(response.parsed_output, MergedFixResponse) and
            response.parsed_output.original_snippet_for_replacement in code_to_search_in
        ):
            logger.info(f"Merge agent produced a verified snippet on attempt {attempt + 1}.")
            # Create a new FixResult representing the merged fix
            merged_finding = winner.finding.model_copy(deep=True)

            # --- START: Build detailed explanation ---
            conflicts_summary = "The following conflicting suggestions were considered:\n"
            for i, fix in enumerate(conflicting_fixes):
                conflicts_summary += f"- Suggestion {i+1} (CWE: {fix.finding.cwe}, Severity: {fix.finding.severity}): {fix.finding.remediation}\n"
            
            final_explanation = f"{conflicts_summary}\nMerge Reasoning:\n{response.parsed_output.explanation}"
            # --- END: Build detailed explanation ---

            merged_finding.description = final_explanation # Update description with the detailed explanation
            
            merged_suggestion = FixSuggestion(
                description=final_explanation,
                original_snippet=response.parsed_output.original_snippet_for_replacement,
                code=response.parsed_output.merged_code,
            )

            logger.info(f"DEBUG: _run_merge_agent merged_suggestion: {merged_suggestion.model_dump()}")
            return FixResult(finding=merged_finding, suggestion=merged_suggestion)
        
        logger.warning(f"Merge agent failed to produce a valid, verifiable snippet on attempt {attempt + 1}.")

    logger.error("Merge agent failed after 3 attempts. Falling back to highest priority fix.")
    return None


async def triage_agents_node(state: WorkerState) -> Dict[str, Any]:
    """
    Uses a lightweight LLM to determine which specialized agents are relevant for each file.
    """
    scan_id = state['scan_id']
    logger.info(f"Entering triage node for scan {scan_id}.")
    
    repository_map = state.get('repository_map')
    all_relevant_agents = state.get('all_relevant_agents', {})
    utility_llm_config_id = state.get('utility_llm_config_id')

    if not all_relevant_agents or not utility_llm_config_id or not repository_map:
        return {"error_message": "Triage node is missing required inputs (agents, llm_config, or repository_map)."}

    llm_client = await get_llm_client(utility_llm_config_id)
    if not llm_client:
        return {"error_message": "Failed to initialize utility LLM client for triage."}

    agent_descriptions = "\n".join([f"- **{agent['name']}**: {agent['description']}" for agent in all_relevant_agents.values()])
    logger.info(f"DEBUG: agent_descriptions content:\n{agent_descriptions}")
    triaged_agents_per_file = {}

    for file_path, file_summary in repository_map.files.items():
        if not file_summary.symbols:
            # If file has no parsable symbols, assume all agents are potentially relevant
            triaged_agents_per_file[file_path] = list(all_relevant_agents.values())
            continue
        
        file_summary_text = f"File: `{file_path}`\nSymbols:\n" + "\n".join([f"- {s.type} {s.name}" for s in file_summary.symbols])
        logger.info(f"DEBUG: file_summary_text for {file_path}:\n{file_summary_text}")
        
        prompt = f"""
Based on the following summary of a code file, select the most relevant security agents to run from the provided list.

FILE SUMMARY:
{file_summary_text}

AVAILABLE AGENTS:
{agent_descriptions}

Your task is to return a JSON object containing a list of the names of the agents that are most relevant for analyzing this specific file.
Respond ONLY with a valid JSON object conforming to the TriageResult schema.
"""
        try:
            response = await llm_client.generate_structured_output(prompt, TriageResult)
            logger.info(f"DEBUG: Triage LLM response for {file_path}: {response.parsed_output.model_dump() if response.parsed_output else 'None'}")
            if response.parsed_output and isinstance(response.parsed_output, TriageResult):
                relevant_names = response.parsed_output.relevant_agent_names
                triaged_agents_per_file[file_path] = [all_relevant_agents[name] for name in relevant_names if name in all_relevant_agents]
            else:
                logger.warning(f"Triage LLM failed for {file_path}. Defaulting to all agents. Error: {response.error}")
                triaged_agents_per_file[file_path] = list(all_relevant_agents.values())
        except Exception as e:
            logger.error(f"Exception during triage for {file_path}: {e}. Defaulting to all agents.")
            triaged_agents_per_file[file_path] = list(all_relevant_agents.values())
            
    logger.info(f"DEBUG: final triaged_agents_per_file content: {triaged_agents_per_file}")
    return {"triaged_agents_per_file": triaged_agents_per_file}


async def estimate_cost_node(state: WorkerState) -> Dict[str, Any]:
    """
    Performs a dry run of the analysis to generate a highly accurate cost estimate.
    """
    scan_id = state['scan_id']
    logger.info(f"Performing cost estimation dry run for scan {scan_id}.")

    # --- REVISED GUARD CLAUSE BLOCK ---
    repository_map = state.get('repository_map')
    if not repository_map: return {"error_message": "Cost estimation missing 'repository_map'."}

    dependency_graph_data = state.get('dependency_graph')
    if not dependency_graph_data: return {"error_message": "Cost estimation missing 'dependency_graph'."}

    reasoning_llm_config_id = state.get('reasoning_llm_config_id')
    if not reasoning_llm_config_id: return {"error_message": "Cost estimation missing 'reasoning_llm_config_id'."}
    
    live_codebase = state.get('live_codebase')
    if not live_codebase: return {"error_message": "Cost estimation missing 'live_codebase'."}
    
    all_relevant_agents = state.get('all_relevant_agents')
    if not all_relevant_agents: return {"error_message": "Cost estimation missing 'all_relevant_agents'."}
    # --- END REVISED GUARD CLAUSE BLOCK ---

    try:
        dependency_graph = nx.node_link_graph(dependency_graph_data)
        processing_order = list(nx.topological_sort(dependency_graph))  
    except nx.NetworkXUnfeasible:
        processing_order = sorted(list(live_codebase.keys()))

    total_input_tokens = 0
    async with AsyncSessionLocal() as db:
        llm_config = await LLMConfigRepository(db).get_by_id_with_decrypted_key(reasoning_llm_config_id)
        if not llm_config:
            return {"error_message": f"LLM Config {reasoning_llm_config_id} not found for cost estimation."}

        for file_path in processing_order:
            file_content = live_codebase[file_path]
            file_summary = repository_map.files.get(file_path)
            if not file_summary: continue

            chunks: List[CodeChunk] = []
            if (len(file_content) / 4) > CHUNK_TOKEN_THRESHOLD:
                chunks = semantic_chunker(file_content, file_summary)
            else:
                chunks = [{"symbol_name": file_path, "code": file_content, "start_line": 1, "end_line": 1}]

            for chunk in chunks:
                # In a dry run, we estimate based on all potentially relevant agents.
                for _ in all_relevant_agents:
                    total_input_tokens += cost_estimation.count_tokens(chunk['code'], llm_config)

    cost_details = cost_estimation.estimate_cost_for_prompt(llm_config, total_input_tokens)
    
    async with AsyncSessionLocal() as db:
        await ScanRepository(db).update_cost_and_status(scan_id, STATUS_PENDING_APPROVAL, cost_details)

    return {}


async def consolidation_node(state: WorkerState) -> Dict[str, Any]:
    """
    Consolidates agent results.
    - Returns ALL findings, regardless of mode.
    - For REMEDIATE mode, it identifies overlapping fixes, uses an LLM to merge them,
      and returns a list of final, non-overlapping fixes to be applied.
    """
    scan_id = state['scan_id']
    scan_type = state['scan_type']
    agent_results = state.get("agent_results") or []
    reasoning_llm_config_id = state.get("reasoning_llm_config_id")

    all_findings = [
        item for sublist in (res.get("findings", []) for res in agent_results) for item in sublist
    ]
    all_fixes = [
        item for sublist in (res.get("fixes", []) for res in agent_results) for item in sublist
    ]

    # For AUDIT/SUGGEST modes, or if no fixes were generated, return all findings and no fixes to apply.
    if scan_type != "REMEDIATE" or not all_fixes:
        return {"findings": all_findings, "fixes_to_apply": []}
    
    if not reasoning_llm_config_id:
        return {"error_message": "Consolidation node requires reasoning_llm_config_id for REMEDIATE mode."}

    # --- New Prioritized Fix Selection & Merging Logic for REMEDIATE mode ---
    sorted_fixes = sorted(all_fixes, key=lambda f: f.finding.line_number)
    fixes_to_apply: List[FixResult] = []
    
    confidence_map = {"High": 3, "Medium": 2, "Low": 1}

    async with AsyncSessionLocal() as session:
        cwe_ids = list(set([f.finding.cwe for f in sorted_fixes]))
        stmt = select(CweOwaspMapping).where(CweOwaspMapping.cwe_id.in_(cwe_ids))
        result = await session.execute(stmt)
        owasp_rank_map = {mapping.cwe_id: mapping.owasp_rank for mapping in result.scalars().all()}

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
        end_line = start_line + len(current_fix.suggestion.original_snippet.splitlines()) - 1

        conflict_group = [current_fix]
        conflict_window_end_line = end_line
        j = i + 1
        while j < len(sorted_fixes):
            next_fix = sorted_fixes[j]
            if next_fix.finding.line_number <= conflict_window_end_line:
                if (next_fix.finding.confidence or "Medium").capitalize() != "Low" and next_fix.suggestion.original_snippet:
                    conflict_group.append(next_fix)
                    conflict_window_end_line = max(conflict_window_end_line, next_fix.finding.line_number + len(next_fix.suggestion.original_snippet.splitlines()) - 1)
                j += 1
            else:
                break
        
        winner = None
        if len(conflict_group) > 1:
            logger.info(f"Resolving conflict among {len(conflict_group)} fixes via Merge Agent for scan {scan_id}.")
            
            conflict_group.sort(
                key=lambda f: (
                    f.finding.cvss_score or 0,
                    owasp_rank_map.get(f.finding.cwe, 99),
                    confidence_map.get((f.finding.confidence or "Medium").capitalize(), 0)
                ),
                reverse=True
            )
            
            # Since the orchestrator passes the full file for verification, we can use it here.
            # Note: This assumes all conflicts are within the same file, which is guaranteed by the logic.
            code_to_search = state.get("file_content_for_verification", "")
            if code_to_search:
                # Determine the full code block spanning all conflicting fixes
                min_line = min(f.finding.line_number for f in conflict_group)
                max_line = max(f.finding.line_number + len(f.suggestion.original_snippet.splitlines()) -1 for f in conflict_group)
                code_lines = code_to_search.splitlines(keepends=True)
                original_block = "".join(code_lines[min_line-1:max_line])

                winner = await _run_merge_agent(reasoning_llm_config_id, original_block, conflict_group, code_to_search)
            
            # Fallback to highest-priority if merge agent fails or context is missing
            if not winner:
                winner = conflict_group[0]
        else:
            winner = current_fix
        
        if winner:
            winner.finding.is_applied_in_remediation = True
            fixes_to_apply.append(winner)
        
        i = j

    logger.info(f"Consolidated fixes for scan {scan_id}: from {len(all_fixes)} to {len(fixes_to_apply)} non-overlapping fixes.")
    
    # Return ALL findings, but only the winning fixes to be applied.
    return {"findings": all_findings, "fixes_to_apply": fixes_to_apply}


async def dependency_aware_analysis_orchestrator(state: WorkerState) -> Dict[str, Any]:
    """
    The main orchestrator node that processes files based on their dependency order.
    """
    scan_id, scan_type = state['scan_id'], state['scan_type']
    logger.info(f"Starting dependency-aware analysis for scan {scan_id} in '{scan_type}' mode.")
    
    # --- REVISED GUARD CLAUSE BLOCK ---
    live_codebase = state.get('live_codebase')
    if not live_codebase: return {"error_message": "Orchestrator is missing 'live_codebase'."}

    repository_map = state.get('repository_map')
    if not repository_map: return {"error_message": "Orchestrator is missing 'repository_map'."}

    graph_data = state.get('dependency_graph')
    if not graph_data: return {"error_message": "Orchestrator is missing 'dependency_graph'."}
    dependency_graph = nx.node_link_graph(graph_data) # Deserialize the graph

    triaged_agents_per_file = state.get('triaged_agents_per_file')
    if not triaged_agents_per_file: return {"error_message": "Orchestrator is missing 'triaged_agents_per_file'."}

    utility_llm_config_id = state.get('utility_llm_config_id')
    if not utility_llm_config_id: return {"error_message": "Orchestrator is missing 'utility_llm_config_id'."}
    
    reasoning_llm_id = state.get('reasoning_llm_config_id')
    if not reasoning_llm_id: return {"error_message": "Orchestrator is missing 'reasoning_llm_config_id'."}
    # --- END REVISED GUARD CLAUSE BLOCK ---
    
    await ScanRepository(AsyncSessionLocal()).update_status(scan_id, STATUS_RUNNING_AGENTS)
    
    try:
        processing_order = list(nx.topological_sort(dependency_graph))
    except nx.NetworkXUnfeasible:
        logger.warning(f"Circular dependency in scan {scan_id}, falling back to alphabetical order.")
        processing_order = sorted(list(dependency_graph.nodes()))

    all_scan_findings: List[VulnerabilityFinding] = []
    generic_agent_graph = build_generic_specialized_agent_graph()
    semaphore = asyncio.Semaphore(CONCURRENT_LLM_LIMIT)
    
    # Initialize the file map for REMEDIATE scans from the correct source
    initial_file_map = state.get('initial_file_map')
    current_file_map = initial_file_map.copy() if scan_type == 'REMEDIATE' and initial_file_map else {}

    async with AsyncSessionLocal() as db:
        repo = ScanRepository(db)

        for file_path in processing_order:
            # For REMEDIATE scans, fetch the latest version of the file from DB using the map
            if scan_type == 'REMEDIATE':
                file_hash = current_file_map.get(file_path)
                if not file_hash: continue
                content_map = await repo.get_source_files_by_hashes([file_hash])
                file_content = content_map.get(file_hash, "")
            else:
                file_content = live_codebase[file_path]

            file_summary = repository_map.files.get(file_path)
            if not file_summary: continue

            token_count = len(file_content) / 4
            is_large_file = token_count > CHUNK_TOKEN_THRESHOLD
            
            chunks: List[CodeChunk] = []
            if is_large_file:
                logger.info(f"{file_path} is a large file, applying chunking.", extra={"scan_id": str(scan_id)})
                chunks = semantic_chunker(file_content, file_summary)
            else:
                chunks = [{"symbol_name": file_path, "code": file_content, "start_line": 1, "end_line": len(file_content.splitlines())}]

            relevant_agents_for_file = triaged_agents_per_file.get(file_path, [])
            if not relevant_agents_for_file:
                logger.info(f"No agents triaged for file {file_path}, skipping.", extra={"scan_id": str(scan_id)})
                continue

            findings_for_file: List[VulnerabilityFinding] = []

            for chunk in chunks:
                tasks = []
                for agent in relevant_agents_for_file:
                    async def run_with_semaphore(coro):
                        async with semaphore: return await coro
                    
                    initial_agent_state: SpecializedAgentState = {
                        "scan_id": scan_id, "llm_config_id": reasoning_llm_id, "filename": file_path,
                        "code_snippet": chunk['code'], "file_content_for_verification": file_content,
                        "workflow_mode": "remediate" if scan_type in ("REMEDIATE", "SUGGEST") else "audit",
                        "findings": [], "fixes": [], "error": None
                    }
                    tasks.append(run_with_semaphore(generic_agent_graph.ainvoke(initial_agent_state, config={"configurable": cast(dict, agent)})))
                
                agent_raw_results = await asyncio.gather(*tasks, return_exceptions=True)
                agent_results = [r for r in agent_raw_results if not isinstance(r, BaseException) and r is not None]
                
                for result in agent_results:
                    findings_for_file.extend(result.get("findings", []))

            # --- HYBRID LOGIC ---
            if scan_type == 'REMEDIATE' and findings_for_file:
                # 1. Save raw findings for this file
                await repo.save_findings(scan_id, findings_for_file)
                
                # 2. Retrieve them to get DB IDs and state
                retrieved_findings_db = await repo.get_findings_for_scan_and_file(scan_id, file_path)
                retrieved_findings = [VulnerabilityFinding.model_validate(f, from_attributes=True) for f in retrieved_findings_db]

                # 3. Consolidate fixes
                temp_state_for_consolidation = cast(WorkerState, {
                    "scan_id": scan_id, "scan_type": scan_type,
                    "reasoning_llm_config_id": reasoning_llm_id,
                    "file_content_for_verification": file_content,
                    # agent_results is needed for the FixResult structure
                    "agent_results": [{"findings": retrieved_findings, "fixes": [FixResult(finding=f, suggestion=f.fixes) for f in retrieved_findings if f.fixes]}]
                })
                consolidation_result = await consolidation_node(temp_state_for_consolidation)
                fixes_to_apply = consolidation_result.get("fixes_to_apply", [])

                # 4. Apply patch and propagate state via DB
                if fixes_to_apply:
                    temp_file_content = file_content
                    applied_finding_ids = []
                    for fix in sorted(fixes_to_apply, key=lambda f: f.finding.line_number):
                        applied_finding_ids.append(fix.finding.id)
                        if fix.suggestion.original_snippet and fix.suggestion.original_snippet in temp_file_content:
                            temp_file_content = temp_file_content.replace(fix.suggestion.original_snippet, fix.suggestion.code, 1)
                    
                    # Persist the new file content and update the in-memory map
                    new_hashes = await repo.get_or_create_source_files([{"path": file_path, "content": temp_file_content, "language": get_language_from_filename(file_path)}])
                    current_file_map[file_path] = new_hashes[0]
                    
                    # Mark the applied findings in the DB
                    await repo.mark_findings_as_applied(applied_finding_ids)

                all_scan_findings.extend(retrieved_findings)
            else:
                all_scan_findings.extend(findings_for_file)

    return {"findings": all_scan_findings, "final_file_map": current_file_map if scan_type == 'REMEDIATE' else None}


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
        if len(group) == 1:
            # If only one agent found it, just use it as is but format agents as a list
            final_finding = group[0]
            final_finding.corroborating_agents = [final_finding.agent_name] if final_finding.agent_name else []
            correlated_findings.append(final_finding)
        else:
            # If multiple agents found it, merge them
            # Use the finding from the group with the highest severity as the base
            base_finding = max(group, key=lambda f: {"High": 3, "Medium": 2, "Low": 1}.get(f.severity, 0))
            
            # Create a new merged finding
            merged_finding = base_finding.model_copy(deep=True)
            merged_finding.confidence = "High" # Confidence is high due to corroboration
            merged_finding.corroborating_agents = sorted(list(set(f.agent_name for f in group if f.agent_name)))
            
            # FIX: Preserve the 'is_applied_in_remediation' flag from the group.
            if any(f.is_applied_in_remediation for f in group):
                merged_finding.is_applied_in_remediation = True
            
            # You could potentially merge descriptions or other fields here if needed
            correlated_findings.append(merged_finding)
            
    return {"findings": correlated_findings}


async def save_results_node(state: WorkerState) -> Dict[str, Any]:
    scan_id = state['scan_id']
    scan_type = state['scan_type']
    findings = state.get('findings', [])
    final_file_map = state.get('final_file_map')

    logger.info(f"Saving final results for scan {scan_id}.")
    async with AsyncSessionLocal() as db:
        repo = ScanRepository(db)
        
        if findings:
            if scan_type in ('AUDIT', 'SUGGEST'):
                # For these modes, we do a bulk insert of new, correlated findings
                await repo.save_findings(scan_id, findings)
            else: # For REMEDIATE, we update the existing findings with correlation data
                await repo.update_correlated_findings(findings)
            
        if scan_type == 'REMEDIATE' and final_file_map:
            logger.info(f"Saving POST_REMEDIATION snapshot for scan {scan_id}.")
            await repo.create_code_snapshot(scan_id=scan_id, file_map=final_file_map, snapshot_type="POST_REMEDIATION")
            
    return {}

async def run_impact_reporting(state: WorkerState) -> Dict[str, Any]:
    scan_id = state['scan_id']
    logger.info(f"Entering node to run ImpactReportingAgent for scan {scan_id}.")
    await ScanRepository(AsyncSessionLocal()).update_status(scan_id, STATUS_GENERATING_REPORTS)
    reporting_input_state: ImpactReportingAgentState = {
        "scan_id": scan_id, "llm_config_id": state.get("reasoning_llm_config_id"),
        "findings": state.get("findings", []), "impact_report": None, "sarif_report": None, "error": None
    }
    report_output_state = await build_impact_reporting_agent_graph().ainvoke(reporting_input_state)
    if report_output_state.get("error"):
        return {"error_message": f"ImpactReportingAgent failed: {report_output_state['error']}"}
    return {"impact_report": report_output_state.get("impact_report"), "sarif_report": report_output_state.get("sarif_report")}

async def save_final_report_node(state: WorkerState) -> Dict[str, Any]:
    scan_id, impact_report, sarif_report, findings = state["scan_id"], state.get("impact_report"), state.get("sarif_report"), state.get("findings", [])
    logger.info(f"Saving final reports and risk score for scan {scan_id}.")
    severity_map = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFORMATIONAL": 0}
    for f in findings:
        sev = (f.severity or "LOW").upper()
        if sev in severity_map: severity_map[sev] += 1
    # Risk score calculation...
    risk_score = 0
    if severity_map["CRITICAL"] > 0: risk_score = 9 + (severity_map["CRITICAL"] * 0.1)
    elif severity_map["HIGH"] > 0: risk_score = 7 + (severity_map["HIGH"] * 0.1)
    elif severity_map["MEDIUM"] > 0: risk_score = 4 + (severity_map["MEDIUM"] * 0.1)
    elif severity_map["LOW"] > 0: risk_score = 1 + (severity_map["LOW"] * 0.1)
    final_risk_score = min(10, int(round(risk_score, 0)))

    summary_data = {
        "summary": {"total_findings_count": len(findings), "files_analyzed_count": len(set(f.file_path for f in findings)), "severity_counts": severity_map},
        "overall_risk_score": {"score": final_risk_score, "severity": "High"}
    }
    final_status = STATUS_REMEDIATION_COMPLETED if state.get('scan_type') == 'REMEDIATE' else STATUS_COMPLETED
    await ScanRepository(AsyncSessionLocal()).save_final_reports_and_status(scan_id=scan_id, status=final_status, impact_report=impact_report, sarif_report=sarif_report, summary=summary_data, risk_score=final_risk_score)
    return {}

async def handle_error_node(state: WorkerState) -> Dict[str, Any]:
    error = state.get("error_message", "An unknown error occurred.")
    scan_id = state['scan_id']
    logger.error(f"Workflow for scan {scan_id} failed: {error}", extra={"error_message": error})
    await ScanRepository(AsyncSessionLocal()).update_status(scan_id, "Failed")
    return {}

# --- FINAL WORKFLOW WIRING ---
workflow = StateGraph(WorkerState)

# Define all nodes
workflow.add_node("retrieve_and_prepare_data", retrieve_and_prepare_data_node)
workflow.add_node("estimate_cost", estimate_cost_node)
workflow.add_node("triage_agents", triage_agents_node)
workflow.add_node("dependency_aware_analysis_orchestrator", dependency_aware_analysis_orchestrator)
workflow.add_node("correlate_findings", correlate_findings_node)
workflow.add_node("save_results", save_results_node)
workflow.add_node("run_impact_reporting", run_impact_reporting)
workflow.add_node("save_final_report", save_final_report_node)
workflow.add_node("handle_error", handle_error_node)

# Build the graph
workflow.set_entry_point("retrieve_and_prepare_data")

def should_continue(state: WorkerState) -> str:
    return "handle_error" if state.get("error_message") else "continue"

def should_estimate_cost_or_run(state: WorkerState) -> str:
    """Routes new scans to cost estimation and approved scans to analysis."""
    if state.get("error_message"):
        return "handle_error"
    
    # This value is fetched from the DB in the first step
    status = state.get("current_scan_status")
    if status == "QUEUED":
        return "estimate_cost"
    elif status == "QUEUED_FOR_SCAN":
        return "run_analysis"
    else:
        logger.error(f"Routing failed due to unexpected status: {status}")
        return "handle_error"

workflow.add_conditional_edges(
    "retrieve_and_prepare_data",
    should_estimate_cost_or_run,
    {
        "estimate_cost": "estimate_cost",
        "run_analysis": "triage_agents",
        "handle_error": "handle_error"
    }
)

# After estimation, the workflow ends, awaiting user approval
workflow.add_edge("estimate_cost", END)

workflow.add_conditional_edges(
    "triage_agents",
    should_continue,
    {"continue": "dependency_aware_analysis_orchestrator", "handle_error": "handle_error"}
)

workflow.add_conditional_edges(
    "dependency_aware_analysis_orchestrator",
    should_continue,
    {"continue": "correlate_findings", "handle_error": "handle_error"}
)
workflow.add_conditional_edges(
    "correlate_findings",
    should_continue,
    {"continue": "save_results", "handle_error": "handle_error"}
)
workflow.add_conditional_edges(
    "save_results",
    should_continue,
    {"continue": "save_final_report", "handle_error": "handle_error"}
)
workflow.add_edge("save_final_report", END)
workflow.add_edge("handle_error", END)


_workflow: Optional[Pregel] = None
_checkpointer_conn: Optional[psycopg.AsyncConnection] = None

async def get_workflow() -> Pregel:
    global _workflow, _checkpointer_conn
    if _workflow is not None: return _workflow
    if not settings.ASYNC_DATABASE_URL: raise ValueError("ASYNC_DATABASE_URL must be configured.")
    if _checkpointer_conn is None or _checkpointer_conn.closed:
        logger.info("Creating new psycopg async connection for checkpointer...")
        try:
            conn_url = settings.ASYNC_DATABASE_URL.replace("postgresql+asyncpg://", "postgresql://")
            _checkpointer_conn = await psycopg.AsyncConnection.connect(conn_url)
        except Exception as e:
            logger.error(f"Failed to create psycopg async connection for checkpointer: {e}", exc_info=True)
            raise
    checkpointer = AsyncPostgresSaver(conn=_checkpointer_conn) # type: ignore
    _workflow = workflow.compile(checkpointer=checkpointer)
    logger.info("Main worker workflow compiled and ready with PostgreSQL checkpointer.")
    return _workflow

async def close_workflow_resources():
    global _checkpointer_conn
    if _checkpointer_conn and not _checkpointer_conn.closed:
        logger.info("Closing checkpointer database connection.")
        await _checkpointer_conn.close()
        _checkpointer_conn = None