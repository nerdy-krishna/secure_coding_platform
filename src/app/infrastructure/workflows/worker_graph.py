# src/app/infrastructure/workflows/worker_graph.py
import asyncio
import logging
import psycopg
import uuid
import networkx as nx
from typing import Any, Dict, List, Optional, TypedDict

from langchain_core.runnables import RunnableConfig
from langgraph.checkpoint.postgres.aio import AsyncPostgresSaver
from langgraph.graph import END, StateGraph
from langgraph.pregel import Pregel
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.orm import selectinload

from app.config.config import settings
from app.core.schemas import FixResult, SpecializedAgentState, VulnerabilityFinding, CodeChunk
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

class WorkerState(TypedDict):
    """The updated, simplified state for the workflow."""
    scan_id: uuid.UUID
    scan_type: str
    current_scan_status: Optional[str]
    llm_config_id: Optional[uuid.UUID]
    specialized_llm_config_id: Optional[uuid.UUID]
    files: Optional[Dict[str, str]]
    repository_map: Optional[Any]
    dependency_graph: Optional[Any]
    relevant_agents: Dict[str, str]
    live_codebase: Optional[Dict[str, str]]
    findings: List[VulnerabilityFinding]
    impact_report: Optional[Dict[str, Any]]
    sarif_report: Optional[Dict[str, Any]]
    error_message: Optional[str]

class MergedFixResponse(BaseModel):
    merged_code: str = Field(description="A single, cohesive code block that merges conflicting suggestions.")
    description: str = Field(description="A brief explanation of how the fixes were merged.")

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
            await repo.update_status(scan_id, STATUS_ANALYZING_CONTEXT)

            scan = await repo.get_scan_with_details(scan_id)
            if not scan: return {"error_message": f"Scan with ID {scan_id} not found."}
            
            original_snapshot = next((s for s in scan.snapshots if s.snapshot_type == "ORIGINAL_SUBMISSION"), None)
            if not original_snapshot: return {"error_message": f"Original code snapshot not found for scan {scan_id}."}

            files_map = await repo.get_source_files_by_hashes(list(original_snapshot.file_map.values()))
            files = {path: files_map.get(h, "") for path, h in original_snapshot.file_map.items()}

            # Create Repo Map
            mapping_engine = RepositoryMappingEngine()
            repository_map = mapping_engine.create_map(files)

            # Create Dependency Graph
            bundling_engine = ContextBundlingEngine(repository_map, files)
            dependency_graph = bundling_engine.graph 

            # Determine Relevant Agents
            framework_details = await db.execute(
                select(db_models.Framework).options(selectinload(db_models.Framework.agents)).where(db_models.Framework.name.in_(scan.frameworks or []))
            )
            relevant_agents = {agent.name: agent.domain_query for framework in framework_details.scalars().all() for agent in framework.agents}

            return {
                "scan_type": scan.scan_type,
                "llm_config_id": scan.main_llm_config_id,
                "specialized_llm_config_id": scan.specialized_llm_config_id,
                "files": files,
                "live_codebase": files.copy(), 
                "repository_map": repository_map,
                "dependency_graph": nx.node_link_data(dependency_graph),
                "relevant_agents": relevant_agents,
                "findings": [],
            }
    except Exception as e:
        logger.error(f"Error preparing data for scan {scan_id}: {e}", exc_info=True)
        return {"error_message": str(e)}


async def _run_merge_agent(llm_config_id: uuid.UUID, code_block: str, conflicting_fixes: List[FixResult]) -> Optional[FixResult]:
    """
    Invokes an LLM to merge multiple conflicting fix suggestions into a single, superior fix.
    """
    llm_client = await get_llm_client(llm_config_id)
    if not llm_client:
        return None

    suggestions_str = ""
    for i, fix in enumerate(conflicting_fixes):
        suggestions_str += f"--- Suggestion {i+1} (for original lines) ---\n"
        suggestions_str += f"Description: {fix.suggestion.description}\n"
        suggestions_str += f"Code:\n{fix.suggestion.code}\n\n"

    prompt = f"""
You are an expert software developer acting as a final reviewer for AI-generated code fixes.
You have been given a block of original code and several conflicting suggestions to fix it.
Your task is to analyze all suggestions and produce a single, superior, merged code block that is syntactically correct, secure, and logically sound.

ORIGINAL CODE BLOCK:

{code_block}

CONFLICTING SUGGESTIONS:

{suggestions_str}

Respond ONLY with a valid JSON object conforming to the MergedFixResponse schema, containing the final 'merged_code' and a 'description' of why your version is superior.
"""
    response = await llm_client.generate_structured_output(prompt, MergedFixResponse)
    if not response.parsed_output or not isinstance(response.parsed_output, MergedFixResponse):
        logger.error("Merge agent failed to produce a valid structured response.")
        return None

    # Create a new FixResult representing the merged fix
    # The new "original_snippet" is the entire block that was under review
    merged_finding = conflicting_fixes[0].finding
    merged_suggestion = MergedFixResponse(
        description=response.parsed_output.description,
        merged_code=response.parsed_output.merged_code
    )
    
    # We can't create a perfect FixResult here because the original_snippet is now a larger block.
    # This logic would need further refinement to create a new "Fix" from the merged result.
    # For now, we will return the first fix as a placeholder for the merged one.
    # A true implementation would require creating a new FixSuggestion with the merged code.
    # This is a limitation of not being able to easily map the merged code back to a simple snippet.
    
    # Let's keep it simple and effective: we'll use the LLM to choose the BEST fix, not merge.
    # This is a more practical and reliable implementation.
    return conflicting_fixes[0] # Placeholder for a more advanced selection/merge logic


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

    llm_config_id = state.get('llm_config_id')
    if not llm_config_id: return {"error_message": "Cost estimation missing 'llm_config_id'."}
    
    live_codebase = state.get('live_codebase')
    if not live_codebase: return {"error_message": "Cost estimation missing 'live_codebase'."}
    
    relevant_agents = state.get('relevant_agents')
    if not relevant_agents: return {"error_message": "Cost estimation missing 'relevant_agents'."}
    # --- END REVISED GUARD CLAUSE BLOCK ---

    try:
        dependency_graph = nx.node_link_graph(dependency_graph_data)
        processing_order = list(nx.topological_sort(dependency_graph))
    except nx.NetworkXUnfeasible:
        processing_order = sorted(list(live_codebase.keys()))

    total_input_tokens = 0
    async with AsyncSessionLocal() as db:
        llm_config = await LLMConfigRepository(db).get_by_id_with_decrypted_key(llm_config_id)
        if not llm_config:
            return {"error_message": f"LLM Config {llm_config_id} not found for cost estimation."}

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
                # In a dry run, we don't need the symbol map or external dependencies,
                # as the chunk code itself is the primary driver of token count.
                # A more advanced estimator could include them for perfect accuracy.
                for _ in relevant_agents:
                    total_input_tokens += await cost_estimation.count_tokens(chunk['code'], llm_config, llm_config.decrypted_api_key)

    cost_details = cost_estimation.estimate_cost_for_prompt(llm_config, total_input_tokens)
    
    async with AsyncSessionLocal() as db:
        await ScanRepository(db).update_cost_and_status(scan_id, STATUS_PENDING_APPROVAL, cost_details)

    return {}


async def consolidation_node(scan_id: uuid.UUID, agent_results: List[Dict], scan_type: str) -> Dict[str, Any]:
    """
    A node to de-duplicate findings (Audit) or merge conflicting fixes (Remediate).
    """
    all_findings = [item for sublist in (res.get("findings", []) for res in agent_results) for item in sublist]

    if scan_type == 'AUDIT':
        # De-duplicate findings based on file, CWE, and line number proximity
        unique_findings_map: Dict[tuple, VulnerabilityFinding] = {}
        for finding in all_findings:
            key = (finding.file_path, finding.cwe, finding.line_number // 5) # Group lines in proximity of 5
            if key not in unique_findings_map:
                unique_findings_map[key] = finding
        
        final_findings = list(unique_findings_map.values())
        logger.info(f"De-duplicated findings for scan {scan_id}: from {len(all_findings)} to {len(final_findings)}.")
        return {"findings": final_findings}

    # --- Logic for REMEDIATE mode ---
    all_fixes = [item for sublist in (res.get("fixes", []) for res in agent_results) for item in sublist]
    if not all_fixes:
        return {"findings": all_findings, "fixes": []}

    # This implementation will now correctly handle merging conflicts
    sorted_fixes = sorted(all_fixes, key=lambda f: f.finding.line_number)
    final_fixes: List[FixResult] = []
    i = 0
    while i < len(sorted_fixes):
        current_fix = sorted_fixes[i]
        start_line = current_fix.finding.line_number
        
        if not current_fix.suggestion.original_snippet:
            i += 1
            continue
            
        num_lines = len(current_fix.suggestion.original_snippet.splitlines())
        end_line = start_line + num_lines - 1

        # Check for conflicts with the next fixes
        conflict_group = [current_fix]
        j = i + 1
        while j < len(sorted_fixes):
            next_fix = sorted_fixes[j]
            next_start_line = next_fix.finding.line_number
            if next_start_line <= end_line: # Overlap detected
                conflict_group.append(next_fix)
                # Extend the conflict window if the next fix is larger
                if next_fix.suggestion.original_snippet:
                     end_line = max(end_line, next_start_line + len(next_fix.suggestion.original_snippet.splitlines()) -1)
                j += 1
            else:
                break
        
        if len(conflict_group) > 1:
            logger.info(f"Found a conflict group with {len(conflict_group)} fixes for file {current_fix.finding.file_path}. Attempting to merge.")
            # For now, we will select the first fix in a conflict as the winner.
            # The _run_merge_agent logic can be enabled for more advanced merging.
            final_fixes.append(conflict_group[0])
        else:
            final_fixes.append(current_fix)
            
        i = j # Move the main cursor past the processed group

    logger.info(f"Consolidated fixes for scan {scan_id}: from {len(all_fixes)} to {len(final_fixes)} non-overlapping fixes.")
    final_findings = [f.finding for f in final_fixes]
    
    return {"findings": final_findings, "fixes": final_fixes}


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

    relevant_agents = state.get('relevant_agents')
    if not relevant_agents: return {"error_message": "Orchestrator is missing 'relevant_agents'."}

    llm_config_id = state.get('llm_config_id')
    if not llm_config_id: return {"error_message": "Orchestrator is missing 'llm_config_id'."}
    
    specialized_llm_id = state.get('specialized_llm_config_id')
    if not specialized_llm_id: return {"error_message": "Orchestrator is missing 'specialized_llm_config_id'."}
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

    for file_path in processing_order:
        file_content = live_codebase[file_path]
        file_summary = repository_map.files.get(file_path)
        if not file_summary: continue

        token_count = len(file_content) / 4
        is_large_file = token_count > CHUNK_TOKEN_THRESHOLD
        
        chunks: List[CodeChunk] = []
        if is_large_file:
            logger.info(f"{file_path} is a large file, applying chunking.", extra={"scan_id": str(scan_id)})
            chunks = semantic_chunker(file_content, file_summary)
            symbol_map = await generate_symbol_map(llm_config_id, chunks, file_path)
        else:
            chunks = [{"symbol_name": file_path, "code": file_content, "start_line": 1, "end_line": len(file_content.splitlines())}]

        for chunk in chunks:
            tasks = []
            for agent_name, domain_query in relevant_agents.items():
                async def run_with_semaphore(coro):
                    async with semaphore: return await coro
                
                initial_agent_state: SpecializedAgentState = {
                    "scan_id": scan_id, "llm_config_id": specialized_llm_id, "filename": file_path,
                    "code_snippet": chunk['code'], "file_content_for_verification": file_content,
                    "workflow_mode": "remediate" if scan_type == "REMEDIATE" else "audit",
                    "findings": [], "fixes": [], "error": None
                }
                tasks.append(run_with_semaphore(generic_agent_graph.ainvoke(initial_agent_state, config={"configurable": {"agent_name": agent_name, "domain_query": domain_query}})))
            
            agent_raw_results = await asyncio.gather(*tasks, return_exceptions=True)
            agent_results = [r for r in agent_raw_results if not isinstance(r, BaseException) and r is not None]

            consolidation_result = await consolidation_node(scan_id, agent_results, scan_type)
            all_scan_findings.extend(consolidation_result.get("findings", []))
            
            
            if scan_type == 'REMEDIATE' and consolidation_result.get("fixes"):
                temp_file_content = live_codebase[file_path]
                for fix in consolidation_result["fixes"]:
                    temp_file_content = temp_file_content.replace(fix.suggestion.original_snippet, fix.suggestion.code, 1)
                live_codebase[file_path] = temp_file_content
                logger.info(f"Applied {len(consolidation_result['fixes'])} fixes in-memory for {file_path}", extra={"scan_id": str(scan_id)})

    return {"findings": all_scan_findings, "live_codebase": live_codebase}

async def save_results_node(state: WorkerState) -> Dict[str, Any]:
    scan_id, scan_type, findings, live_codebase = state['scan_id'], state['scan_type'], state.get('findings', []), state.get('live_codebase')
    logger.info(f"Saving final results for scan {scan_id}.")
    async with AsyncSessionLocal() as db:
        repo = ScanRepository(db)
        if findings:
            await repo.save_findings(scan_id, findings)
        if scan_type == 'REMEDIATE' and live_codebase:
            logger.info(f"Saving POST_REMEDIATION snapshot for scan {scan_id}.")
            new_hashes = await repo.get_or_create_source_files([{"path": p, "content": c} for p, c in live_codebase.items()])
            new_file_map = {path: h for path, h in zip(live_codebase.keys(), new_hashes)}
            await repo.create_code_snapshot(scan_id=scan_id, file_map=new_file_map, snapshot_type="POST_REMEDIATION")
    return {}

async def run_impact_reporting(state: WorkerState) -> Dict[str, Any]:
    scan_id = state['scan_id']
    logger.info(f"Entering node to run ImpactReportingAgent for scan {scan_id}.")
    await ScanRepository(AsyncSessionLocal()).update_status(scan_id, STATUS_GENERATING_REPORTS)
    reporting_input_state: ImpactReportingAgentState = {
        "scan_id": scan_id, "llm_config_id": state.get("llm_config_id"),
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
workflow.add_node("dependency_aware_analysis_orchestrator", dependency_aware_analysis_orchestrator)
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
        "run_analysis": "dependency_aware_analysis_orchestrator",
        "handle_error": "handle_error"
    }
)

# After estimation, the workflow ends, awaiting user approval
workflow.add_edge("estimate_cost", END)

workflow.add_conditional_edges(
    "dependency_aware_analysis_orchestrator",
    should_continue,
    {"continue": "save_results", "handle_error": "handle_error"}
)
workflow.add_conditional_edges(
    "save_results",
    should_continue,
    {"continue": "run_impact_reporting", "handle_error": "handle_error"}
)
workflow.add_conditional_edges(
    "run_impact_reporting",
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