# src/app/infrastructure/agents/coordinator_agent.py
import asyncio
import logging
from typing import Any, Dict, List, TypedDict, Optional, Coroutine
import uuid

from langgraph.graph import END, StateGraph
from sqlalchemy import select
from sqlalchemy.orm import selectinload

from app.shared.analysis_tools.context_bundler import ContextBundlingEngine, ContextBundle
from app.shared.analysis_tools.repository_map import RepositoryMap
from app.core.schemas import (
    SpecializedAgentState,
    VulnerabilityFinding as VulnerabilityFindingModel,
    FixResult as FixResultModel,
    WorkflowMode,
)
from app.shared.lib import cost_estimation
from app.infrastructure.database import models as db_models
from app.infrastructure.database.repositories.scan_repo import ScanRepository
from app.infrastructure.database.repositories.llm_config_repo import LLMConfigRepository
from app.infrastructure.database import AsyncSessionLocal as async_session_factory

from app.infrastructure.agents.generic_specialized_agent import build_generic_specialized_agent_graph

logger = logging.getLogger(__name__)

AGENT_NAME = "CoordinatorAgent"
CONCURRENT_LLM_LIMIT = 5
STATUS_PENDING_APPROVAL = "PENDING_COST_APPROVAL"
STATUS_COST_APPROVED = "QUEUED_FOR_SCAN"



class CoordinatorState(TypedDict):
    scan_id: uuid.UUID
    # This will now hold the ID for the specialized agents
    llm_config_id: Optional[uuid.UUID]
    files: Dict[str, str]
    repository_map: RepositoryMap
    # This field is now populated by the context analysis agent and is not used here
    asvs_analysis: Dict[str, Any]
    workflow_mode: WorkflowMode
    context_bundles: Optional[List[ContextBundle]]
    # This will now be a mapping of agent_name -> domain_query
    relevant_agents: Dict[str, str]
    estimated_cost: Optional[Dict[str, float]]
    cost_approval_met: Optional[bool]
    current_scan_status: Optional[str]
    live_codebase: Optional[Dict[str, str]]
    findings: List[VulnerabilityFindingModel]
    fixes: List[FixResultModel]
    final_status: Optional[str]
    error: Optional[str]


async def determine_relevant_agents_node(state: CoordinatorState) -> Dict[str, Any]:
    """
    Determines which specialized agents are relevant by querying the database
    based on the frameworks selected for the scan.
    """
    scan_id = state['scan_id']
    logger.info(f"[{AGENT_NAME}] Determining relevant agents for scan from DB.", extra={"scan_id": str(scan_id)})
    
    relevant_agents: Dict[str, str] = {}
    
    async with async_session_factory() as db:
        try:
            scan_repo = ScanRepository(db)
            scan = await scan_repo.get_scan_with_details(scan_id)
            if not scan:
                return {"error": f"Scan {scan_id} not found."}

            if not scan.frameworks:
                logger.warning(f"Scan {scan_id} has no frameworks selected. No agents will run.")
                return {"relevant_agents": {}}
                
            # This fetches the framework objects, which have their agents pre-loaded by the relationship
            framework_details = await db.execute(
                select(db_models.Framework)
                .options(selectinload(db_models.Framework.agents))
                .where(db_models.Framework.name.in_(scan.frameworks))
            )
            
            for framework in framework_details.scalars().all():
                for agent in framework.agents:
                    if agent.name not in relevant_agents:
                        relevant_agents[agent.name] = agent.domain_query
        
        except Exception as e:
            error_msg = f"Failed to determine relevant agents from DB for scan {scan_id}: {e}"
            logger.error(error_msg, exc_info=True)
            return {"error": error_msg}

    logger.info(f"[{AGENT_NAME}] Relevant agents identified: {list(relevant_agents.keys())}")
    return {"relevant_agents": relevant_agents}


def create_context_bundles_node(state: CoordinatorState) -> Dict[str, Any]:
    """Creates context-rich code bundles for each file to be analyzed."""
    scan_id = state['scan_id']
    logger.info(f"[{AGENT_NAME}] Creating context bundles for scan.", extra={"scan_id": str(scan_id)})
    repository_map = state.get("repository_map")
    files = state.get("files")
    if not repository_map or not files:
        return {"error": "Repository map or files missing, cannot create bundles."}
    try:
        engine = ContextBundlingEngine(repository_map, files)
        bundles = engine.create_bundles()
        logger.info(f"[{AGENT_NAME}] Successfully created {len(bundles)} context bundles.", extra={"scan_id": str(scan_id)})
        return {"context_bundles": bundles}
    except Exception as e:
        logger.error(f"[{AGENT_NAME}] Failed to create context bundles: {e}", exc_info=True, extra={"scan_id": str(scan_id)})
        return {"error": f"Failed to create context bundles: {e}"}


async def estimate_cost_node(state: CoordinatorState) -> Dict[str, Any]:
    """Estimates analysis cost. If a cost has not been approved, it pauses the graph."""
    scan_id = state["scan_id"]
    logger.info(f"[{AGENT_NAME}] Evaluating cost and approval status for scan.", extra={"scan_id": str(scan_id)})
    
    async with async_session_factory() as db:
        scan_repo = ScanRepository(db)
        llm_config_repo = LLMConfigRepository(db)

        scan = await scan_repo.get_scan(scan_id)
        if not scan:
            logger.error(f"[{AGENT_NAME}] Scan not found during cost evaluation.", extra={"scan_id": str(scan_id)})
            return {"error": f"Scan {scan_id} not found.", "current_scan_status": "ERROR_NO_SCAN"}

        current_status = scan.status
        estimated_cost_from_db = scan.cost_details

        if current_status == STATUS_COST_APPROVED:
            logger.info(f"[{AGENT_NAME}] Cost for scan is already approved. Proceeding.", extra={"scan_id": str(scan_id)})
            return {"cost_approval_met": True, "current_scan_status": current_status, "estimated_cost": estimated_cost_from_db}

        if current_status == STATUS_PENDING_APPROVAL:
            logger.info(f"[{AGENT_NAME}] Scan is still {STATUS_PENDING_APPROVAL}. Waiting.", extra={"scan_id": str(scan_id)})
            return {"cost_approval_met": False, "current_scan_status": current_status, "estimated_cost": estimated_cost_from_db}

        logger.info(f"[{AGENT_NAME}] Performing new cost estimation for scan.", extra={"scan_id": str(scan_id)})
        bundles = state.get("context_bundles")
        llm_config_id = state.get("llm_config_id")

        if not bundles or not llm_config_id:
            return {"error": "Bundles or LLM config ID missing, cannot estimate cost."}
        try:
            llm_config = await llm_config_repo.get_by_id_with_decrypted_key(llm_config_id)
            if not llm_config:
                return {"error": f"LLM Configuration with ID {llm_config_id} not found."}

            full_bundle_text = "".join(content for bundle in bundles for content in bundle.context_files.values())
            
            total_input_tokens = await cost_estimation.count_tokens(
                text=full_bundle_text, 
                config=llm_config, 
                api_key=getattr(llm_config, 'decrypted_api_key', None)
            )
            cost_details = cost_estimation.estimate_cost_for_prompt(config=llm_config, input_tokens=total_input_tokens)
            
            await scan_repo.update_cost_and_status(scan_id, STATUS_PENDING_APPROVAL, cost_details)
            logger.info(f"[{AGENT_NAME}] Scan status set to {STATUS_PENDING_APPROVAL}.", extra={"scan_id": str(scan_id)})
            return {"estimated_cost": cost_details, "cost_approval_met": False, "current_scan_status": STATUS_PENDING_APPROVAL}
        except Exception as e:
            logger.error(f"[{AGENT_NAME}] Failed to estimate cost for {scan_id}: {e}", exc_info=True)
            return {"error": f"Failed to estimate cost: {e}"}


def route_after_cost_estimation(state: CoordinatorState) -> str:
    if state.get("error"):
        logger.error(f"[{AGENT_NAME}] Error in coordinator state after cost estimation: {state['error']}")
        return "end_with_error"
    if state.get("cost_approval_met"):
        logger.info(f"[{AGENT_NAME}] Cost approval met for scan. Proceeding.", extra={"scan_id": str(state['scan_id'])})
        return "run_specialized_agents"
    logger.info(f"[{AGENT_NAME}] Cost approval not met. Coordinator ending.", extra={"scan_id": str(state['scan_id'])})
    return END


async def run_specialized_agents_node(state: CoordinatorState) -> Dict[str, Any]:
    scan_id = state["scan_id"]
    relevant_agents = state["relevant_agents"] # Now a dict of name -> domain_query
    context_bundles = state["context_bundles"]
    workflow_mode = state["workflow_mode"]
    files = state["files"]
    
    # Get the specialized LLM config ID from the scan record
    async with async_session_factory() as db:
        scan = await db.get(db_models.Scan, scan_id)
        if not scan or not scan.specialized_llm_config_id:
            return {"error": f"Could not retrieve specialized LLM config for scan {scan_id}"}
        specialized_llm_id = scan.specialized_llm_config_id

    logger.info(f"[{AGENT_NAME}] Beginning agent runs in '{workflow_mode}' mode with concurrency {CONCURRENT_LLM_LIMIT}.", extra={"scan_id": str(scan_id)})
    if not context_bundles or not files:
        return {"error": "Context bundles or files not found."}

    # The single generic agent graph is built once
    generic_agent_graph = build_generic_specialized_agent_graph()
    
    # --- This entire block is refactored for dynamic invocation ---
    semaphore = asyncio.Semaphore(CONCURRENT_LLM_LIMIT)
    async def run_with_semaphore(coro: Coroutine) -> Any:
        async with semaphore:
            return await coro
            
    tasks = []
    bundle_map: Dict[str, ContextBundle] = {b.target_file_path: b for b in context_bundles}
    
    # Iterate through the agents and files assigned to them
    for agent_name, domain_query in relevant_agents.items():
        for bundle in context_bundles:
            formatted_bundle_content = "".join(f"--- FILE: {path} ---\n{content}\n\n" for path, content in bundle.context_files.items())
            
            # This config is passed to the generic agent node
            agent_run_config = {
                "configurable": {
                    "agent_name": agent_name,
                    "domain_query": domain_query,
                }
            }
            
            initial_agent_state: SpecializedAgentState = {
                "scan_id": scan_id,
                "llm_config_id": specialized_llm_id,
                "filename": bundle.target_file_path,
                "code_snippet": formatted_bundle_content,
                "workflow_mode": workflow_mode,
                "findings": [],
                "fixes": [],
                "error": None
            }
            
            tasks.append(run_with_semaphore(generic_agent_graph.ainvoke(initial_agent_state, config=agent_run_config))) # type: ignore

    if not tasks:
        logger.warning(f"[{AGENT_NAME}] No agent tasks were created for scan {scan_id}.")
        return {"findings": [], "fixes": [], "live_codebase": files}

    agent_results = await asyncio.gather(*tasks, return_exceptions=True)
    
    all_findings = []
    all_fixes = []
    has_errors = False
    for i, res in enumerate(agent_results):
        if isinstance(res, Exception):
            logger.error(f"[{AGENT_NAME}] Agent task {i} failed with an exception: {res}", exc_info=res)
            has_errors = True
        elif isinstance(res, dict) and res.get("error"):
            logger.error(f"[{AGENT_NAME}] Agent task {i} returned an error: {res['error']}")
            has_errors = True
        elif isinstance(res, dict):
            all_findings.extend(res.get("findings", []))
            all_fixes.extend(res.get("fixes", []))

    if has_errors:
        return {"error": "One or more specialized agents failed. Check logs for details."}
        
    # The 'live_codebase' logic for REMEDIATE mode will be handled by the patching node,
    # so we can return None here for now.
    return {"findings": all_findings, "fixes": all_fixes, "live_codebase": None}


async def finalize_analysis_node(state: CoordinatorState) -> Dict[str, Any]:
    """Saves all findings and fixes from the agent runs into the database."""
    if state.get("error"):
        return {}
    scan_id, findings_to_save, fixes_to_save, live_codebase, workflow_mode = state["scan_id"], state.get("findings", []), state.get("fixes", []), state.get("live_codebase"), state["workflow_mode"]
    logger.info(f"[{AGENT_NAME}] Finalizing analysis for scan in '{workflow_mode}' mode.", extra={"scan_id": str(scan_id), "mode": workflow_mode, "findings_count": len(findings_to_save)})
    async with async_session_factory() as db:
        repo = ScanRepository(db)
        try:
            if findings_to_save:
                await repo.save_findings(scan_id, findings_to_save)
                logger.info(f"[{AGENT_NAME}] Saved {len(findings_to_save)} findings.")
            
            if workflow_mode == 'remediate' and live_codebase:
                # This needs to create a new snapshot, not just update the scan
                await repo.create_code_snapshot(scan_id=scan_id, file_map=live_codebase, snapshot_type="POST_REMEDIATION")
                logger.info(f"[{AGENT_NAME}] Saved post-remediation code snapshot.")
        except Exception as e:
            logger.error(f"[{AGENT_NAME}] Error saving results to DB for {scan_id}: {e}", exc_info=True)
            return {"error": f"DB error: {e}"}
    return {"final_status": "Analysis complete."}


def route_after_agent_runs(state: CoordinatorState) -> str:
    """Checks for errors after agent execution and routes accordingly."""
    if state.get("error"):
        return "end_with_error"
    return "finalize_analysis"


def build_coordinator_graph():
    workflow = StateGraph(CoordinatorState)
    workflow.add_node("determine_relevant_agents", determine_relevant_agents_node)
    workflow.add_node("create_context_bundles", create_context_bundles_node)
    workflow.add_node("estimate_cost", estimate_cost_node)
    workflow.add_node("run_specialized_agents", run_specialized_agents_node)
    workflow.add_node("finalize_analysis", finalize_analysis_node)
    workflow.add_node("end_with_error", lambda s: s)
    workflow.set_entry_point("determine_relevant_agents")
    workflow.add_edge("determine_relevant_agents", "create_context_bundles")
    workflow.add_conditional_edges("create_context_bundles", lambda s: "estimate_cost" if not s.get("error") else "end_with_error", {"estimate_cost": "estimate_cost", "end_with_error": "end_with_error"})
    workflow.add_conditional_edges("estimate_cost", route_after_cost_estimation, {"run_specialized_agents": "run_specialized_agents", END: END, "end_with_error": "end_with_error"})
    
    workflow.add_conditional_edges(
        "run_specialized_agents",
        route_after_agent_runs,
        {
            "finalize_analysis": "finalize_analysis",
            "end_with_error": END,
        }
    )

    workflow.add_edge("finalize_analysis", END)
    workflow.add_edge("end_with_error", END)
    return workflow.compile()