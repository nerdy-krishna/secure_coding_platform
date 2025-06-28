# src/app/agents/coordinator_agent.py

import asyncio
import logging
from typing import Any, Dict, List, TypedDict, Optional, Coroutine
import uuid

from langgraph.graph import END, StateGraph

# --- New/Updated Imports ---
from app.analysis.context_bundler import ContextBundlingEngine, ContextBundle
from app.analysis.repository_map import RepositoryMap
from app.agents.schemas import (
    SpecializedAgentState,
    VulnerabilityFinding as VulnerabilityFindingModel,
    FixResult as FixResultModel,
    WorkflowMode,
)
from app.utils import cost_estimation # Import the whole module
# --- End New/Updated Imports ---

from app.agents.access_control_agent import build_specialized_agent_graph as build_access_control_agent
from app.agents.api_security_agent import build_specialized_agent_graph as build_api_security_agent
from app.agents.architecture_agent import build_specialized_agent_graph as build_architecture_agent
from app.agents.authentication_agent import build_specialized_agent_graph as build_authentication_agent
from app.agents.business_logic_agent import build_specialized_agent_graph as build_business_logic_agent
from app.agents.code_integrity_agent import build_specialized_agent_graph as build_code_integrity_agent
from app.agents.communication_agent import build_specialized_agent_graph as build_communication_agent
from app.agents.configuration_agent import build_specialized_agent_graph as build_configuration_agent
from app.agents.cryptography_agent import build_specialized_agent_graph as build_cryptography_agent
from app.agents.data_protection_agent import build_specialized_agent_graph as build_data_protection_agent
from app.agents.error_handling_agent import build_specialized_agent_graph as build_error_handling_agent
from app.agents.file_handling_agent import build_specialized_agent_graph as build_file_handling_agent
from app.agents.session_management_agent import build_specialized_agent_graph as build_session_management_agent
from app.agents.validation_agent import build_specialized_agent_graph as build_validation_agent

from app.db import crud
from app.db.database import AsyncSessionLocal as async_session_factory

logger = logging.getLogger(__name__)

AGENT_NAME = "CoordinatorAgent"

# The maximum number of specialized agents that can make LLM calls concurrently.
# This value can be tuned or moved to settings later.
CONCURRENT_LLM_LIMIT = 5

# Define status constants for clarity within this agent
STATUS_PENDING_APPROVAL = "PENDING_COST_APPROVAL"
STATUS_COST_APPROVED = "Approved - Queued" # This status is set by the API upon user approval

AGENT_BUILDER_MAP = {
    "AccessControlAgent": build_access_control_agent, "ApiSecurityAgent": build_api_security_agent,
    "ArchitectureAgent": build_architecture_agent, "AuthenticationAgent": build_authentication_agent,
    "BusinessLogicAgent": build_business_logic_agent, "CodeIntegrityAgent": build_code_integrity_agent,
    "CommunicationAgent": build_communication_agent, "ConfigurationAgent": build_configuration_agent,
    "CryptographyAgent": build_cryptography_agent, "DataProtectionAgent": build_data_protection_agent,
    "ErrorHandlingAgent": build_error_handling_agent, "FileHandlingAgent": build_file_handling_agent,
    "SessionManagementAgent": build_session_management_agent, "ValidationAgent": build_validation_agent,
}


class CoordinatorState(TypedDict):
    """ The state for the coordinator, aligned with the new architecture. """
    # Inputs from Worker Graph
    submission_id: uuid.UUID
    llm_config_id: Optional[uuid.UUID]
    files: Dict[str, str]
    repository_map: RepositoryMap
    asvs_analysis: Dict[str, Any]
    workflow_mode: WorkflowMode

    # Generated within this agent
    context_bundles: Optional[List[ContextBundle]]
    relevant_agents: Dict[str, List[str]]
    estimated_cost: Optional[Dict[str, float]]
    cost_approval_met: Optional[bool] 
    current_submission_status: Optional[str]
    live_codebase: Optional[Dict[str, str]] # ADDED: To hold code during remediation
    
    # Outputs
    findings: List[VulnerabilityFindingModel] # Changed from nested results
    fixes: List[FixResultModel]               # Changed from nested results
    final_status: Optional[str]               # New top-level field for status message
    error: Optional[str]


def determine_relevant_agents_node(state: CoordinatorState) -> Dict[str, Any]:
    """ Determines which specialized agents are relevant based on the project-wide context analysis. """
    logger.info(f"[{AGENT_NAME}] Determining relevant agents from ASVS analysis.")
    asvs_analysis = state.get("asvs_analysis", {})
    relevant_agents: Dict[str, List[str]] = {}
    # The original code incorrectly used all files. This now correctly uses the
    # already-filtered list of files from the repository map.
    repository_map = state.get("repository_map")
    if not repository_map:
        return {"error": "Repository map is missing, cannot determine agent assignments."}
    files_to_scan = list(repository_map.files.keys())

    for agent_name, details in asvs_analysis.items():
        agent_key = agent_name if agent_name.endswith("Agent") else f"{agent_name}Agent"
        if agent_key in AGENT_BUILDER_MAP and details.get("is_relevant"):
            relevant_agents[agent_key] = files_to_scan

    logger.info(f"[{AGENT_NAME}] Relevant agents identified: {list(relevant_agents.keys())}")
    return {"relevant_agents": relevant_agents}


def create_context_bundles_node(state: CoordinatorState) -> Dict[str, Any]:
    """ Uses the ContextBundlingEngine to create dependency-aware bundles for analysis. """
    logger.info(f"[{AGENT_NAME}] Creating context bundles.")
    repository_map = state.get("repository_map")
    files = state.get("files")

    if not repository_map or not files:
        return {"error": "Repository map or files missing, cannot create bundles."}

    try:
        engine = ContextBundlingEngine(repository_map, files)
        bundles = engine.create_bundles()
        logger.info(f"[{AGENT_NAME}] Successfully created {len(bundles)} context bundles.")
        return {"context_bundles": bundles}
    except Exception as e:
        logger.error(f"[{AGENT_NAME}] Failed to create context bundles: {e}", exc_info=True)
        return {"error": f"Failed to create context bundles: {e}"}


# --- NEW NODE FOR COST ESTIMATION ---
async def estimate_cost_node(state: CoordinatorState) -> Dict[str, Any]:
    """
    Estimates the cost of the analysis and determines if the workflow should pause.
    """
    submission_id = state["submission_id"]
    logger.info(f"[{AGENT_NAME}] Evaluating cost and approval status for submission {submission_id}.")
    
    async with async_session_factory() as db:
        submission = await crud.get_submission(db, submission_id)
        if not submission:
            logger.error(f"[{AGENT_NAME}] Submission {submission_id} not found during cost evaluation.")
            return {"error": f"Submission {submission_id} not found.", "current_submission_status": "ERROR_NO_SUBMISSION"}

        current_status = submission.status
        estimated_cost_from_db = submission.estimated_cost

        # If cost is already approved, signal to proceed.
        if current_status == STATUS_COST_APPROVED:
            logger.info(f"[{AGENT_NAME}] Cost for submission {submission_id} is already approved ({STATUS_COST_APPROVED}). Proceeding.")
            return {"cost_approval_met": True, "current_submission_status": current_status, "estimated_cost": estimated_cost_from_db}

        # If it's currently pending approval, it means we are re-invoked while waiting.
        # The coordinator should end, and the worker graph will handle the pause.
        if current_status == STATUS_PENDING_APPROVAL:
            logger.info(f"[{AGENT_NAME}] Submission {submission_id} is still {STATUS_PENDING_APPROVAL}. Waiting for external approval.")
            return {"cost_approval_met": False, "current_submission_status": current_status, "estimated_cost": estimated_cost_from_db}

        # If none of the above, it's a new estimation.
        logger.info(f"[{AGENT_NAME}] Performing new cost estimation for submission {submission_id}.")
        bundles = state.get("context_bundles")
        llm_config_id = state.get("llm_config_id")

        if not bundles or not llm_config_id:
            logger.error(f"[{AGENT_NAME}] Bundles or LLM config ID missing for submission {submission_id}.")
            return {"error": "Bundles or LLM config ID missing, cannot estimate cost.", "current_submission_status": current_status}
        
        try:
            # Fetch the config with the decrypted key to pass to the token counter
            llm_config = await crud.get_llm_config_with_decrypted_key(db, llm_config_id)
            if not llm_config:
                logger.error(f"[{AGENT_NAME}] LLM Config {llm_config_id} not found for submission {submission_id}.")
                return {"error": f"LLM Configuration with ID {llm_config_id} not found.", "current_submission_status": current_status}

            full_bundle_text = ""
            for bundle in bundles:
                for content in bundle.context_files.values():
                    full_bundle_text += content
            
            # Await the new async token counter and pass the full config and key
            total_input_tokens = await cost_estimation.count_tokens(
                text=full_bundle_text, 
                config=llm_config, 
                api_key=getattr(llm_config, 'decrypted_api_key', None)
            )
            logger.info(f"[{AGENT_NAME}] Total estimated input tokens for {submission_id}: {total_input_tokens}")

            cost_details = cost_estimation.estimate_cost_for_prompt(
                config=llm_config,
                input_tokens=total_input_tokens
            )
            
            await crud.update_submission_cost_and_status(
                db, 
                submission_id, 
                STATUS_PENDING_APPROVAL, 
                cost_details
            )
            logger.info(f"[{AGENT_NAME}] Submission {submission_id} status set to {STATUS_PENDING_APPROVAL}. Estimated cost: {cost_details['total_estimated_cost']:.6f} USD.")
            return {"estimated_cost": cost_details, "cost_approval_met": False, "current_submission_status": STATUS_PENDING_APPROVAL}
        except Exception as e:
            logger.error(f"[{AGENT_NAME}] Failed to estimate cost for {submission_id}: {e}", exc_info=True)
            return {"error": f"Failed to estimate cost: {e}", "current_submission_status": current_status}


def route_after_cost_estimation(state: CoordinatorState) -> str:
    """Routes based on whether cost approval is met or an error occurred."""
    if state.get("error"):
        logger.error(f"[{AGENT_NAME}] Error in coordinator state after cost estimation: {state['error']}")
        return "end_with_error"
    
    if state.get("cost_approval_met"): # True if status was COST_APPROVED
        logger.info(f"[{AGENT_NAME}] Cost approval met for submission {state['submission_id']}. Proceeding to specialized agents.")
        return "run_specialized_agents"
    
    # If cost_approval_met is False (i.e., status is PENDING_COST_APPROVAL or it's a new estimation)
    # The coordinator sub-graph ends. The worker graph will decide to pause.
    logger.info(f"[{AGENT_NAME}] Cost approval not met (status: {state.get('current_submission_status')}) for {state['submission_id']}. Coordinator ending.")
    return END


async def run_specialized_agents_node(state: CoordinatorState) -> Dict[str, Any]:
    """
    Runs the identified specialized agents, feeding them the rich context bundles
    and setting the appropriate workflow_mode.
    NOW handles both parallel 'audit' and sequential 'remediate' modes.
    """
    submission_id = state["submission_id"]
    relevant_agents = state["relevant_agents"]
    context_bundles = state["context_bundles"]
    specialized_llm_id = state.get("llm_config_id")
    workflow_mode = state["workflow_mode"]
    files = state["files"] # Get original files

    logger.info(f"[{AGENT_NAME}] Beginning specialized agent runs in '{workflow_mode}' mode with a concurrency limit of {CONCURRENT_LLM_LIMIT}.")

    if not context_bundles or not files:
        return {"error": "Context bundles or original files not found, cannot run specialized agents."}

    # --- Mode: 'audit' (Parallel Execution) ---
    if workflow_mode == "audit":
        semaphore = asyncio.Semaphore(CONCURRENT_LLM_LIMIT)

        async def run_with_semaphore(coro: Coroutine) -> Any:
            async with semaphore:
                return await coro

        bundle_map: Dict[str, ContextBundle] = {b.target_file_path: b for b in context_bundles}
        tasks = []

        for agent_name, file_paths in relevant_agents.items():
            agent_builder = AGENT_BUILDER_MAP.get(agent_name)
            if not agent_builder: continue

            agent_graph = agent_builder()
            for file_path in file_paths:
                bundle = bundle_map.get(file_path)
                if not bundle: continue

                formatted_bundle_content = ""
                for path, content in bundle.context_files.items():
                    formatted_bundle_content += f"--- FILE: {path} ---\n{content}\n\n"

                initial_agent_state: SpecializedAgentState = {
                    "submission_id": submission_id,
                    "llm_config_id": specialized_llm_id,
                    "filename": file_path,
                    "code_snippet": formatted_bundle_content,
                    "workflow_mode": workflow_mode,
                    "findings": [],
                    "fixes": [],
                    "error": None,
                }
                agent_coro = agent_graph.ainvoke(initial_agent_state)
                tasks.append(run_with_semaphore(agent_coro))

        if not tasks:
            return {"findings": [], "fixes": []}

        agent_results = await asyncio.gather(*tasks, return_exceptions=True)
        
        all_findings: List[VulnerabilityFindingModel] = []
        all_fixes: List[FixResultModel] = []
        for result in agent_results:
            if isinstance(result, dict):
                all_findings.extend(result.get("findings", []))
                # Audit mode doesn't produce fixes, but we handle it just in case
                all_fixes.extend(result.get("fixes", [])) 
            elif isinstance(result, Exception):
                logger.error(f"[{AGENT_NAME}] An agent task failed during audit: {result}", exc_info=result)

        logger.info(f"[{AGENT_NAME}] Collated {len(all_findings)} findings from audit.")
        return {"findings": all_findings, "fixes": all_fixes, "live_codebase": None}

    # --- Mode: 'remediate' (Sequential Execution) ---
    elif workflow_mode == "remediate":
        live_codebase = files.copy() # Start with a copy of the original code
        all_findings: List[VulnerabilityFindingModel] = []
        all_fixes: List[FixResultModel] = []
        
        bundle_map: Dict[str, ContextBundle] = {b.target_file_path: b for b in context_bundles}

        # Sequentially process each file that has been identified for analysis
        for agent_name, file_paths in relevant_agents.items():
            agent_builder = AGENT_BUILDER_MAP.get(agent_name)
            if not agent_builder: continue
            
            agent_graph = agent_builder()
            
            for file_path in file_paths:
                bundle = bundle_map.get(file_path)
                if not bundle: continue
                
                # IMPORTANT: For remediation, the context must be the CURRENT state of the codebase
                formatted_bundle_content = ""
                for path in bundle.context_files.keys():
                    # Use the version from live_codebase
                    current_content = live_codebase.get(path, "")
                    formatted_bundle_content += f"--- FILE: {path} ---\n{current_content}\n\n"
                
                logger.info(f"[{AGENT_NAME}] Sequentially remediating '{file_path}' with '{agent_name}'.")

                initial_agent_state: SpecializedAgentState = {
                    "submission_id": submission_id,
                    "llm_config_id": specialized_llm_id,
                    "filename": file_path,
                    "code_snippet": formatted_bundle_content,
                    "workflow_mode": workflow_mode,
                    "findings": [],
                    "fixes": [],
                    "error": None,
                }

                agent_result = await agent_graph.ainvoke(initial_agent_state)

                if isinstance(agent_result, dict) and not agent_result.get('error'):
                    findings_from_run = agent_result.get("findings", [])
                    fixes_from_run = agent_result.get("fixes", [])
                    
                    all_findings.extend(findings_from_run)
                    all_fixes.extend(fixes_from_run)
                    
                    # Apply fixes to the live codebase
                    for fix_result in fixes_from_run:
                        target_file = fix_result.finding.file_path
                        original_snippet = fix_result.suggestion.original_snippet
                        new_code = fix_result.suggestion.code
                        
                        if target_file in live_codebase:
                            file_content = live_codebase[target_file]
                            if original_snippet in file_content:
                                # Replace only the first occurrence to avoid unintended changes
                                live_codebase[target_file] = file_content.replace(original_snippet, new_code, 1)
                                logger.info(f"Applied fix in '{target_file}'.")
                            else:
                                logger.warning(f"Could not find original snippet in '{target_file}' to apply fix. The code may have been changed by a previous fix.")
                elif isinstance(agent_result, Exception):
                     logger.error(f"[{AGENT_NAME}] An agent task failed during remediation: {agent_result}", exc_info=agent_result)


        logger.info(f"[{AGENT_NAME}] Collated {len(all_findings)} findings and {len(all_fixes)} fixes from remediation.")
        return {"findings": all_findings, "fixes": all_fixes, "live_codebase": live_codebase}

    else:
        return {"error": f"Unknown workflow_mode: {workflow_mode}"}


async def finalize_analysis_node(state: CoordinatorState) -> Dict[str, Any]:
    """
    Saves all findings and their associated fixes. If it was a remediation run,
    it saves the fixed code map. Then updates the submission status.
    """
    submission_id = state["submission_id"]
    findings_to_save = state.get("findings", [])
    fixes_to_save = state.get("fixes", [])
    live_codebase = state.get("live_codebase")
    workflow_mode = state["workflow_mode"]

    logger.info(f"[{AGENT_NAME}] Finalizing analysis for submission {submission_id} in '{workflow_mode}' mode.")

    async with async_session_factory() as db:
        try:
            if findings_to_save:
                persisted_findings = await crud.save_findings(db, submission_id, findings_to_save)
                logger.info(f"[{AGENT_NAME}] Saved {len(persisted_findings)} findings.")

                if fixes_to_save:
                    finding_map = {(f.file_path, f.line_number, f.cwe): f.id for f in persisted_findings}
                    for fix_result in fixes_to_save:
                        pydantic_finding = fix_result.finding
                        finding_key = (pydantic_finding.file_path, pydantic_finding.line_number, pydantic_finding.cwe)
                        finding_id = finding_map.get(finding_key)
                        if finding_id:
                            await crud.save_fix_suggestion(db, finding_id, fix_result.suggestion)
                    logger.info(f"[{AGENT_NAME}] Saved {len(fixes_to_save)} fix suggestions.")

            # New logic to handle remediation completion
            if workflow_mode == 'remediate' and live_codebase:
                await crud.update_remediated_code_and_status(
                    db,
                    submission_id,
                    "Remediation-Completed",
                    live_codebase
                )
                logger.info(f"[{AGENT_NAME}] Saved fixed code map and updated status to 'Remediation-Completed'.")
            else:
                # Original logic for audit completion
                await crud.update_submission_status(db, submission_id, "Completed")
                logger.info(f"[{AGENT_NAME}] Updated status to 'Completed' for submission {submission_id}.")

        except Exception as e:
            logger.error(f"[{AGENT_NAME}] Error saving results to DB for {submission_id}: {e}", exc_info=True)
            return {"error": f"DB error: {e}", "findings": findings_to_save, "fixes": fixes_to_save}

    return {
        "findings": findings_to_save, 
        "fixes": fixes_to_save, 
        "final_status": "Analysis complete."
    }


def build_coordinator_graph():
    """Builds the coordinator graph with the new cost estimation and pause step."""
    workflow = StateGraph(CoordinatorState)

    workflow.add_node("determine_relevant_agents", determine_relevant_agents_node)
    workflow.add_node("create_context_bundles", create_context_bundles_node)
    workflow.add_node("estimate_cost", estimate_cost_node)
    
    # These nodes are declared but will only be used in the "resume" part of the workflow,
    # which will be triggered by a separate message after user approval.
    workflow.add_node("run_specialized_agents", run_specialized_agents_node)
    workflow.add_node("finalize_analysis", finalize_analysis_node)
    workflow.add_node("end_with_error", lambda s: s) # Simple error endpoint

    workflow.set_entry_point("determine_relevant_agents")
    workflow.add_edge("determine_relevant_agents", "create_context_bundles")
    
    workflow.add_conditional_edges(
        "create_context_bundles",
        lambda s: "estimate_cost" if not s.get("error") else "end_with_error",
        {
            "estimate_cost": "estimate_cost",
            "end_with_error": "end_with_error"
        }
    )
    
    workflow.add_conditional_edges(
        "estimate_cost",
        route_after_cost_estimation,
        {
            "run_specialized_agents": "run_specialized_agents",
            END: END,  # Ends this sub-graph if pending or error during estimation
            "end_with_error": "end_with_error"
        }
    )
    workflow.add_edge("run_specialized_agents", "finalize_analysis") # This runs if cost_approval_met was true
    workflow.add_edge("finalize_analysis", END)
    workflow.add_edge("end_with_error", END)

    return workflow.compile()
