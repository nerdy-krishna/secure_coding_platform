# src/app/agents/coordinator_agent.py

import asyncio
import logging
from typing import Any, Dict, List, TypedDict, Optional, cast
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
    estimated_cost: Optional[Dict[str, float]] # ADDED
    
    # Outputs
    results: Dict[str, Any]
    error: Optional[str]


def determine_relevant_agents_node(state: CoordinatorState) -> Dict[str, Any]:
    """ Determines which specialized agents are relevant based on the project-wide context analysis. """
    logger.info(f"[{AGENT_NAME}] Determining relevant agents from ASVS analysis.")
    asvs_analysis = state.get("asvs_analysis", {})
    relevant_agents: Dict[str, List[str]] = {}
    all_files = list(state.get("files", {}).keys())
    
    for agent_name, details in asvs_analysis.items():
        agent_key = agent_name if agent_name.endswith("Agent") else f"{agent_name}Agent"
        if agent_key in AGENT_BUILDER_MAP and details.get("is_relevant"):
            relevant_agents[agent_key] = all_files

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
    Estimates the cost of the analysis and pauses the workflow for approval.
    """
    logger.info(f"[{AGENT_NAME}] Preparing to estimate cost for submission {state['submission_id']}.")
    bundles = state.get("context_bundles")
    llm_config_id = state.get("llm_config_id")
    submission_id = state["submission_id"]

    if not bundles or not llm_config_id:
        return {"error": "Bundles or LLM config ID missing, cannot estimate cost."}

    async with async_session_factory() as db:
        try:
            llm_config = await crud.get_llm_config(db, llm_config_id)
            if not llm_config:
                return {"error": f"LLM Configuration with ID {llm_config_id} not found."}

            total_input_tokens = 0
            # We estimate cost based on the number of agent runs needed
            agent_runs = sum(len(files) for files in state.get("relevant_agents", {}).values())
            
            # Simple token estimation: sum of all bundled content multiplied by agent runs
            # A more advanced approach could be more granular.
            full_bundle_text = ""
            for bundle in bundles:
                for content in bundle.context_files.values():
                    full_bundle_text += content

            total_input_tokens = cost_estimation.count_tokens(full_bundle_text, llm_config.tokenizer_encoding)
            
            logger.info(f"[{AGENT_NAME}] Total estimated input tokens for analysis: {total_input_tokens}")

            cost_details = cost_estimation.estimate_cost_for_prompt(
                config=llm_config,
                input_tokens=total_input_tokens
            )
            
            # Save cost and update status
            await crud.update_submission_cost_and_status(
                db, 
                submission_id, 
                "Pending Cost Approval", 
                cost_details
            )
            logger.info(f"[{AGENT_NAME}] Submission {submission_id} paused. Estimated cost: {cost_details['total_estimated_cost']:.6f} USD.")

            return {"estimated_cost": cost_details}
        except Exception as e:
            logger.error(f"[{AGENT_NAME}] Failed to estimate cost: {e}", exc_info=True)
            return {"error": f"Failed to estimate cost: {e}"}


def should_continue(state: CoordinatorState) -> str:
    if state.get("error"):
        return "end_with_error"
    # This node is now only for routing after bundling
    return "estimate_cost"


async def run_specialized_agents_node(state: CoordinatorState) -> Dict[str, Any]:
    """
    Runs the identified specialized agents, feeding them the rich context bundles
    and setting the appropriate workflow_mode.
    """
    submission_id = state["submission_id"]
    relevant_agents = state["relevant_agents"]
    context_bundles = state["context_bundles"]
    specialized_llm_id = state.get("llm_config_id")
    workflow_mode = state["workflow_mode"]

    logger.info(f"[{AGENT_NAME}] Beginning specialized agent runs in '{workflow_mode}' mode.")

    if not context_bundles:
        return {"error": "Context bundles not found, cannot run specialized agents."}

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
            tasks.append(agent_graph.ainvoke(initial_agent_state))

    if not tasks:
        return {"results": {"findings": [], "fixes": []}}

    agent_results = await asyncio.gather(*tasks, return_exceptions=True)
    
    all_findings, all_fixes = [], []
    for result in agent_results:
        if isinstance(result, dict):
            all_findings.extend(result.get("findings", []))
            all_fixes.extend(result.get("fixes", []))
        elif isinstance(result, Exception):
            logger.error(f"[{AGENT_NAME}] An agent task failed: {result}", exc_info=result)

    logger.info(f"[{AGENT_NAME}] Collated {len(all_findings)} findings and {len(all_fixes)} fixes.")
    return {"results": {"findings": all_findings, "fixes": all_fixes}}


async def finalize_analysis_node(state: CoordinatorState) -> Dict[str, Any]:
    """
    Saves all findings and their associated fixes, then updates the submission status.
    """
    submission_id = state["submission_id"]
    results = state.get("results", {})
    findings_to_save = results.get("findings", [])
    fixes_to_save = results.get("fixes", [])

    logger.info(f"[{AGENT_NAME}] Finalizing analysis for submission {submission_id}.")

    if findings_to_save:
        async with async_session_factory() as db:
            try:
                persisted_findings = await crud.save_findings(db, submission_id, findings_to_save)
                logger.info(f"[{AGENT_NAME}] Saved {len(persisted_findings)} findings.")

                finding_map = {(f.file_path, f.line_number, f.cwe): f.id for f in persisted_findings}
                if fixes_to_save:
                    for fix_result in fixes_to_save:
                        pydantic_finding = fix_result.finding
                        finding_key = (pydantic_finding.file_path, pydantic_finding.line_number, pydantic_finding.cwe)
                        finding_id = finding_map.get(finding_key)
                        if finding_id:
                            await crud.save_fix_suggestion(db, finding_id, fix_result.suggestion)
                    logger.info(f"[{AGENT_NAME}] Saved {len(fixes_to_save)} fix suggestions.")
            except Exception as e:
                logger.error(f"[{AGENT_NAME}] Error saving findings/fixes to DB for {submission_id}: {e}", exc_info=True)

    async with async_session_factory() as db:
        await crud.update_submission_status(db, submission_id, "Completed")
    logger.info(f"[{AGENT_NAME}] Updated status to 'Completed' for submission {submission_id}.")

    results["final_status"] = "Analysis complete."
    return {"results": results}


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
        # This routing logic ensures we proceed to cost estimation only if bundling is successful
        lambda s: "estimate_cost" if not s.get("error") else "end_with_error",
        {
            "estimate_cost": "estimate_cost",
            "end_with_error": "end_with_error" # Route to a defined error endpoint
        }
    )
    
    # After estimation, the workflow pauses by reaching an end state.
    # The 'resume' logic will be handled by a new entry point in the worker.
    workflow.add_edge("estimate_cost", END)
    workflow.add_edge("end_with_error", END)

    return workflow.compile()