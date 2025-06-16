# src/app/agents/coordinator_agent.py
import asyncio
import logging
from typing import Any, Dict, List, TypedDict, Optional
import uuid

from langgraph.graph import END, StateGraph

from app.agents.schemas import (
    SpecializedAgentState,
    VulnerabilityFinding as VulnerabilityFindingModel,
    FixResult as FixResultModel,
)
from app.agents.access_control_agent import (
    build_specialized_agent_graph as build_access_control_agent,
)
from app.agents.api_security_agent import (
    build_specialized_agent_graph as build_api_security_agent,
)
from app.agents.architecture_agent import (
    build_specialized_agent_graph as build_architecture_agent,
)
from app.agents.authentication_agent import (
    build_specialized_agent_graph as build_authentication_agent,
)
from app.agents.business_logic_agent import (
    build_specialized_agent_graph as build_business_logic_agent,
)
from app.agents.code_integrity_agent import (
    build_specialized_agent_graph as build_code_integrity_agent,
)
from app.agents.communication_agent import (
    build_specialized_agent_graph as build_communication_agent,
)
from app.agents.configuration_agent import (
    build_specialized_agent_graph as build_configuration_agent,
)
from app.agents.context_analysis_agent import (
    build_context_analysis_agent_graph,
    ContextAnalysisAgentState,
)
from app.agents.cryptography_agent import (
    build_specialized_agent_graph as build_cryptography_agent,
)
from app.agents.data_protection_agent import (
    build_specialized_agent_graph as build_data_protection_agent,
)
from app.agents.error_handling_agent import (
    build_specialized_agent_graph as build_error_handling_agent,
)
from app.agents.file_handling_agent import (
    build_specialized_agent_graph as build_file_handling_agent,
)
from app.agents.session_management_agent import (
    build_specialized_agent_graph as build_session_management_agent,
)
from app.agents.validation_agent import (
    build_specialized_agent_graph as build_validation_agent,
)
from app.db import crud
from app.db.database import AsyncSessionLocal as async_session_factory # Corrected import alias
from app.db.models import CodeSubmission

logger = logging.getLogger(__name__)

AGENT_NAME = "CoordinatorAgent"

AGENT_BUILDER_MAP = {
    "AccessControlAgent": build_access_control_agent,
    "ApiSecurityAgent": build_api_security_agent,
    "ArchitectureAgent": build_architecture_agent,
    "AuthenticationAgent": build_authentication_agent,
    "BusinessLogicAgent": build_business_logic_agent,
    "CodeIntegrityAgent": build_code_integrity_agent,
    "CommunicationAgent": build_communication_agent,
    "ConfigurationAgent": build_configuration_agent,
    "CryptographyAgent": build_cryptography_agent,
    "DataProtectionAgent": build_data_protection_agent,
    "ErrorHandlingAgent": build_error_handling_agent,
    "FileHandlingAgent": build_file_handling_agent,
    "SessionManagementAgent": build_session_management_agent,
    "ValidationAgent": build_validation_agent,
}


class CoordinatorState(TypedDict):
    submission_id: uuid.UUID  # Changed from int
    submission: Optional[CodeSubmission]
    code_snippets_and_paths: List[Dict[str, Any]]  # Values can be str, int (for file_db_id)
    relevant_agents: Dict[str, List[str]]
    results: Dict[str, Any]
    error: Optional[str]


async def retrieve_submission_node(state: CoordinatorState) -> Dict[str, Any]:
    """
    Retrieves the code submission details from the database.
    This is the entry point for the worker's graph execution.
    """
    submission_id_val = state["submission_id"]  # Now uuid.UUID
    logger.info(f"[{AGENT_NAME}] Retrieving submission {submission_id_val}")

    async with async_session_factory() as db:
        try:
            # submission_id_val is already uuid.UUID, no conversion needed.
            submission = await crud.get_submission(db, submission_id_val)
            if not submission:
                logger.error(f"[{AGENT_NAME}] Submission {submission_id_val} not found.")
                return {
                    "submission": None,
                    "code_snippets_and_paths": [],
                    "error": "Submission not found",
                }

            # Access submitted files through the relationship on the Submission object
            # The relationship is named 'files' in the CodeSubmission model.
            # and each item has 'id' (int PK), 'file_path', 'content', 'language'
            submitted_files_list = submission.files # Changed from submission.submitted_files
            if submitted_files_list is None: # Handle case where relationship might not be loaded or is empty
                logger.warning(f"[{AGENT_NAME}] No submitted files found for submission {submission_id_val}.")
                submitted_files_list = []


            code_snippets_and_paths = [
                {
                    "path": file_obj.file_path,
                    "code": file_obj.content,
                    "language": file_obj.language,
                    "file_db_id": file_obj.id,  # Add file_db_id (int PK of SubmittedFile)
                }
                for file_obj in submitted_files_list
            ]

            return {
                "submission": submission,
                "code_snippets_and_paths": code_snippets_and_paths,
                "error": None, # Explicitly set error to None on success
            }
        except Exception as e:
            logger.error(
                f"Failed to retrieve submission {submission_id_val}: {e}", exc_info=True
            )
            return {
                "submission": None,
                "code_snippets_and_paths": [],
                "error": f"Failed to retrieve submission: {e}",
            }


async def initial_analysis_and_routing_node(state: CoordinatorState) -> Dict[str, Any]:
    submission = state["submission"]
    if not submission:
        error_msg = f"[{AGENT_NAME}] Critical error: Submission object is None in 'initial_analysis_and_routing_node'."
        logger.error(error_msg)
        # Return a state that includes 'error' to be caught by 'should_continue'
        # and 'relevant_agents' to match the expected output structure if other paths were taken.
        return {"error": error_msg, "relevant_agents": {}}

    code_snippets_and_paths = state["code_snippets_and_paths"]
    logger.info(
        f"[{AGENT_NAME}] Starting initial analysis for submission {submission.id}"
    )

    # Get the ID for the main LLM, selected by the user during submission
    main_llm_id = submission.main_llm_config_id # Now submission is confirmed not None
    if not main_llm_id:
        # This error implies submission exists but main_llm_config_id is missing.
        return {"error": "Main LLM configuration ID not found in submission.", "relevant_agents": {}}

    relevant_agents: Dict[str, List[str]] = {}
    context_analysis_workflow = build_context_analysis_agent_graph()

    for file_info in code_snippets_and_paths:
        file_path = file_info["path"]
        logger.info(f"[{AGENT_NAME}] Analyzing context for file: {file_path}")

        # Corrected: Prepare the initial state for the sub-agent, including the llm_config_id
        initial_state: ContextAnalysisAgentState = {
            "submission_id": submission.id, # submission is confirmed not None here
            "filename": file_path,
            "code_snippet": file_info["code"],
            "language": file_info["language"],
            "llm_config_id": main_llm_id,  # <-- Pass the main LLM config ID
            "analysis_summary": None,
            "identified_components": None,
            "asvs_analysis": None,
            "error_message": None,
        }
        result_state = await context_analysis_workflow.ainvoke(initial_state)

        if result_state.get("error_message"):
            logger.error(
                f"Context analysis failed for {file_path}: {result_state['error_message']}"
            )
            continue
        
        # ... (the rest of your logic for processing the results remains the same)
        asvs_analysis = result_state.get("asvs_analysis", {})
        context_data = {
            "analysis_summary": result_state.get("analysis_summary"),
            "identified_components": result_state.get("identified_components"),
            "asvs_analysis": asvs_analysis,
        }
        file_db_id = file_info.get("file_db_id")
        if file_db_id:
            async with async_session_factory() as db:
                await crud.update_submission_file_context(
                    db=db,
                    file_id=file_db_id,
                    context=context_data,
                )
        for agent, details in asvs_analysis.items():
            if details.get("is_relevant"):
                if agent not in relevant_agents:
                    relevant_agents[agent] = []
                relevant_agents[agent].append(file_path)

    logger.info(
        f"[{AGENT_NAME}] Relevant agents identified: {list(relevant_agents.keys())}"
    )
    return {"relevant_agents": relevant_agents}


def should_continue(state: CoordinatorState) -> str:
    if state.get("error"):
        return "end"
    if not state.get("relevant_agents"):
        logger.info(
            f"[{AGENT_NAME}] No relevant agents identified. Finalizing analysis."
        )
        return "finalize_analysis"
    return "run_specialized_agents"


async def run_specialized_agents_node(state: CoordinatorState) -> Dict[str, Any]:
    submission_id = state["submission_id"]
    relevant_agents = state["relevant_agents"]
    logger.info(
        f"[{AGENT_NAME}] Beginning specialized agent runs for submission {submission_id}"
    )

    code_map = {item["path"]: item["code"] for item in state["code_snippets_and_paths"]}
    tasks = []

    for agent_name, file_paths in relevant_agents.items():
        agent_builder = AGENT_BUILDER_MAP.get(agent_name)
        if not agent_builder:
            logger.warning(
                f"[{AGENT_NAME}] No builder found for agent: {agent_name}. Skipping."
            )
            continue

        agent_graph = agent_builder()
        for file_path in file_paths:
            code_snippet = code_map.get(file_path)
            if not code_snippet:
                logger.warning(
                    f"Could not find code for file {file_path} for agent {agent_name}. Skipping."
                )
                continue

            initial_agent_state: SpecializedAgentState = {
                "submission_id": submission_id,
                "filename": file_path,
                "code_snippet": code_snippet,
                "findings": [],
                "fixes": [],
                "error": None,
            }
            tasks.append(agent_graph.ainvoke(initial_agent_state))

    if not tasks:
        logger.warning(
            f"[{AGENT_NAME}] No tasks were created for specialized agent runs."
        )
        return {"results": {"findings": [], "fixes": []}}

    logger.info(
        f"[{AGENT_NAME}] Executing {len(tasks)} specialized agent tasks concurrently."
    )
    agent_results = await asyncio.gather(*tasks, return_exceptions=True)

    all_findings: List[VulnerabilityFindingModel] = []
    all_fixes: List[FixResultModel] = []
    for result in agent_results:
        if isinstance(result, Exception):
            logger.error(
                f"[{AGENT_NAME}] An agent task failed: {result}", exc_info=result
            )
        elif isinstance(result, dict): # Check if result is a dictionary
            if result.get("error"):
                logger.error(
                    f"[{AGENT_NAME}] An agent task completed with an error: {result.get('error')}" # Use .get() for safety
                )
            else:
                all_findings.extend(result.get("findings", []))
                all_fixes.extend(result.get("fixes", []))
        else:
            # Handle unexpected result types, though gather with return_exceptions=True should yield dicts or exceptions
            logger.error(f"[{AGENT_NAME}] Unexpected result type from agent task: {type(result)} - {result!r}")

    logger.info(
        f"[{AGENT_NAME}] Collated {len(all_findings)} findings and {len(all_fixes)} fixes from all agents."
    )
    return {"results": {"findings": all_findings, "fixes": all_fixes}}


async def finalize_analysis_node(state: CoordinatorState) -> Dict[str, Any]:
    submission_id = state["submission_id"]
    # Ensure results dict exists, defaulting to an empty one if not provided by previous nodes
    results = state.get("results", {}).copy() # Use a copy to avoid modifying state directly if not intended
    findings_to_save = results.get("findings", [])
    fixes_to_save = results.get("fixes", [])

    logger.info(f"[{AGENT_NAME}] Finalizing analysis for submission {submission_id}.")

    current_submission = state.get("submission")

    if findings_to_save:
        if current_submission and hasattr(current_submission, 'id'):
            submission_int_pk = current_submission.id  # Assuming .id is the int PK
            async with async_session_factory() as db:  # Single session for findings and fixes
                # Save Findings
                persisted_findings = await crud.save_findings(
                    db, submission_int_pk, findings_to_save
                )
                logger.info(f"[{AGENT_NAME}] Saved {len(persisted_findings)} findings for submission {submission_id}.")

                finding_map = {
                    (f.file_path, f.line_number, f.cwe, f.description): f.id
                    for f in persisted_findings
                }

                # Save Fixes (if any persisted_findings and fixes_to_save)
                if persisted_findings and fixes_to_save:
                    logger.info(f"[{AGENT_NAME}] Saving {len(fixes_to_save)} fix suggestions for submission {submission_id}.")
                    for fix_result in fixes_to_save:
                        pydantic_finding = fix_result.finding
                        finding_key = (
                            pydantic_finding.file_path,
                            pydantic_finding.line_number,
                            pydantic_finding.cwe,
                            pydantic_finding.description,
                        )
                        finding_id = finding_map.get(finding_key)

                        if finding_id:
                            await crud.save_fix_suggestion(
                                db, finding_id, fix_result.suggestion
                            )
                        else:
                            logger.warning(
                                f"[{AGENT_NAME}] Could not find a matching saved finding for fix: '{fix_result.suggestion.description}' in submission {submission_id}. Fix will not be saved."
                            )
                elif fixes_to_save:  # Log if fixes exist but no findings were persisted (e.g., DB error during save_findings)
                     logger.warning(
                        f"[{AGENT_NAME}] Fixes present but no findings were persisted for submission {submission_id} (persisted_findings count: {len(persisted_findings)}). Fixes will not be saved."
                    )
        else:
            logger.error(
                f"[{AGENT_NAME}] Cannot save findings for submission {submission_id} "
                f"because submission object or its integer PK is missing in state. Fixes will also be skipped."
            )
    elif fixes_to_save:  # Log if fixes exist but no findings were generated/requested to save
        logger.warning(
            f"[{AGENT_NAME}] No findings to save for submission {submission_id}, but {len(fixes_to_save)} fixes were generated. "
            "Fixes will not be saved as they require associated findings."
        )

    # Update submission status
    async with async_session_factory() as db:
        await crud.update_submission_status(db, submission_id, "Completed")
    logger.info(f"[{AGENT_NAME}] Updated status to 'Completed' for submission {submission_id}.")

    results["final_status"] = "Analysis complete."
    logger.info(
        f"[{AGENT_NAME}] Analysis for submission {submission_id} has been completed."
    )
    return {"results": results}


def build_coordinator_graph():
    """Builds the main coordinator graph."""
    workflow = StateGraph(CoordinatorState)

    workflow.add_node("retrieve_submission", retrieve_submission_node)
    workflow.add_node("initial_analysis_and_routing", initial_analysis_and_routing_node)
    workflow.add_node("run_specialized_agents", run_specialized_agents_node)
    workflow.add_node("finalize_analysis", finalize_analysis_node)

    workflow.set_entry_point("retrieve_submission")
    workflow.add_edge("retrieve_submission", "initial_analysis_and_routing")
    workflow.add_conditional_edges(
        "initial_analysis_and_routing",
        should_continue,
        {
            "run_specialized_agents": "run_specialized_agents",
            "finalize_analysis": "finalize_analysis",
            "end": END,
        },
    )
    workflow.add_edge("run_specialized_agents", "finalize_analysis")
    workflow.add_edge("finalize_analysis", END)

    return workflow
