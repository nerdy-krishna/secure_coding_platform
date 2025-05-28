import logging
from typing import TypedDict, List, Optional, Dict, Any

from langgraph.graph import StateGraph, END
# No LLM calls are expected for the CoordinatorAgent in Sprint 2 (basic dispatch)

logger = logging.getLogger(__name__)

# Mapping from ASVS categories (or other analysis dimensions) to Specialized Agent names
# This should align with the output structure of ContextAnalysisAgent's 'security_areas'
# and the names of your specialized agent modules.
AREA_TO_SPECIALIZED_AGENT = {
    "V1_Architecture": "ArchitectureAgent",
    "V2_Authentication": "AuthenticationAgent",
    "V3_SessionManagement": "SessionManagementAgent",
    "V4_AccessControl": "AccessControlAgent",
    "V5_Validation": "ValidationAgent",
    "V6_Cryptography": "CryptographyAgent",
    "V7_ErrorHandling": "ErrorHandlingAgent",
    "V8_DataProtection": "DataProtectionAgent",
    "V9_Communication": "CommunicationAgent",
    "V10_MaliciousCode": "CodeIntegrityAgent",  # Assuming CodeIntegrityAgent handles V10
    "V11_BusinessLogic": "BusinessLogicAgent",
    "V12_FileHandling": "FileHandlingAgent",
    "V13_APISecurity": "APISecurityAgent",
    "V14_Configuration": "ConfigurationAgent",
}

# Likelihoods that trigger dispatch to a specialized agent
DISPATCH_LIKELIHOODS = ["Low", "Medium", "High"]


# --- State Definition for CoordinatorAgent ---
class CoordinatorAgentState(TypedDict):
    submission_id: int  # For context and logging
    # Input: Analysis from ContextAnalysisAgent (filename -> analysis_dict)
    contextual_analysis: Dict[str, Any]
    # Input: Original file data
    files_data: List[
        Dict[str, Any]
    ]  # Each dict: {"filename": str, "content": str, "detected_language": str}
    primary_language: Optional[str]
    # Input: Frameworks selected by the user (for future RAG by coordinator/specialized agents)
    # For Sprint 2, this might be implicitly "asvs_v5.0" or passed if available
    selected_frameworks: Optional[List[str]]

    # Output of this agent
    dispatch_tasks: List[Dict[str, Any]]  # List of tasks for specialized agents
    error_message: Optional[str]


# --- Node Functions ---


def generate_dispatch_tasks_node(state: CoordinatorAgentState) -> Dict[str, Any]:
    """
    Generates dispatch tasks for specialized security agents based on contextual analysis.
    This logic is moved from the worker_graph.py's original coordinator_dispatch_node.
    """
    submission_id = state["submission_id"]
    per_file_contextual_analysis = state.get("contextual_analysis", {})
    files_data = state.get("files_data", [])
    primary_language = state.get("primary_language")  # Overall primary language
    # selected_frameworks = state.get("selected_frameworks", ["asvs_v5.0"]) # Default or pass from state

    dispatch_tasks: List[Dict[str, Any]] = []
    any_input_errors = False
    collective_error_message = ""

    logger.info(
        f"CoordinatorAgent Node: generate_dispatch_tasks_node for Submission ID: {submission_id}"
    )

    if not files_data:
        logger.warning(
            f"CoordinatorAgent: No files data found for dispatch (Submission ID: {submission_id})."
        )
        return {
            "dispatch_tasks": [],
            "error_message": "No files data provided to CoordinatorAgent.",
        }

    if not per_file_contextual_analysis:
        logger.warning(
            f"CoordinatorAgent: Contextual analysis missing for dispatch (Submission ID: {submission_id})."
        )
        # This might indicate an upstream issue, but the coordinator itself can't proceed.
        return {
            "dispatch_tasks": [],
            "error_message": "Contextual analysis missing for CoordinatorAgent.",
        }

    for file_info in files_data:
        filename = file_info["filename"]
        file_content = file_info["content"]
        file_language = file_info.get(
            "detected_language", primary_language or "unknown"
        )

        file_level_analysis_output = per_file_contextual_analysis.get(filename, {})

        if file_level_analysis_output.get("agent_error"):
            error_detail = f"Error in contextual analysis for '{filename}': {file_level_analysis_output['agent_error']}"
            logger.warning(
                f"CoordinatorAgent: {error_detail} (Submission ID: {submission_id}). Skipping dispatch for this file."
            )
            any_input_errors = True
            collective_error_message = (
                collective_error_message + "; " if collective_error_message else ""
            ) + error_detail
            continue

        # 'security_areas' is the key holding the ASVS analysis from ContextAnalysisAgent
        # Example: {"V1_Architecture": {"likelihood": "High", "evidence": "...", ...}}
        security_areas_analysis = file_level_analysis_output.get("security_areas", {})
        if not security_areas_analysis:
            logger.warning(
                f"CoordinatorAgent: No security_areas analysis found for '{filename}' (Submission ID: {submission_id}). Skipping dispatch for this file."
            )
            continue

        for area_category, details in security_areas_analysis.items():
            if not isinstance(details, dict):
                logger.warning(
                    f"CoordinatorAgent: Skipping area '{area_category}' for file '{filename}' due to unexpected details format: {type(details)} (Submission ID: {submission_id})"
                )
                continue

            likelihood = details.get("likelihood", "None")

            if likelihood in DISPATCH_LIKELIHOODS:
                specialized_agent_name = AREA_TO_SPECIALIZED_AGENT.get(area_category)
                if specialized_agent_name:
                    logger.debug(
                        f"CoordinatorAgent: Creating dispatch task for {specialized_agent_name} on file '{filename}' (Likelihood: {likelihood}, Area: {area_category}, Submission ID: {submission_id})"
                    )
                    # Prepare context for the specialized agent
                    # This context can be enriched by the CoordinatorAgent in later sprints
                    # (e.g., by adding specific RAG-retrieved framework controls for the specialized agent)
                    task_context_for_specialized_agent = {
                        "triggering_area": area_category,
                        "likelihood_from_context_analysis": likelihood,
                        "evidence_from_context_analysis": details.get("evidence", ""),
                        "key_elements_from_context_analysis": details.get(
                            "key_elements", []
                        ),
                        "relevant_asvs_controls_from_context_analysis": details.get(
                            "relevant_asvs_controls", []
                        ),
                        "file_summary_from_context_analysis": file_level_analysis_output.get(
                            "summary"
                        ),
                        "file_components_from_context_analysis": file_level_analysis_output.get(
                            "components"
                        ),
                        # "selected_frameworks": selected_frameworks # Pass this along
                    }

                    dispatch_tasks.append(
                        {
                            "agent_name": specialized_agent_name,
                            "filename": filename,
                            "snippet": file_content,  # Pass the actual code snippet
                            "language": file_language,
                            "framework": None,  # Placeholder for overall project framework if any; specialized agents might infer or be told
                            "context": task_context_for_specialized_agent,
                        }
                    )
                else:
                    logger.warning(
                        f"CoordinatorAgent: Contextual analysis identified relevant area '{area_category}' (Likelihood: {likelihood}) in '{filename}', but no specialized agent mapping exists. (Submission ID: {submission_id})"
                    )

    if any_input_errors:
        logger.warning(
            f"CoordinatorAgent: Encountered errors in contextual analysis for some files. Dispatch list may be incomplete. Error summary: {collective_error_message} (Submission ID: {submission_id})"
        )
        # Return current dispatch_tasks along with the error message
        return {
            "dispatch_tasks": dispatch_tasks,
            "error_message": collective_error_message,
        }

    logger.info(
        f"CoordinatorAgent: Created {len(dispatch_tasks)} dispatch tasks for Submission ID: {submission_id}."
    )
    return {"dispatch_tasks": dispatch_tasks, "error_message": None}


# --- Graph Construction ---
def build_coordinator_agent_graph() -> Any:
    """Builds and returns the compiled LangGraph for the CoordinatorAgent."""
    graph = StateGraph(CoordinatorAgentState)

    graph.add_node("generate_dispatch_tasks", generate_dispatch_tasks_node)
    graph.set_entry_point("generate_dispatch_tasks")
    graph.add_edge("generate_dispatch_tasks", END)

    compiled_graph = graph.compile()
    logger.info("CoordinatorAgent graph compiled successfully.")
    return compiled_graph


# Optional: If you want to pre-compile it for direct import, though dynamic loading in worker_graph is also fine.
# coordinator_agent_workflow = build_coordinator_agent_graph()
