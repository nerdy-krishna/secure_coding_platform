# src/app/graphs/worker_graph.py

import logging
import re
import json
import asyncio
import importlib
import datetime
from typing import TypedDict, Dict, Any, List, Optional

from langgraph.graph import StateGraph, END
from langgraph.errors import GraphRecursionError

# --- Database Imports ---
from sqlalchemy.future import select
from sqlalchemy.exc import SQLAlchemyError
from src.app.db.database import AsyncSessionLocal
from src.app.db.models import AnalysisResult
from src.app.db.models import CodeSubmission, SubmittedFile


# --- LLM Client and Agent State Import ---
# LLMResult is already imported by context_analysis_agent if needed there.
# SecurityAgentState is for specialized agents, ContextAnalysisAgentState for ContextAnalysisAgent
from ..agents.context_analysis_agent import (
    ContextAnalysisAgentState,
    build_context_analysis_agent_graph,
)


# --- Utilities ---
from ..agents.coordinator_agent import (
    CoordinatorAgentState,
    build_coordinator_agent_graph,
)
from ..agents.reporting_agent import ReportingAgentState, build_reporting_agent_graph


logger = logging.getLogger(__name__)

# --- Agent Loading Implementation ---
COMPILED_AGENTS: Dict[str, Any] = {}

# Pre-compile ContextAnalysisAgent as it's a core part of this graph's initial phase.
# Specialized security agents (V1-V14) will still be loaded dynamically.
try:
    COMPILED_AGENTS["ContextAnalysisAgent"] = build_context_analysis_agent_graph()
    logger.info(
        "ContextAnalysisAgent graph pre-compiled successfully for worker_graph."
    )
    COMPILED_AGENTS["CoordinatorAgent"] = build_coordinator_agent_graph()
    logger.info("CoordinatorAgent graph pre-compiled successfully for worker_graph.")
    # Add ReportingAgent compilation
    COMPILED_AGENTS["ReportingAgent"] = build_reporting_agent_graph()
    logger.info("ReportingAgent graph pre-compiled successfully for worker_graph.")
except Exception as e:
    logger.critical(
        f"Failed to pre-compile a core supporting agent: {e}", exc_info=True
    )
    # This is a critical failure for the worker's intended operation.


def get_compiled_agent(agent_name: str) -> Optional[Any]:
    """
    Retrieves or dynamically loads and compiles a LangGraph for a specific agent.
    Uses importlib to load agents from the src/app/agents/ directory.
    Assumes a convention: Agent 'MyAgentName' is in 'my_agent_name.py'
    and has a build function 'build_my_agent_name_graph'.
    Handles CamelCase to snake_case conversion, including for acronyms like 'API'.
    Tries absolute import first, then falls back to relative import.
    Returns the compiled graph object (type Any for compatibility).
    """
    global COMPILED_AGENTS

    if agent_name in COMPILED_AGENTS:
        logger.debug(f"Returning cached compiled graph for agent '{agent_name}'.")
        return COMPILED_AGENTS[agent_name]

    logger.info(f"Attempting to dynamically load and compile agent '{agent_name}'...")
    module_name = (
        ""  # Initialize to ensure it's defined for logging in case of early failure
    )
    try:
        s1 = re.sub("(.)([A-Z][a-z]+)", r"\1_\2", agent_name)
        module_name_base = re.sub("([a-z0-9])([A-Z])", r"\1_\2", s1).lower()

        if module_name_base.endswith("_agent"):
            module_name = module_name_base
        elif module_name_base.endswith("agent") and agent_name.endswith("Agent"):
            module_name = module_name_base.replace("agent", "_agent", 1)
        else:
            module_name = f"{module_name_base}_agent"

        logger.debug(
            f"Converted agent name '{agent_name}' to module name '{module_name}'"
        )

        agent_module = None
        try:
            absolute_path = f"src.app.agents.{module_name}"
            logger.debug(f"Attempting absolute import from: {absolute_path}")
            agent_module = importlib.import_module(absolute_path)
            logger.info(
                f"Successfully imported module using absolute path: {absolute_path}"
            )
        except ImportError as e1:
            logger.warning(f"Absolute import failed: {e1}. Trying relative import...")
            try:
                relative_path = f"..agents.{module_name}"
                logger.debug(
                    f"Attempting relative import from: {relative_path} (package='src.app.graphs')"
                )
                agent_module = importlib.import_module(
                    relative_path, package="src.app.graphs"
                )
                logger.info(
                    f"Successfully imported module using relative path: {relative_path}"
                )
            except ImportError as e2:
                logger.error(f"Relative import also failed: {e2}")
                raise ImportError(
                    f"Could not import agent module '{module_name}' for agent '{agent_name}' using absolute or relative paths."
                ) from e2

        build_func_name = f"build_{module_name}_graph"
        logger.debug(f"Getting build function: {build_func_name}")
        build_func = getattr(agent_module, build_func_name)

        logger.info(f"Building and compiling graph for agent '{agent_name}'...")
        agent_graph_compiled_object = build_func()

        COMPILED_AGENTS[agent_name] = agent_graph_compiled_object
        logger.info(f"Successfully loaded and compiled agent '{agent_name}'.")
        return agent_graph_compiled_object
    except (ImportError, AttributeError, Exception) as e:
        logger.error(
            f"Failed to load/compile agent '{agent_name}' (module: '{module_name}'): {e}",
            exc_info=True,
        )
        return None


# --- Worker Graph State Definition ---
class WorkerGraphState(TypedDict):
    submission_id: int
    files_data: Optional[List[Dict[str, Any]]] = None
    primary_language: Optional[str] = None
    # This will store the output from ContextAnalysisAgent for each file
    contextual_analysis: Optional[Dict[str, Any]] = None  # filename -> analysis_dict
    dispatch_tasks: Optional[List[Dict[str, Any]]] = None
    agent_results: Optional[List[Dict[str, Any]]] = None
    sast_findings: Optional[List[Dict[str, Any]]] = None  # For future tool integration
    sca_findings: Optional[List[Dict[str, Any]]] = None  # For future tool integration
    ts_query_matches: Optional[List[Dict[str, Any]]] = (
        None  # For future Tree-sitter path
    )
    collated_findings: Optional[List[Dict[str, Any]]] = None
    final_report: Optional[Dict[str, Any]] = None
    final_fixed_code: Optional[Dict[str, str]] = None  # filename -> fixed_code_string
    db_save_status: Optional[str] = None
    error_message: Optional[str] = None


# --- Specialized Security Agent State Definition (used by V1-V14 agents) ---
class SecurityAgentState(TypedDict):
    code_snippet: str
    language: str
    framework: Optional[str]
    task_context: Optional[Dict[str, Any]]
    findings: Optional[List[Dict[str, Any]]]
    fixed_code_snippet: Optional[str]
    explanation: Optional[str]
    error: Optional[str]
    asvs_mapping: Optional[List[Dict[str, str]]]
    cwe_mapping: Optional[List[Dict[str, str]]]


# --- Node Functions ---
async def fetch_code_from_db_node(state: WorkerGraphState) -> Dict[str, Any]:
    logger.info(
        f"Worker Node: fetch_code_from_db_node (Submission ID: {state['submission_id']})"
    )
    submission_id = state["submission_id"]
    files_data = []
    primary_language = None
    try:
        async with AsyncSessionLocal() as session:
            submission_result = await session.execute(
                select(CodeSubmission).where(CodeSubmission.id == submission_id)
            )
            submission = submission_result.scalar_one_or_none()
            if not submission:
                return {"error_message": f"Submission ID {submission_id} not found."}
            primary_language = submission.primary_language
            files_result = await session.execute(
                select(SubmittedFile).where(
                    SubmittedFile.submission_id == submission_id
                )
            )
            files = files_result.scalars().all()
            if not files:
                logger.warning(
                    f"No files found for submission ID {submission_id}. Proceeding without files."
                )
                return {
                    "files_data": [],
                    "primary_language": primary_language,
                    "error_message": None,
                }
            for (
                file_obj
            ) in files:  # Changed 'file' to 'file_obj' to avoid conflict with built-in
                files_data.append(
                    {
                        "filename": file_obj.filename,
                        "content": file_obj.content,
                        "detected_language": file_obj.detected_language,
                    }
                )
            logger.info(
                f"Fetched {len(files_data)} file(s) for submission {submission_id}."
            )
        return {
            "files_data": files_data,
            "primary_language": primary_language,
            "error_message": None,
        }
    except SQLAlchemyError as e:
        logger.error(
            f"Database error fetching code for submission {submission_id}: {e}",
            exc_info=True,
        )
        return {"error_message": f"DB fetch failed: {e}"}
    except Exception as e:
        logger.error(
            f"Unexpected error fetching code for submission {submission_id}: {e}",
            exc_info=True,
        )
        return {"error_message": f"Unexpected error during DB fetch: {e}"}


async def initial_contextual_analysis_node(state: WorkerGraphState) -> Dict[str, Any]:
    """
    Invokes the ContextAnalysisAgent for each file to perform RAG-enhanced analysis.
    """
    logger.info(
        f"Worker Node: initial_contextual_analysis_node (Submission ID: {state['submission_id']})"
    )
    files_data = state.get("files_data")
    submission_id = state["submission_id"]
    primary_language = state.get("primary_language", "unknown")

    # This will store the analysis output for each file, keyed by filename
    per_file_contextual_analysis: Dict[str, Any] = {}
    any_agent_errors = False
    collective_error_message = state.get("error_message", "")

    if not files_data:
        logger.warning("No files_data found for initial contextual analysis. Skipping.")
        return {"contextual_analysis": {}, "error_message": collective_error_message}

    context_analysis_workflow = get_compiled_agent("ContextAnalysisAgent")
    if not context_analysis_workflow:
        err_msg = (
            "ContextAnalysisAgent could not be loaded. Cannot perform initial analysis."
        )
        logger.critical(err_msg)
        return {
            "contextual_analysis": {},
            "error_message": (
                collective_error_message + "; " if collective_error_message else ""
            )
            + err_msg,
        }

    analysis_tasks = []
    for file_info in files_data:
        filename = file_info["filename"]
        content = file_info["content"]
        language = file_info.get("detected_language", primary_language)

        agent_initial_state: ContextAnalysisAgentState = {
            "submission_id": submission_id,
            "filename": filename,
            "code_snippet": content,
            "language": language,
            # selected_frameworks can be added here if needed by the agent
            "analysis_summary": None,
            "identified_components": None,
            "asvs_analysis": None,
            "error_message": None,
        }
        analysis_tasks.append(context_analysis_workflow.ainvoke(agent_initial_state))

    logger.info(
        f"Running ContextAnalysisAgent for {len(analysis_tasks)} files concurrently..."
    )
    results: List[ContextAnalysisAgentState] = await asyncio.gather(
        *analysis_tasks, return_exceptions=True
    )

    for i, agent_final_state in enumerate(results):
        filename = files_data[i]["filename"]  # Get filename based on original order
        if isinstance(agent_final_state, Exception):
            logger.error(
                f"ContextAnalysisAgent failed for file '{filename}': {agent_final_state}",
                exc_info=agent_final_state,
            )
            agent_error = f"Agent exception for {filename}: {str(agent_final_state)}"
            any_agent_errors = True
            collective_error_message = (
                collective_error_message + "; " if collective_error_message else ""
            ) + agent_error
            per_file_contextual_analysis[filename] = {
                "filename": filename,
                "summary": "Error during analysis.",
                "components": [],
                "security_areas": {},  # Ensure this key exists for coordinator
                "agent_error": agent_error,  # Keep agent_error for per-file context
            }
        elif agent_final_state.get("error_message"):
            agent_error = agent_final_state["error_message"]
            logger.warning(
                f"ContextAnalysisAgent for '{filename}' reported error: {agent_error}"
            )
            any_agent_errors = True
            collective_error_message = (
                collective_error_message + "; " if collective_error_message else ""
            ) + f"Error for {filename}: {agent_error}"
            per_file_contextual_analysis[filename] = {
                "filename": filename,
                "summary": agent_final_state.get("analysis_summary", "Analysis error."),
                "components": agent_final_state.get("identified_components", []),
                "security_areas": agent_final_state.get(
                    "asvs_analysis", {}
                ),  # Ensure security_areas exists
                "agent_error": agent_error,  # Keep agent_error for per-file context
            }
        else:
            logger.info(
                f"ContextAnalysisAgent successfully processed file '{filename}'."
            )
            per_file_contextual_analysis[filename] = {
                "filename": filename,  # Ensure filename is part of the stored structure
                "summary": agent_final_state.get("analysis_summary"),
                "components": agent_final_state.get("identified_components"),
                "security_areas": agent_final_state.get(
                    "asvs_analysis"
                ),  # This is the ASVS-specific analysis
                "agent_error": None,
            }

    logger.info(f"Initial contextual analysis complete for submission {submission_id}.")
    return {
        "contextual_analysis": per_file_contextual_analysis,
        "error_message": collective_error_message
        if any_agent_errors
        else state.get("error_message"),
    }


async def coordinator_dispatch_node(state: WorkerGraphState) -> Dict[str, Any]:
    """
    Invokes the CoordinatorAgent to generate dispatch tasks for specialized agents.
    """
    submission_id = state["submission_id"]
    logger.info(
        f"Worker Node: coordinator_dispatch_node (Invoking CoordinatorAgent for Submission ID: {submission_id})"
    )

    contextual_analysis_data = state.get("contextual_analysis")
    files_data_list = state.get("files_data")
    current_error_message = state.get(
        "error_message", ""
    )  # Carry forward existing errors

    if not contextual_analysis_data or not files_data_list:
        err_msg = (
            "Missing contextual analysis or files data for CoordinatorAgent invocation."
        )
        logger.error(f"{err_msg} (Submission ID: {submission_id})")
        return {
            "dispatch_tasks": [],
            "error_message": (
                current_error_message + "; " if current_error_message else ""
            )
            + err_msg,
        }

    coordinator_workflow = get_compiled_agent("CoordinatorAgent")
    if not coordinator_workflow:
        err_msg = (
            "CoordinatorAgent could not be loaded. Cannot generate dispatch tasks."
        )
        logger.critical(f"{err_msg} (Submission ID: {submission_id})")
        return {
            "dispatch_tasks": [],
            "error_message": (
                current_error_message + "; " if current_error_message else ""
            )
            + err_msg,
        }

    coordinator_initial_state: CoordinatorAgentState = {
        "submission_id": submission_id,
        "contextual_analysis": contextual_analysis_data,
        "files_data": files_data_list,
        "primary_language": state.get("primary_language"),
        "selected_frameworks": state.get(
            "selected_frameworks"
        ),  # Pass this if available in WorkerGraphState
        "dispatch_tasks": [],  # Will be populated by the agent
        "error_message": None,  # Agent's own error message
    }

    try:
        coordinator_final_state: CoordinatorAgentState = (
            await coordinator_workflow.ainvoke(coordinator_initial_state)
        )

        dispatch_tasks = coordinator_final_state.get("dispatch_tasks", [])
        agent_error_message = coordinator_final_state.get("error_message")

        if agent_error_message:
            logger.warning(
                f"CoordinatorAgent reported an error: {agent_error_message} (Submission ID: {submission_id})"
            )
            current_error_message = (
                current_error_message + "; " if current_error_message else ""
            ) + f"Coordinator Error: {agent_error_message}"

        logger.info(
            f"CoordinatorAgent produced {len(dispatch_tasks)} dispatch tasks. (Submission ID: {submission_id})"
        )

        return {
            "dispatch_tasks": dispatch_tasks,
            "error_message": current_error_message
            or None,  # Return None if it's an empty string
        }

    except Exception as e:
        err_msg = f"Exception invoking CoordinatorAgent: {str(e)}"
        logger.error(f"{err_msg} (Submission ID: {submission_id})", exc_info=True)
        return {
            "dispatch_tasks": [],
            "error_message": (
                current_error_message + "; " if current_error_message else ""
            )
            + err_msg,
        }


async def run_specialized_agents_node(state: WorkerGraphState) -> Dict[str, Any]:
    submission_id = state["submission_id"]
    logger.info(
        f"Worker Node: run_specialized_agents_node (Submission ID: {submission_id})"
    )
    dispatch_tasks = state.get("dispatch_tasks")
    primary_language = state.get("primary_language", "unknown")
    # Ensure error_message from previous steps is carried forward and potentially appended to
    collective_error_message = state.get("error_message", "")
    any_agent_run_errors = False  # Tracks if any new errors occur in this node

    if not dispatch_tasks:
        logger.warning(
            f"No dispatch tasks found for running specialized agents (Submission ID: {submission_id})."
        )
        # Return current state of errors, no new agent_results
        return {"agent_results": [], "error_message": collective_error_message or None}

    all_agent_results: List[Dict[str, Any]] = []
    tasks_to_run: List[asyncio.Task] = []

    async def invoke_specialized_agent(task_details: Dict[str, Any]) -> Dict[str, Any]:
        agent_name = task_details["agent_name"]
        filename = task_details["filename"]
        code_snippet = task_details["snippet"]  # Renamed from 'snippet' for clarity
        language = task_details.get("language", primary_language)
        framework = task_details.get(
            "framework"
        )  # This was passed from CoordinatorAgent
        task_context = task_details["context"]

        # Unique ID for logging this specific agent invocation attempt
        task_invocation_id = (
            f"{agent_name}-{filename}-{task_context.get('triggering_area', 'general')}"
        )

        logger.info(
            f"Preparing to run agent '{agent_name}' for file '{filename}' (Task Invocation ID: {task_invocation_id}, Submission: {submission_id})"
        )

        agent_workflow = get_compiled_agent(agent_name)
        if agent_workflow is None:
            err_msg = f"Could not load compiled graph for agent '{agent_name}'. Skipping task {task_invocation_id}."
            logger.error(err_msg)
            # No direct LLM call here, but we mark this as a failure of this agent task
            return {
                "agent_name": agent_name,
                "filename": filename,
                "status": "error",
                "error": f"Agent graph load failed: {agent_name}",
                "output": None,  # No agent state to return
                "task_context": task_context,
            }

        # Prepare the initial state for the specialized agent
        # Crucially, pass submission_id and filename for the agent's internal logging
        agent_initial_state: SecurityAgentState = {
            "submission_id": submission_id,  # Passed for agent's internal logging
            "filename": filename,  # Passed for agent's internal logging
            "code_snippet": code_snippet,
            "language": language,
            "framework": framework,
            "task_context": task_context,
            "findings": None,
            "fixed_code_snippet": None,
            "explanation": None,
            "error": None,  # Agent will populate this if it encounters internal errors
            "asvs_mapping": None,
            "cwe_mapping": None,
        }

        agent_final_state: Optional[SecurityAgentState] = None
        invocation_error_msg: Optional[str] = None

        try:
            logger.debug(
                f"Invoking agent '{agent_name}' graph for task {task_invocation_id} (Submission: {submission_id})..."
            )
            agent_final_state = await agent_workflow.ainvoke(
                agent_initial_state,
                config={"recursion_limit": 15},  # Standard recursion limit
            )
            logger.info(
                f"Agent '{agent_name}' completed for task {task_invocation_id} (Submission: {submission_id})."
            )

            # Check if the agent itself reported an error in its final state
            if agent_final_state and agent_final_state.get("error"):
                invocation_error_msg = agent_final_state.get("error")
                logger.warning(
                    f"Agent '{agent_name}' for task {task_invocation_id} reported an internal error: {invocation_error_msg} (Submission: {submission_id})"
                )

        except GraphRecursionError as rec_err:
            invocation_error_msg = f"GraphRecursionError for agent '{agent_name}', task {task_invocation_id}: {str(rec_err)}"
            logger.error(
                invocation_error_msg, exc_info=False
            )  # Keep log cleaner for recursion
        except Exception as agent_exc:
            invocation_error_msg = f"Exception during agent '{agent_name}' invocation for task {task_invocation_id}: {str(agent_exc)}"
            logger.error(invocation_error_msg, exc_info=True)

        # Construct the result for this agent task
        # If agent_final_state is None (due to early exception before ainvoke returns),
        # create a minimal error state.
        if agent_final_state is None:
            agent_final_state = agent_initial_state.copy()  # type: ignore # Start with initial
            agent_final_state["error"] = (
                invocation_error_msg or "Unknown invocation error"
            )

        # The definitive error for this task is either what the agent returned or an invocation exception
        final_task_error = agent_final_state.get("error") or invocation_error_msg

        return {
            "agent_name": agent_name,
            "filename": filename,
            "status": "error" if final_task_error else "completed",
            "error": final_task_error,
            "output": agent_final_state,  # The entire final state of the specialized agent
            "task_context": task_context,
        }

    # --- End invoke_specialized_agent helper ---

    for task_data_item in dispatch_tasks:  # Renamed to avoid conflict
        tasks_to_run.append(
            asyncio.create_task(invoke_specialized_agent(task_data_item))
        )

    if tasks_to_run:
        logger.info(
            f"Waiting for {len(tasks_to_run)} specialized agent tasks to complete (Submission ID: {submission_id})..."
        )

        # This captures results from invoke_specialized_agent or exceptions if invoke_specialized_agent itself fails
        results_or_exceptions_from_tasks = await asyncio.gather(
            *tasks_to_run, return_exceptions=True
        )

        for i, res_or_exc in enumerate(results_or_exceptions_from_tasks):
            original_task_details = dispatch_tasks[
                i
            ]  # Get corresponding original task details
            agent_name_for_reporting = original_task_details["agent_name"]
            filename_for_reporting = original_task_details["filename"]

            if isinstance(res_or_exc, Exception):
                # This means the invoke_specialized_agent task itself had an unhandled exception
                # (should be rare if invoke_specialized_agent has good try-except)
                error_str = f"Task execution exception for {agent_name_for_reporting} on {filename_for_reporting}: {str(res_or_exc)}"
                logger.error(error_str, exc_info=res_or_exc)
                any_agent_run_errors = True
                collective_error_message = (
                    collective_error_message + "; " if collective_error_message else ""
                ) + error_str
                all_agent_results.append(
                    {
                        "agent_name": agent_name_for_reporting,
                        "filename": filename_for_reporting,
                        "status": "error",
                        "error": error_str,
                        "output": None,  # No agent state if task itself failed
                        "task_context": original_task_details["context"],
                    }
                )
            else:
                # res_or_exc is the dictionary returned by invoke_specialized_agent
                all_agent_results.append(res_or_exc)
                if res_or_exc.get(
                    "error"
                ):  # If the agent task completed but reported an error
                    any_agent_run_errors = True
                    # The error from the agent is already part of res_or_exc["error"]
                    # We construct the collective_error_message based on these.
                    err_detail = f"Error from {res_or_exc['agent_name']} for {res_or_exc['filename']}: {res_or_exc['error']}"
                    collective_error_message = (
                        collective_error_message + "; "
                        if collective_error_message
                        else ""
                    ) + err_detail

        logger.info(
            f"All {len(tasks_to_run)} specialized agent tasks finished processing (Submission ID: {submission_id})."
        )
    else:
        logger.info(
            f"No specialized agent tasks were created to run (Submission ID: {submission_id})."
        )

    final_overall_error_message = (
        collective_error_message
        if any_agent_run_errors or collective_error_message
        else None
    )

    # Log a summary of errors encountered during this node's execution
    if any_agent_run_errors:
        logger.warning(
            f"One or more specialized agent tasks reported errors or failed during execution. Collective error: {final_overall_error_message} (Submission ID: {submission_id})"
        )

    return {
        "agent_results": all_agent_results,
        "error_message": final_overall_error_message,
    }


async def assemble_and_collate_node(state: WorkerGraphState) -> Dict[str, Any]:
    logger.info(
        f"Worker Node: assemble_and_collate_node (Submission ID: {state['submission_id']})"
    )
    agent_results_list = state.get("agent_results", [])
    collated_findings = []
    merged_fixed_code_map: Dict[str, str] = {}
    # Initialize original_code_map from files_data in the current state
    files_data_list = state.get("files_data", [])
    original_code_map: Dict[str, str] = {
        f["filename"]: f["content"] for f in files_data_list
    }

    collective_error_message = state.get("error_message", "")
    any_new_collation_errors = False

    try:
        for result in agent_results_list:
            agent_name = result["agent_name"]
            filename = result["filename"]
            status = result["status"]
            agent_output: Optional[SecurityAgentState] = result.get(
                "output"
            )  # Output is SecurityAgentState

            if status == "completed" and agent_output:
                findings = agent_output.get("findings", [])
                if findings:
                    for finding in findings:
                        finding_detail = {
                            "source": f"Agent:{agent_name}",
                            "filename": filename,
                            "details": finding,
                            "trigger_context": result.get("task_context"),
                        }
                        collated_findings.append(finding_detail)

                fixed_snippet = agent_output.get("fixed_code_snippet")
                # Get original code for THIS specific file to compare
                original_snippet_for_file = original_code_map.get(filename)

                if fixed_snippet and fixed_snippet != original_snippet_for_file:
                    logger.debug(
                        f"Agent '{agent_name}' provided a fix for '{filename}'. Storing it."
                    )
                    # Simple strategy: last agent to provide a fix for this file wins for now
                    # More sophisticated merging can be added later if needed.
                    merged_fixed_code_map[filename] = fixed_snippet
                elif fixed_snippet and fixed_snippet == original_snippet_for_file:
                    logger.debug(
                        f"Agent '{agent_name}' provided a 'fix' for '{filename}' that is identical to original. Not storing."
                    )

            elif status == "error":
                err_msg = f"Agent '{agent_name}' reported an error for file '{filename}': {result.get('error')}"
                logger.warning(err_msg)
                collated_findings.append(
                    {
                        "source": f"Agent:{agent_name}",
                        "filename": filename,
                        "is_error": True,
                        "details": {"error_message": result.get("error")},
                        "trigger_context": result.get("task_context"),
                    }
                )
                any_new_collation_errors = (
                    True  # Though this error originated from agent
                )
                collective_error_message = (
                    collective_error_message + "; " if collective_error_message else ""
                ) + err_msg

        # TODO: Integrate SAST, SCA, TreeSitter findings in future sprints
        sast_findings = state.get("sast_findings")
        sca_findings = state.get("sca_findings")
        ts_matches = state.get("ts_query_matches")

        if sast_findings:
            logger.debug("Collating SAST findings...")
            collated_findings.extend(
                [{"source": "SAST", "details": f} for f in sast_findings]
            )
        if sca_findings:
            logger.debug("Collating SCA findings...")
            collated_findings.extend(
                [{"source": "SCA", "details": f} for f in sca_findings]
            )
        if ts_matches:
            logger.debug("Collating TreeSitter findings...")
            collated_findings.extend(
                [{"source": "TreeSitter", "details": m} for m in ts_matches]
            )

        if merged_fixed_code_map:
            logger.info(
                f"Collation complete. {len(collated_findings)} findings/errors collated. "
                f"Suggested fixes available for {list(merged_fixed_code_map.keys())}."
            )
        else:
            logger.info(
                f"Collation complete. {len(collated_findings)} findings/errors collated. "
                "No new fixed code snippets provided or accepted from agents."
            )

        final_error_message = (
            collective_error_message
            if any_new_collation_errors
            else state.get("error_message")
        )

        return {
            "collated_findings": collated_findings,
            "final_fixed_code": merged_fixed_code_map,
            "error_message": final_error_message,
        }

    except Exception as e:
        new_err = f"Collation failed: {e}"
        logger.error(f"Error during collation node: {e}", exc_info=True)
        final_error_message = (
            collective_error_message + "; " if collective_error_message else ""
        ) + new_err
        return {"error_message": final_error_message}


async def generate_report_node(state: WorkerGraphState) -> Dict[str, Any]:
    submission_id = state["submission_id"]
    logger.info(
        f"Worker Node: generate_report_node (Invoking ReportingAgent for Submission ID: {submission_id})"
    )

    collated_findings = state.get("collated_findings", [])
    files_data = state.get("files_data", [])
    primary_language = state.get("primary_language")
    final_fixed_code_map = state.get("final_fixed_code")
    current_error_message = state.get(
        "error_message", ""
    )  # Carry forward existing errors

    reporting_workflow = get_compiled_agent("ReportingAgent")
    if not reporting_workflow:
        err_msg = "ReportingAgent could not be loaded. Cannot generate final reports."
        logger.critical(f"{err_msg} (Submission ID: {submission_id})")
        # Ensure final_report is initialized to avoid downstream errors if save_results expects it
        return {
            "final_report": {
                "submission_id": submission_id,
                "error": "ReportingAgent failed to load.",
                "summary": "Critical error: Reporting agent unavailable.",
                "findings": collated_findings,  # Pass findings along if they exist
            },
            "error_message": (
                current_error_message + "; " if current_error_message else ""
            )
            + err_msg,
        }

    reporting_initial_state: ReportingAgentState = {
        "submission_id": submission_id,
        "collated_findings": collated_findings,
        "files_data": files_data,
        "primary_language": primary_language,
        "final_fixed_code_map": final_fixed_code_map,
        "json_report_data": None,
        "sarif_report_data": None,
        "text_summary_data": None,
        "final_structured_report": None,  # Will be populated by the agent
        "error_message": None,  # Agent's own error message
    }

    try:
        reporting_final_state: ReportingAgentState = await reporting_workflow.ainvoke(
            reporting_initial_state
        )

        final_structured_report = reporting_final_state.get("final_structured_report")
        agent_error_message = reporting_final_state.get("error_message")

        if agent_error_message:
            logger.warning(
                f"ReportingAgent reported an error: {agent_error_message} (Submission ID: {submission_id})"
            )
            current_error_message = (
                current_error_message + "; " if current_error_message else ""
            ) + f"Reporting Error: {agent_error_message}"

        if not final_structured_report:
            err_msg = "ReportingAgent did not produce a final_structured_report."
            logger.error(f"{err_msg} (Submission ID: {submission_id})")
            current_error_message = (
                current_error_message + "; " if current_error_message else ""
            ) + err_msg
            # Provide a minimal error report structure
            final_structured_report = {
                "submission_id": submission_id,
                "error": err_msg,
                "summary": "Error: Failed to generate complete report.",
                "findings": collated_findings,  # Include findings if available
                "generated_at": datetime.datetime.now(
                    datetime.timezone.utc
                ).isoformat(),
            }

        logger.info(
            f"ReportingAgent successfully generated reports. (Submission ID: {submission_id})"
        )

        return {
            "final_report": final_structured_report,  # This is the comprehensive report object
            "error_message": current_error_message or None,
        }

    except Exception as e:
        err_msg = f"Exception invoking ReportingAgent: {str(e)}"
        logger.error(f"{err_msg} (Submission ID: {submission_id})", exc_info=True)
        # Provide a minimal error report structure in case of critical failure
        error_report = {
            "submission_id": submission_id,
            "error": err_msg,
            "summary": "Critical error during report generation.",
            "findings": collated_findings,  # Include findings if available
            "generated_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        }
        return {
            "final_report": error_report,
            "error_message": (
                current_error_message + "; " if current_error_message else ""
            )
            + err_msg,
        }


async def save_results_node(state: WorkerGraphState) -> Dict[str, Any]:
    logger.info(
        f"Worker Node: save_results_node (Submission ID: {state['submission_id']})"
    )
    final_report = state.get("final_report")
    # final_fixed_code_map is a Dict[str, str] from previous node
    final_fixed_code_map = state.get("final_fixed_code")
    submission_id = state.get("submission_id")
    error_message = state.get("error_message")  # This is the cumulative error message

    status = "failed" if error_message else "completed"

    if not final_report and not error_message:
        logger.warning(
            f"No final report generated for submission {submission_id}, but no explicit error. Saving minimal result."
        )
        # Create a minimal report if none exists but there's no overarching error
        final_report = {
            "submission_id": submission_id,
            "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "summary": "Analysis completed with no explicit findings or errors reported by content generation stages.",
            "findings": [],
        }
    elif final_report and error_message:  # Report exists but there were errors
        final_report["error_summary"] = (
            f"Analysis completed with issues: {error_message}"
        )

    files_data = state.get("files_data") or []  # Ensure files_data is a list
    original_code_map = {f["filename"]: f["content"] for f in files_data}
    original_code_to_save_json = None  # This will store the JSON string
    if original_code_map:
        try:
            original_code_to_save_json = json.dumps(
                original_code_map
            )  # No indent needed for DB usually
        except TypeError as json_err:
            logger.error(f"Failed to serialize original_code_map to JSON: {json_err}")
            error_message = (
                (error_message + "; " if error_message else "")
                + f"Failed to serialize original code: {json_err}"
            )
            status = "failed"

    # Serialize the final_fixed_code_map to JSON string for TEXT column
    fixed_code_to_save_json = None
    if final_fixed_code_map and isinstance(final_fixed_code_map, dict):
        try:
            fixed_code_to_save_json = json.dumps(
                final_fixed_code_map
            )  # No indent needed
        except TypeError as json_err:
            logger.error(
                f"Failed to serialize final_fixed_code_map to JSON: {json_err}"
            )
            error_message = (
                (error_message + "; " if error_message else "")
                + f"Failed to serialize fixed code: {json_err}"
            )
            status = "failed"
            fixed_code_to_save_json = None

    try:
        async with AsyncSessionLocal() as session:
            async with session.begin():
                result_stmt = select(AnalysisResult).where(
                    AnalysisResult.submission_id == submission_id
                )
                existing_result = (
                    await session.execute(result_stmt)
                ).scalar_one_or_none()

                if existing_result:
                    logger.info(f"Updating existing AnalysisResult for {submission_id}")
                    existing_result.report_content = final_report
                    # --- CORRECTED ATTRIBUTE NAMES BELOW ---
                    existing_result.original_code_snapshot = (
                        original_code_to_save_json
                    )
                    existing_result.fixed_code_snapshot = (
                        fixed_code_to_save_json
                    )
                    # --- END OF CORRECTION ---
                    existing_result.completed_at = datetime.datetime.now(
                        datetime.timezone.utc
                    )
                    existing_result.status = status
                    existing_result.error_message = error_message
                    session.add(existing_result)
                else:
                    logger.info(f"Creating new AnalysisResult for {submission_id}")
                    db_result = AnalysisResult(
                        submission_id=submission_id,
                        report_content=final_report,
                        original_code_snapshot=original_code_to_save_json,
                        fixed_code_snapshot=fixed_code_to_save_json,
                        status=status,
                        error_message=error_message,
                        completed_at=datetime.datetime.now(
                            datetime.timezone.utc
                        ),
                    )
                    session.add(db_result)
        logger.info(
            f"Successfully saved results to DB for {submission_id} (Status: '{status}')"
        )
        return {
            "db_save_status": "Success",
            "error_message": error_message if status == "failed" else None,
        }

    except SQLAlchemyError as db_exc:
        logger.error(
            f"Database error saving final results for submission {submission_id}: {db_exc}",
            exc_info=True,
        )
        final_error_msg = (
            (error_message + "; " if error_message else "") + f"DB save failed: {db_exc}"
        )
        return {"db_save_status": "Failed", "error_message": final_error_msg}
    except Exception as e:
        logger.error(
            f"Unexpected error saving final results for submission {submission_id}: {e}",
            exc_info=True,
        )
        final_error_msg = (
            (error_message + "; " if error_message else "") + f"Unexpected error during DB save: {e}"
        )
        return {"db_save_status": "Failed", "error_message": final_error_msg}


# --- Conditional Edge Logic ---
def route_after_fetch(state: WorkerGraphState) -> str:
    if state.get("error_message"):
        logger.error(
            f"Routing to save_results due to DB fetch error: {state['error_message']}"
        )
        return "save_results"
    elif not state.get("files_data"):
        logger.warning(
            f"No files fetched for submission {state.get('submission_id')}. Proceeding to save empty result."
        )
        return "save_results"
    else:
        logger.info("DB fetch successful, proceeding to Initial Contextual Analysis.")
        # Corrected target node name
        return "initial_contextual_analysis"


def route_after_initial_contextual_analysis(state: WorkerGraphState) -> str:
    """Routes after initial contextual analysis by ContextAnalysisAgent."""
    if state.get("error_message"):
        logger.error(
            f"Routing to save_results due to error in initial contextual analysis: {state['error_message']}"
        )
        return "save_results"
    else:
        logger.info(
            "Initial contextual analysis complete, proceeding to coordinator dispatch."
        )
        return "coordinator_dispatch"  # Corrected target node name


def route_after_dispatch(state: WorkerGraphState) -> str:
    if state.get("error_message"):
        logger.error(
            f"Routing to save_results due to error during dispatch: {state['error_message']}"
        )
        return "save_results"
    elif not state.get("dispatch_tasks"):
        logger.warning(
            f"No agent dispatch tasks created for submission {state.get('submission_id')}. Proceeding directly to collation."
        )
        return "assemble_collate"  # Corrected target node name
    else:
        logger.info(
            "Coordinator dispatch complete, proceeding to run specialized agents."
        )
        return "run_specialized_agents"  # Corrected target node name


def route_after_agents(state: WorkerGraphState) -> str:
    if state.get("error_message"):
        logger.error(
            f"Routing to save_results due to critical error passed from agent run: {state['error_message']}"
        )
        return "save_results"
    else:
        logger.info("Specialized agent processing complete, proceeding to collation.")
        return "assemble_collate"  # Corrected target node name


def route_after_collation(state: WorkerGraphState) -> str:
    if state.get("error_message"):
        logger.error(
            f"Routing to save_results due to error during collation: {state['error_message']}"
        )
        return "save_results"
    else:
        logger.info("Collation complete, proceeding to report generation.")
        return "generate_report"


def route_after_report(state: WorkerGraphState) -> str:
    # All paths, including errors during report generation, lead to save_results
    if state.get("error_message"):
        logger.error(
            f"Routing to save_results due to error during report generation (or carried from previous step): {state['error_message']}"
        )
    else:
        logger.info("Report generation complete, proceeding to save results.")
    return "save_results"


# --- Build and Compile the Worker Graph ---
def build_worker_graph() -> Any:
    logger.info(
        "Building worker graph with ContextAnalysisAgent and dynamic specialized agent loading..."
    )
    graph = StateGraph(WorkerGraphState)

    graph.add_node("fetch_code", fetch_code_from_db_node)
    # Renamed node for clarity
    graph.add_node("initial_contextual_analysis", initial_contextual_analysis_node)
    graph.add_node("coordinator_dispatch", coordinator_dispatch_node)
    # Renamed node for clarity
    graph.add_node("run_specialized_agents", run_specialized_agents_node)
    graph.add_node("assemble_collate", assemble_and_collate_node)
    graph.add_node("generate_report", generate_report_node)
    graph.add_node("save_results", save_results_node)

    graph.set_entry_point("fetch_code")

    graph.add_conditional_edges(
        "fetch_code",
        route_after_fetch,
        {
            "initial_contextual_analysis": "initial_contextual_analysis",  # Corrected target
            "save_results": "save_results",
        },
    )
    graph.add_conditional_edges(
        "initial_contextual_analysis",  # From new node
        route_after_initial_contextual_analysis,  # New routing logic
        {
            "coordinator_dispatch": "coordinator_dispatch",  # Corrected target
            "save_results": "save_results",
        },
    )
    graph.add_conditional_edges(
        "coordinator_dispatch",  # Corrected source node name
        route_after_dispatch,
        {
            "run_specialized_agents": "run_specialized_agents",  # Corrected target
            "assemble_collate": "assemble_collate",  # Corrected target
            "save_results": "save_results",
        },
    )
    graph.add_conditional_edges(
        "run_specialized_agents",  # Corrected source node name
        route_after_agents,
        {
            "assemble_collate": "assemble_collate",  # Corrected target
            "save_results": "save_results",
        },
    )
    graph.add_conditional_edges(
        "assemble_collate",  # Corrected source node name
        route_after_collation,
        {
            "generate_report": "generate_report",
            "save_results": "save_results",
        },
    )
    graph.add_conditional_edges(
        "generate_report",
        route_after_report,
        {
            "save_results": "save_results",
        },
    )
    graph.add_edge("save_results", END)

    logger.info("Worker graph built with updated initial analysis stage.")
    compiled_graph_object = graph.compile()
    logger.info("Worker graph compiled.")
    return compiled_graph_object


worker_workflow = build_worker_graph()
