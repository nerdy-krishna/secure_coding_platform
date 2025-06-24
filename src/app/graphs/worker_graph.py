# src/app/graphs/worker_graph.py

import logging
from typing import TypedDict, Dict, Optional, Any, List
import uuid
import psycopg

from langgraph.graph import StateGraph, END
from langgraph.pregel import Pregel
from langgraph.checkpoint.postgres.aio import AsyncPostgresSaver

from app.agents.context_analysis_agent import build_context_analysis_agent_graph, ContextAnalysisAgentState
from app.agents.coordinator_agent import build_coordinator_graph, CoordinatorState
from app.agents.impact_reporting_agent import build_impact_reporting_agent_graph, ImpactReportingAgentState
from app.agents.schemas import WorkflowMode, VulnerabilityFinding
from app.db.database import get_db
from app.db import crud
from app.core.config import settings

logger = logging.getLogger(__name__)

STATUS_PENDING_APPROVAL = "PENDING_COST_APPROVAL"


# --- UPDATED: WorkerState with corrected report fields ---
class WorkerState(TypedDict):
    submission_id: uuid.UUID
    llm_config_id: Optional[uuid.UUID]
    files: Optional[Dict[str, str]]
    workflow_mode: WorkflowMode
    excluded_files: Optional[List[str]]
    
    # from context_analysis_agent
    repository_map: Optional[Any]
    asvs_analysis: Optional[Dict[str, Any]]
    
    # from coordinator_agent
    findings: List[VulnerabilityFinding]
    
    # from impact_reporting_agent
    impact_report: Optional[Dict[str, Any]]
    sarif_report: Optional[Dict[str, Any]]
    
    # error and routing
    error_message: Optional[str]
    current_submission_status: Optional[str]


# --- Node Functions ---

async def retrieve_submission_data(state: WorkerState) -> Dict[str, Any]:
    submission_id = state['submission_id']
    logger.info(f"[WorkerGraph] Retrieving data for submission_id: {submission_id}")
    
    # Default return in case the async for loop doesn't run or an early exit occurs without a specific error.
    # This ensures a Dict[str, Any] is always returned.
    return_value: Dict[str, Any] = {"error_message": f"Failed to retrieve data for submission {submission_id}."}

    try:
        files_map: Dict[str, str] = {}
        async for db in get_db():
            submission = await crud.get_submission(db, submission_id)
            if not submission:
                return_value = {"error_message": f"Submission with ID {submission_id} not found."}
                break # Exit loop, will return default or this specific error

            submitted_files = await crud.get_submitted_files_for_submission(db, submission_id)
            if not submitted_files:
                return_value = {"error_message": f"No files found for submission ID {submission_id}."}
                break # Exit loop

            for f in submitted_files:
                files_map[f.file_path] = f.content
            
            llm_id_to_use = submission.main_llm_config_id
            if state.get("workflow_mode") == "remediate":
                llm_id_to_use = submission.specialized_llm_config_id

            return_value = {
                "files": files_map, 
                "llm_config_id": llm_id_to_use, 
                "excluded_files": submission.excluded_files, # <-- ADDED
                "error_message": None
            }
            break # Successfully processed, exit loop

        return return_value
    except Exception as e:
        logger.error(f"[WorkerGraph] Error retrieving data for submission {submission_id}: {e}", exc_info=True)
        return {"error_message": str(e)}

# --- NEW: Node to correctly invoke the reporting agent and manage state ---
async def run_impact_reporting(state: WorkerState) -> Dict[str, Any]:
    """Prepares input, runs the reporting agent, and returns its results."""
    logger.info(f"[WorkerGraph] Preparing inputs and running ImpactReportingAgent for {state['submission_id']}.")

    # **FIX 1: Pass the findings from the main state into the sub-graph's input**
    # Ensure all required fields for ImpactReportingAgentState are present.
    reporting_input_state: ImpactReportingAgentState = {
        "submission_id": state["submission_id"],
        "llm_config_id": state["llm_config_id"],
        "findings": state.get("findings", []), # Access top-level findings populated by CoordinatorAgent
        "impact_report": None,  # Initialize as None, will be populated by the agent
        "sarif_report": None,   # Initialize as None, will be populated by the agent
        "error": None,          # Initialize as None
    }

    reporting_graph = build_impact_reporting_agent_graph()
    report_output_state = await reporting_graph.ainvoke(reporting_input_state)

    if report_output_state.get("error"):
        error_msg = f"ImpactReportingAgent sub-graph failed: {report_output_state['error']}"
        logger.error(f"[WorkerGraph] {error_msg}")
        return {"error_message": error_msg}
    
    logger.info("[WorkerGraph] Received successful output from ImpactReportingAgent.")

    # **FIX 2: Extract the reports from the sub-graph's output and return them**
    return {
        "impact_report": report_output_state.get("impact_report"),
        "sarif_report": report_output_state.get("sarif_report"),
    }

# --- UPDATED: save_final_report_node now reads from the corrected state fields ---
async def save_final_report_node(state: WorkerState) -> Dict[str, Any]:
    """Saves the generated reports to the database and marks the submission as 'Completed'."""
    submission_id = state["submission_id"]
    impact_report = state.get("impact_report")
    sarif_report = state.get("sarif_report")
    logger.info(f"[WorkerGraph] Saving final reports for submission {submission_id}")

    if not impact_report and not sarif_report:
        logger.warning(f"[WorkerGraph] No reports were found in state. The submission will be marked 'Completed' without reports.")
    
    async for db in get_db():
        await crud.save_final_reports_and_status(
            db,
            submission_id=submission_id,
            status="Completed",
            impact_report=impact_report,
            sarif_report=sarif_report
        )
    return {}


async def handle_error_node(state: WorkerState) -> Dict[str, Any]:
    """Node to handle and log errors that occur during the workflow."""
    error = state.get("error_message", "An unknown error occurred.")
    submission_id = state['submission_id']
    logger.error(f"[WorkerGraph] Workflow for submission {submission_id} failed: {error}")
    async for db in get_db():
        await crud.update_submission_status(db, submission_id, "Failed")
    return {}

def should_continue(state: WorkerState) -> str:                                                                                                                                                                    
    """Conditional edge to check for errors before continuing.                                                                                                                                                     
    Checks for 'error_message' (from main graph nodes) or 'error' (potentially from sub-graphs).                                                                                                                   
    """                                                                                                                                                                                                            
    if state.get("error_message") or state.get("error"):                                                                                                                                                           
        return "handle_error"                                                                                                                                                                                      
    return "continue"


async def check_approval_status_node(state: WorkerState) -> Dict[str, Any]: # type: ignore
    """Fetches the current submission status from the DB to decide on pausing."""
    submission_id = state['submission_id']
    logger.info(f"[WorkerGraph] Checking approval status for submission {submission_id} after coordinator.")
    
    # Default to an error if DB call fails, to prevent unexpected continuation.
    # The coordinator's output (analysis_results, etc.) is already in the state.
    # We only need to update current_submission_status.
    output_state = {**state.get("analysis_results", {}), "current_submission_status": "UNKNOWN_DB_ERROR"}

    async for db in get_db():
        try:
            submission = await crud.get_submission(db, submission_id)
            if not submission:
                logger.error(f"[WorkerGraph] Submission {submission_id} not found during status check.")
                return {**output_state, "error_message": f"Submission {submission_id} not found.", "current_submission_status": "ERROR_NO_SUBMISSION"}
            
            current_status = submission.status
            logger.info(f"[WorkerGraph] Submission {submission_id} current status from DB: {current_status}.")
            return {**output_state, "current_submission_status": current_status, "error_message": state.get("error_message")} # Preserve existing error
        except Exception as e:
            logger.error(f"[WorkerGraph] DB Error checking status for {submission_id}: {e}", exc_info=True)
            # Preserve existing error message if any, or set a new one
            error_msg = state.get("error_message") or f"DB error checking status: {e}"
            return {**output_state, "error_message": error_msg, "current_submission_status": "ERROR_DB_READ"}

def route_after_coordinator_check(state: WorkerState) -> str:
    """
    Determines if the workflow should pause, handle an error, or proceed to reporting.
    """
    if state.get("error_message"):
        return "handle_error"

    current_status = state.get("current_submission_status")
    submission_id = state['submission_id']

    if current_status == STATUS_PENDING_APPROVAL:
        logger.info(f"[WorkerGraph] Submission {submission_id} is {STATUS_PENDING_APPROVAL}. Pausing worker graph.")
        return END
    
    logger.info(f"[WorkerGraph] Submission {submission_id} status is '{current_status}'. Proceeding to reporting.")
    # **FIX 3: Route directly to the new reporting node**
    return "run_impact_reporting"
# Module-level cache for workflow, checkpointer, and its connection
_workflow: Optional[Pregel] = None
_checkpointer_conn: Optional[psycopg.AsyncConnection] = None # Changed type hint

async def get_workflow() -> Pregel:
    """
    Asynchronously builds the workflow with a persistent checkpointer connection.
    Caches the compiled workflow for reuse.
    """
    global _workflow, _checkpointer_conn
    if _workflow is not None:
        return _workflow

    if not settings.ASYNC_DATABASE_URL:
        raise ValueError("ASYNC_DATABASE_URL must be configured.")

    if _checkpointer_conn is None or _checkpointer_conn.closed: # Changed is_closed() to closed
        logger.info("Creating new psycopg async connection for checkpointer...")
        try:
            # Ensure DSN is suitable for psycopg (e.g., postgresql://...)
            conn_url = settings.ASYNC_DATABASE_URL.replace("postgresql+asyncpg://", "postgresql://")
            _checkpointer_conn = await psycopg.AsyncConnection.connect(conn_url) # Changed to psycopg
        except Exception as e:
            logger.error(f"Failed to create psycopg async connection for checkpointer: {e}", exc_info=True)
            raise

    checkpointer = AsyncPostgresSaver(conn=_checkpointer_conn) # type: ignore

    context_analysis_graph = build_context_analysis_agent_graph()
    coordinator_graph = build_coordinator_graph()
    impact_reporting_graph = build_impact_reporting_agent_graph()

    workflow = StateGraph(WorkerState)

    workflow.add_node("retrieve_submission_data", retrieve_submission_data)
    workflow.add_node("context_analysis", context_analysis_graph.with_config(run_name="ContextAnalysisAgent"))
    workflow.add_node("coordinator", coordinator_graph.with_config(run_name="CoordinatorAgent"))
    workflow.add_node("check_approval_status", check_approval_status_node)
    
    workflow.add_node("run_impact_reporting", run_impact_reporting)
    workflow.add_node("save_final_report", save_final_report_node)
    workflow.add_node("handle_error", handle_error_node)

    workflow.set_entry_point("retrieve_submission_data")
    
    workflow.add_conditional_edges("retrieve_submission_data", should_continue, {"continue": "context_analysis", "handle_error": "handle_error"})
    workflow.add_conditional_edges("context_analysis", should_continue, {"continue": "coordinator", "handle_error": "handle_error"})
    workflow.add_conditional_edges("coordinator", should_continue, {"continue": "check_approval_status", "handle_error": "handle_error"})
    
    # UPDATED: Routing from the status check
    workflow.add_conditional_edges(
        "check_approval_status",
        route_after_coordinator_check,
        {
            "run_impact_reporting": "run_impact_reporting", # Proceed to new node
            END: END,
            "handle_error": "handle_error"
        }
    )
    
    workflow.add_conditional_edges("run_impact_reporting", should_continue, {"continue": "save_final_report", "handle_error": "handle_error"})
    workflow.add_edge("save_final_report", END)
    workflow.add_edge("handle_error", END)
    
    _workflow = workflow.compile(checkpointer=checkpointer)
    logger.info("Main worker workflow compiled and ready with PostgreSQL checkpointer.")
    return _workflow

async def close_workflow_resources():
    """Closes the persistent database connection used by the checkpointer."""
    global _checkpointer_conn
    if _checkpointer_conn and not _checkpointer_conn.closed: # Changed is_closed() to closed
        logger.info("Closing checkpointer database connection.")
        await _checkpointer_conn.close()
        _checkpointer_conn = None
