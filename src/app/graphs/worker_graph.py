# src/app/graphs/worker_graph.py

import logging
from typing import TypedDict, Dict, Optional, Any, List
import uuid
import psycopg # Changed from asyncpg

from langgraph.graph import StateGraph, END
from langgraph.pregel import Pregel
from langgraph.checkpoint.postgres.aio import AsyncPostgresSaver

from app.agents.context_analysis_agent import build_context_analysis_agent_graph
from app.agents.coordinator_agent import build_coordinator_graph
from app.agents.impact_reporting_agent import build_impact_reporting_agent_graph
from app.agents.schemas import WorkflowMode, VulnerabilityFinding, FinalReport
from app.db.database import get_db
from app.db import crud
from app.core.config import settings

logger = logging.getLogger(__name__)

# Define status constants for clarity, matching those in coordinator or API
STATUS_PENDING_APPROVAL = "PENDING_COST_APPROVAL"
# STATUS_COST_APPROVED = "COST_APPROVED" # Not strictly needed here if routing logic is robust

class WorkerState(TypedDict):
    submission_id: uuid.UUID
    llm_config_id: Optional[uuid.UUID]
    files: Optional[Dict[str, str]]
    workflow_mode: WorkflowMode
    repository_map: Optional[Any]
    asvs_analysis: Optional[Dict[str, Any]]
    analysis_results: Dict[str, Any]
    findings: List[VulnerabilityFinding]
    final_report: Optional[FinalReport]
    error_message: Optional[str]
    current_submission_status: Optional[str] = None # To store status for routing

# --- Node Functions for the Worker Graph ---

async def retrieve_submission_data(state: WorkerState) -> Dict[str, Any]: # type: ignore
    """Node to fetch the code submission and all its files from the database."""
    submission_id = state['submission_id']
    logger.info(f"[WorkerGraph] Retrieving data for submission_id: {submission_id}")
    
    # FIX: Wrap the entire logic in a try/except to guarantee a return value
    try:
        files_map: Dict[str, str] = {}
        async for db in get_db():
            submission = await crud.get_submission(db, submission_id)
            if not submission:
                return {"error_message": f"Submission with ID {submission_id} not found."}

            submitted_files = await crud.get_submitted_files_for_submission(db, submission_id)
            if not submitted_files:
                return {"error_message": f"No files found for submission ID {submission_id}."}

            for f in submitted_files:
                files_map[f.file_path] = f.content
            
            llm_id_to_use = submission.main_llm_config_id
            if state.get("workflow_mode") == "remediate":
                llm_id_to_use = submission.specialized_llm_config_id

            return {
                "files": files_map,
                "llm_config_id": llm_id_to_use,
                "error_message": None
            }
    except Exception as e:
        logger.error(f"[WorkerGraph] Error retrieving data for submission {submission_id}: {e}", exc_info=True)
        return {"error_message": str(e)}

def prepare_report_input(state: WorkerState) -> Dict[str, Any]:
    """Prepares the input for the ImpactReportingAgent by extracting findings."""
    logger.info("[WorkerGraph] Preparing inputs for impact report generation.")
    findings = state.get("analysis_results", {}).get("findings", [])
    return {"findings": findings}

async def save_final_report_node(state: WorkerState) -> Dict[str, Any]:
    """Saves the generated reports to the database and marks the submission as 'Completed'."""
    submission_id = state["submission_id"]
    final_report = state.get("final_report")
    logger.info(f"[WorkerGraph] Saving final reports for submission {submission_id}")

    # Use a default status and update it based on the presence of a report
    final_status = "Completed"
    report_data = {}
    if not final_report:
        logger.warning(f"[WorkerGraph] No final report generated for submission {submission_id}.")
    else:
        report_data["impact_report"] = final_report.impact_analysis.model_dump()
        report_data["sarif_report"] = final_report.sarif_report
        logger.info(f"[WorkerGraph] Final reports prepared for saving for submission {submission_id}.")

    async for db in get_db():
        await crud.save_final_reports_and_status(
            db,
            submission_id=submission_id,
            status=final_status,
            **report_data
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
    """Conditional edge to check for errors before continuing."""
    return "handle_error" if state.get("error_message") else "continue"


async def check_approval_status_node(state: WorkerState) -> Dict[str, Any]:
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
    """Determines if the main workflow should pause or continue based on DB status."""
    # Prioritize errors from check_approval_status_node or earlier
    if state.get("error_message"):
        # Check if the error is specifically from the status check itself
        if state.get("current_submission_status") in ["ERROR_NO_SUBMISSION", "ERROR_DB_READ", "UNKNOWN_DB_ERROR"]:
             logger.error(f"[WorkerGraph] Error during status check for {state['submission_id']}: {state['error_message']}. Routing to handle_error.")
        else: # Error from coordinator or earlier steps
            logger.error(f"[WorkerGraph] Error message present before status check for {state['submission_id']}: {state['error_message']}. Routing to handle_error.")
        return "handle_error"

    current_status = state.get("current_submission_status")
    submission_id = state['submission_id']

    if current_status == STATUS_PENDING_APPROVAL:
        logger.info(f"[WorkerGraph] Submission {submission_id} is {STATUS_PENDING_APPROVAL}. Pausing worker graph.")
        return END # Actual pause of the worker graph.
    
    # If status is not PENDING_COST_APPROVAL (e.g., COST_APPROVED, or any other state implying continuation)
    logger.info(f"[WorkerGraph] Submission {submission_id} status is '{current_status}'. Proceeding to reporting.")
    return "prepare_report_input"
    

# --- NEW: Robust Async Factory with Manual Connection Management ---

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
    workflow.add_node("context_analysis", context_analysis_graph)
    workflow.add_node("coordinator", coordinator_graph) # Coordinator sub-graph
    workflow.add_node("check_approval_status", check_approval_status_node) # New node
    workflow.add_node("prepare_report_input", prepare_report_input)
    workflow.add_node("impact_reporting", impact_reporting_graph)
    workflow.add_node("save_final_report", save_final_report_node)
    workflow.add_node("handle_error", handle_error_node)

    workflow.set_entry_point("retrieve_submission_data")
    workflow.add_conditional_edges("retrieve_submission_data", should_continue, {"continue": "context_analysis", "handle_error": "handle_error"})
    workflow.add_conditional_edges("context_analysis", should_continue, {"continue": "coordinator", "handle_error": "handle_error"})
    
    # After coordinator, always go to check_approval_status. Errors from coordinator are handled by 'should_continue'.
    workflow.add_conditional_edges(
        "coordinator", 
        should_continue, # Checks for errors from the coordinator sub-graph
        {
            "continue": "check_approval_status", # If coordinator finished without error
            "handle_error": "handle_error"
        }
    )

    # New routing after checking the DB status
    workflow.add_conditional_edges(
        "check_approval_status",
        route_after_coordinator_check,
        {
            "prepare_report_input": "prepare_report_input",
            END: END,  # This is the actual pause point
            "handle_error": "handle_error" # If status check itself failed
        }
    )
    
    workflow.add_edge("prepare_report_input", "impact_reporting")
    workflow.add_conditional_edges("impact_reporting", should_continue, {"continue": "save_final_report", "handle_error": "handle_error"})
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
