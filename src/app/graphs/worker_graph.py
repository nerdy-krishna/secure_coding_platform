# src/app/graphs/worker_graph.py

import logging
from typing import TypedDict, Dict, Optional, Any, List
import uuid
from datetime import datetime

from langgraph.graph import StateGraph, END
from sqlalchemy import create_engine, update

# Agents and services
from app.agents.context_analysis_agent import build_context_analysis_agent_graph
from app.agents.coordinator_agent import build_coordinator_graph
from app.agents.impact_reporting_agent import build_impact_reporting_agent_graph
# UPDATED: Import FinalReport from schemas
from app.agents.schemas import WorkflowMode, VulnerabilityFinding, FinalReport
from app.db.database import get_db
from app.db import crud, models as db_models
from langgraph.checkpoint.sqlite import AioSqliteSaver
from sqlalchemy.ext.asyncio import create_async_engine
from app.core.config import settings

logger = logging.getLogger(__name__)

# --- Updated master state for the entire worker workflow ---

class WorkerState(TypedDict):
    """
    The complete state for the asynchronous worker graph.
    """
    submission_id: uuid.UUID
    llm_config_id: Optional[uuid.UUID]
    files: Optional[Dict[str, str]]
    workflow_mode: WorkflowMode
    
    # Context Analysis Outputs
    repository_map: Optional[Any]
    asvs_analysis: Optional[Dict[str, Any]]
    
    # Coordinator Agent Outputs
    analysis_results: Dict[str, Any]
    
    # Impact Reporting Agent Inputs/Outputs
    findings: List[VulnerabilityFinding]
    final_report: Optional[FinalReport]

    # Error handling
    error_message: Optional[str]


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

# --- Build the final, runnable workflow ---

def _build_and_compile_workflow():
    """Constructs and compiles the full worker workflow with a database checkpointer."""
    logger.debug("Building the main worker workflow graph...")
    
    # --- Checkpointer Setup ---
    # FIX: Add a check to ensure the database URL is configured
    if not settings.ASYNC_DATABASE_URL:
        raise ValueError("ASYNC_DATABASE_URL must be configured in settings to use a checkpointer.")

    # AioSqliteSaver works with any async SQLAlchemy engine, including PostgreSQL
    engine = create_async_engine(settings.ASYNC_DATABASE_URL)
    checkpointer = AioSqliteSaver(conn=engine)
    
    context_analysis_graph = build_context_analysis_agent_graph()
    coordinator_graph = build_coordinator_graph()
    impact_reporting_graph = build_impact_reporting_agent_graph()

    workflow = StateGraph(WorkerState)

    workflow.add_node("retrieve_submission_data", retrieve_submission_data)
    workflow.add_node("context_analysis", context_analysis_graph) # type: ignore
    workflow.add_node("coordinator", coordinator_graph) # type: ignore
    workflow.add_node("prepare_report_input", prepare_report_input)
    workflow.add_node("impact_reporting", impact_reporting_graph) # type: ignore
    workflow.add_node("save_final_report", save_final_report_node)
    workflow.add_node("handle_error", handle_error_node)

    workflow.set_entry_point("retrieve_submission_data")
    
    workflow.add_conditional_edges("retrieve_submission_data", should_continue, {"continue": "context_analysis", "handle_error": "handle_error"})
    workflow.add_conditional_edges("context_analysis", should_continue, {"continue": "coordinator", "handle_error": "handle_error"})
    workflow.add_conditional_edges("coordinator", should_continue, {"continue": "prepare_report_input", "handle_error": "handle_error"})
    workflow.add_edge("prepare_report_input", "impact_reporting")
    workflow.add_conditional_edges("impact_reporting", should_continue, {"continue": "save_final_report", "handle_error": "handle_error"})
    workflow.add_edge("save_final_report", END)
    workflow.add_edge("handle_error", END)
    
    logger.debug("Compiling the main worker graph with checkpointer...")
    # Compile the graph with the checkpointer
    return workflow.compile(checkpointer=checkpointer)



# Create the final, runnable graph object
worker_workflow = _build_and_compile_workflow()
logger.info("Main worker workflow graph compiled and ready.")
