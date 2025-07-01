# src/app/infrastructure/workflows/worker_graph.py

import logging
from typing import TypedDict, Dict, Optional, Any, List
import uuid
import psycopg

from langgraph.graph import StateGraph, END
from langgraph.pregel import Pregel
from langgraph.checkpoint.postgres.aio import AsyncPostgresSaver

from app.infrastructure.agents.context_analysis_agent import build_context_analysis_agent_graph, ContextAnalysisAgentState
from app.infrastructure.agents.coordinator_agent import build_coordinator_graph, CoordinatorState
from app.infrastructure.agents.impact_reporting_agent import build_impact_reporting_agent_graph, ImpactReportingAgentState
from app.core.schemas import WorkflowMode, VulnerabilityFinding
from app.infrastructure.database import get_db, AsyncSessionLocal
from app.infrastructure.database.repositories.submission_repo import SubmissionRepository
from app.config.config import settings

logger = logging.getLogger(__name__)

STATUS_PENDING_APPROVAL = "PENDING_COST_APPROVAL"


class WorkerState(TypedDict):
    submission_id: uuid.UUID
    llm_config_id: Optional[uuid.UUID]
    files: Optional[Dict[str, str]]
    workflow_mode: WorkflowMode
    excluded_files: Optional[List[str]]
    remediation_categories: Optional[List[str]]
    repository_map: Optional[Any]
    asvs_analysis: Optional[Dict[str, Any]]
    findings: List[VulnerabilityFinding]
    impact_report: Optional[Dict[str, Any]]
    sarif_report: Optional[Dict[str, Any]]
    error_message: Optional[str]
    current_submission_status: Optional[str]


# --- Node Functions ---

async def retrieve_submission_data(state: WorkerState) -> Dict[str, Any]:
    """Retrieves the submission files and configuration from the database."""
    submission_id = state['submission_id']
    logger.info(
        f"Entering node to retrieve data for submission.", 
        extra={"submission_id": str(submission_id)}
    )
    
    async with AsyncSessionLocal() as db:
        try:
            repo = SubmissionRepository(db)
            submission = await repo.get_submission(submission_id)
            if not submission:
                return {"error_message": f"Submission with ID {submission_id} not found."}

            if not submission.files:
                return {"error_message": f"No files found for submission ID {submission_id}."}

            files_map = {file.file_path: file.content for file in submission.files}
            
            workflow_mode = state.get("workflow_mode") or submission.workflow_mode or "audit"
            llm_id_to_use = submission.main_llm_config_id
            if workflow_mode in ["remediate", "audit_and_remediate"]:
                llm_id_to_use = submission.specialized_llm_config_id

            return {
                "files": files_map, 
                "llm_config_id": llm_id_to_use, 
                "excluded_files": submission.excluded_files,
                "workflow_mode": workflow_mode,
                "error_message": None
            }
        except Exception as e:
            logger.error(f"Error retrieving data for submission {submission_id}: {e}", exc_info=True, extra={"submission_id": str(submission_id)})
            return {"error_message": str(e)}

async def run_impact_reporting(state: WorkerState) -> Dict[str, Any]:
    """Invokes the ImpactReportingAgent sub-graph to generate the final reports."""
    submission_id_str = str(state['submission_id'])
    logger.info(f"Entering node to run ImpactReportingAgent.", extra={"submission_id": submission_id_str})
    
    reporting_input_state: ImpactReportingAgentState = {
        "submission_id": state["submission_id"],
        "llm_config_id": state["llm_config_id"],
        "findings": state.get("findings", []),
        "impact_report": None,
        "sarif_report": None,
        "error": None,
    }

    reporting_graph = build_impact_reporting_agent_graph()
    report_output_state = await reporting_graph.ainvoke(reporting_input_state)

    if report_output_state.get("error"):
        error_msg = f"ImpactReportingAgent sub-graph failed: {report_output_state['error']}"
        logger.error(error_msg, extra={"submission_id": submission_id_str})
        return {"error_message": error_msg}
    
    logger.info("Received successful output from ImpactReportingAgent.", extra={"submission_id": submission_id_str})
    return {
        "impact_report": report_output_state.get("impact_report"),
        "sarif_report": report_output_state.get("sarif_report"),
    }

async def save_final_report_node(state: WorkerState) -> Dict[str, Any]:
    """Saves the final reports (impact, SARIF) and risk score to the database."""
    submission_id = state["submission_id"]
    impact_report = state.get("impact_report")
    sarif_report = state.get("sarif_report")
    findings = state.get("findings", [])
    logger.info("Entering node to save final reports.", extra={"submission_id": str(submission_id)})

    if not impact_report and not sarif_report:
        logger.warning(f"No reports were found in state for submission.", extra={"submission_id": str(submission_id)})

    # Calculate risk score
    risk_score = 0
    for finding in findings:
        severity = finding.severity.upper()
        if severity == "CRITICAL":
            risk_score += 10
        elif severity == "HIGH":
            risk_score += 5
        elif severity == "MEDIUM":
            risk_score += 2
        elif severity == "LOW":
            risk_score += 1
            
    async with AsyncSessionLocal() as db:
        repo = SubmissionRepository(db)
        await repo.save_final_reports_and_status(
            submission_id=submission_id,
            status="Completed",
            impact_report=impact_report,
            sarif_report=sarif_report,
            risk_score=risk_score
        )
        logger.info("Successfully saved final reports and set status to 'Completed'.", extra={"submission_id": str(submission_id)})
    return {}


async def handle_error_node(state: WorkerState) -> Dict[str, Any]:
    """A terminal node to handle any errors that occurred during the workflow."""
    error = state.get("error_message", "An unknown error occurred.")
    submission_id = state['submission_id']
    logger.error(f"Workflow for submission failed: {error}", extra={"submission_id": str(submission_id), "error_message": error})
    async with AsyncSessionLocal() as db:
        repo = SubmissionRepository(db)
        await repo.update_status(submission_id, "Failed")
    return {}

def should_continue(state: WorkerState) -> str:
    if state.get("error_message") or state.get("error"):
        return "handle_error"
    return "continue"


async def check_approval_status_node(state: WorkerState) -> Dict[str, Any]:
    submission_id = state['submission_id']
    logger.info(f"[WorkerGraph] Checking approval status for submission {submission_id} after coordinator.")
    
    output_state = {**state, "current_submission_status": "UNKNOWN_DB_ERROR"}

    async with AsyncSessionLocal() as db:
        try:
            repo = SubmissionRepository(db)
            submission = await repo.get_submission(submission_id)
            if not submission:
                return {**output_state, "error_message": f"Submission {submission_id} not found."}
            
            output_state["current_submission_status"] = submission.status
            logger.info(f"[WorkerGraph] Submission {submission_id} current status from DB: {submission.status}.")
            return output_state
        except Exception as e:
            logger.error(f"[WorkerGraph] DB Error checking status for {submission_id}: {e}", exc_info=True)
            error_msg = state.get("error_message") or f"DB error checking status: {e}"
            return {**output_state, "error_message": error_msg, "current_submission_status": "ERROR_DB_READ"}

def route_after_coordinator_check(state: WorkerState) -> str:
    if state.get("error_message"):
        return "handle_error"
    current_status = state.get("current_submission_status")
    submission_id = state['submission_id']
    if current_status == STATUS_PENDING_APPROVAL:
        logger.info(f"[WorkerGraph] Submission {submission_id} is {STATUS_PENDING_APPROVAL}. Pausing worker graph.")
        return END
    
    logger.info(f"[WorkerGraph] Submission {submission_id} status is '{current_status}'. Proceeding to reporting.")
    return "run_impact_reporting"

_workflow: Optional[Pregel] = None
_checkpointer_conn: Optional[psycopg.AsyncConnection] = None

async def get_workflow() -> Pregel:
    global _workflow, _checkpointer_conn
    if _workflow is not None:
        return _workflow

    if not settings.ASYNC_DATABASE_URL:
        raise ValueError("ASYNC_DATABASE_URL must be configured.")

    if _checkpointer_conn is None or _checkpointer_conn.closed:
        logger.info("Creating new psycopg async connection for checkpointer...")
        try:
            conn_url = settings.ASYNC_DATABASE_URL.replace("postgresql+asyncpg://", "postgresql://")
            _checkpointer_conn = await psycopg.AsyncConnection.connect(conn_url)
        except Exception as e:
            logger.error(f"Failed to create psycopg async connection for checkpointer: {e}", exc_info=True)
            raise

    checkpointer = AsyncPostgresSaver(conn=_checkpointer_conn)  # type: ignore

    context_analysis_graph = build_context_analysis_agent_graph()
    coordinator_graph = build_coordinator_graph()
    
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
    
    workflow.add_conditional_edges(
        "check_approval_status",
        route_after_coordinator_check,
        {"run_impact_reporting": "run_impact_reporting", END: END, "handle_error": "handle_error"}
    )
    
    workflow.add_conditional_edges("run_impact_reporting", should_continue, {"continue": "save_final_report", "handle_error": "handle_error"})
    workflow.add_edge("save_final_report", END)
    workflow.add_edge("handle_error", END)
    
    _workflow = workflow.compile(checkpointer=checkpointer)
    logger.info("Main worker workflow compiled and ready with PostgreSQL checkpointer.")
    return _workflow

async def close_workflow_resources():
    global _checkpointer_conn
    if _checkpointer_conn and not _checkpointer_conn.closed:
        logger.info("Closing checkpointer database connection.")
        await _checkpointer_conn.close()
        _checkpointer_conn = None