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
from app.infrastructure.database.repositories.scan_repo import ScanRepository
from app.config.config import settings

logger = logging.getLogger(__name__)

STATUS_PENDING_APPROVAL = "PENDING_COST_APPROVAL"


class WorkerState(TypedDict):
    scan_id: uuid.UUID
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
    current_scan_status: Optional[str]


async def retrieve_scan_data(state: WorkerState) -> Dict[str, Any]:
    """Retrieves the scan files and configuration from the database."""
    scan_id = state['scan_id']
    logger.info(
        f"Entering node to retrieve data for scan.", 
        extra={"scan_id": str(scan_id)}
    )
   
    async with AsyncSessionLocal() as db:
        try:
            repo = ScanRepository(db)
            scan = await repo.get_scan_with_details(scan_id)
            if not scan:
                return {"error_message": f"Scan with ID {scan_id} not found."}

            # Find the original submission snapshot
            original_snapshot = next((s for s in scan.snapshots if s.snapshot_type == "ORIGINAL_SUBMISSION"), None)
            if not original_snapshot:
                return {"error_message": f"Original code snapshot not found for scan {scan_id}."}

            # Get the file hashes from the snapshot's file_map
            file_hashes = list(original_snapshot.file_map.values())
            if not file_hashes:
                 return {"files": {}, "llm_config_id": scan.main_llm_config_id, "workflow_mode": scan.scan_type, "error_message": None}

            # Retrieve the content for all files in one DB call
            hash_to_content_map = await repo.get_source_files_by_hashes(file_hashes)

            # Reconstruct the files dictionary {path: content}
            files_map = {
                path: hash_to_content_map.get(file_hash, "")
                for path, file_hash in original_snapshot.file_map.items()
            }
            
            # The coordinator will need both LLM configs, but for now we pass the main one
            # for the initial context analysis step.
            llm_id_to_use = scan.main_llm_config_id

            return {
                "files": files_map, 
                "llm_config_id": llm_id_to_use, 
                "workflow_mode": scan.scan_type,
                "error_message": None,
                "excluded_files": [], # This is now handled by the frontend for uploads
            }
        except Exception as e:
            logger.error(f"Error retrieving data for scan {scan_id}: {e}", exc_info=True, extra={"scan_id": str(scan_id)})
            return {"error_message": str(e)}


async def run_impact_reporting(state: WorkerState) -> Dict[str, Any]:
    """Invokes the ImpactReportingAgent sub-graph to generate the final reports."""
    scan_id_str = str(state['scan_id'])
    logger.info(f"Entering node to run ImpactReportingAgent.", extra={"scan_id": scan_id_str})
    
    reporting_input_state: ImpactReportingAgentState = {
        "scan_id": state["scan_id"],
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
        logger.error(error_msg, extra={"scan_id": scan_id_str})
        return {"error_message": error_msg}
    
    logger.info("Received successful output from ImpactReportingAgent.", extra={"scan_id": scan_id_str})
    return {
        "impact_report": report_output_state.get("impact_report"),
        "sarif_report": report_output_state.get("sarif_report"),
    }

async def save_final_report_node(state: WorkerState) -> Dict[str, Any]:
    """Saves the final reports (impact, SARIF) and risk score to the database."""
    scan_id = state["scan_id"]
    impact_report = state.get("impact_report")
    sarif_report = state.get("sarif_report")
    findings = state.get("findings", [])
    logger.info("Entering node to save final reports.", extra={"scan_id": str(scan_id)})

    if not impact_report and not sarif_report:
        logger.warning(f"No reports were found in state for scan.", extra={"scan_id": str(scan_id)})

    risk_score = 0
    if findings:
        severity_map = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
        for f in findings:
            sev = f.severity.upper()
            if sev in severity_map:
                severity_map[sev] += 1
        
        if severity_map["CRITICAL"] > 0:
            base_score = 9.0
            risk_score = min(10.0, base_score + (severity_map["CRITICAL"] * 0.1))
        elif severity_map["HIGH"] > 0:
            base_score = 7.0
            risk_score = min(8.9, base_score + (severity_map["HIGH"] * 0.1))
        elif severity_map["MEDIUM"] > 0:
            base_score = 4.0
            risk_score = min(6.9, base_score + (severity_map["MEDIUM"] * 0.1))
        elif severity_map["LOW"] > 0:
            base_score = 1.0
            risk_score = min(3.9, base_score + (severity_map["LOW"] * 0.1))
    
    final_risk_score = int(round(risk_score, 0))
    
    # Build a more complete summary object to save to the database
    summary_data = {
        "summary": {
            "total_findings_count": len(findings),
            "files_analyzed_count": len(set(f.file_path for f in findings)),
            "severity_counts": severity_map,
        },
        "overall_risk_score": {
            "score": final_risk_score,
            "severity": "High" # Placeholder, this could be calculated more granularly
        }
    }
            
    async with AsyncSessionLocal() as db:
        repo = ScanRepository(db)
        await repo.save_final_reports_and_status(
            scan_id=scan_id,
            status="COMPLETED",
            impact_report=impact_report,
            sarif_report=sarif_report,
            summary=summary_data,
            risk_score=final_risk_score
        )
    
    logger.info("Successfully saved final reports and set status to 'Completed'.", extra={"scan_id": str(scan_id)})
    return {}


async def handle_error_node(state: WorkerState) -> Dict[str, Any]:
    """A terminal node to handle any errors that occurred during the workflow."""
    error = state.get("error_message", "An unknown error occurred.")
    scan_id = state['scan_id']
    logger.error(f"Workflow for scan failed: {error}", extra={"scan_id": str(scan_id), "error_message": error})
    async with AsyncSessionLocal() as db:
        repo = ScanRepository(db)
        await repo.update_status(scan_id, "Failed")
    return {}

def should_continue(state: WorkerState) -> str:
    if state.get("error_message") or state.get("error"):
        return "handle_error"
    return "continue"


async def check_approval_status_node(state: WorkerState) -> Dict[str, Any]:
    scan_id = state['scan_id']
    logger.info(f"[WorkerGraph] Checking approval status for scan {scan_id} after coordinator.")
    
    output_state = {**state, "current_scan_status": "UNKNOWN_DB_ERROR"}

    async with AsyncSessionLocal() as db:
        try:
            repo = ScanRepository(db)
            scan = await repo.get_scan(scan_id)
            if not scan:
                return {**output_state, "error_message": f"Scan {scan_id} not found."}
            
            output_state["current_scan_status"] = scan.status
            logger.info(f"[WorkerGraph] Scan {scan_id} current status from DB: {scan.status}.")
            return output_state
        except Exception as e:
            logger.error(f"[WorkerGraph] DB Error checking status for {scan_id}: {e}", exc_info=True)
            error_msg = state.get("error_message") or f"DB error checking status: {e}"
            return {**output_state, "error_message": error_msg, "current_scan_status": "ERROR_DB_READ"}

def route_after_coordinator_check(state: WorkerState) -> str:
    if state.get("error_message"):
        return "handle_error"
    
    current_status = state.get("current_scan_status")
    scan_id = state['scan_id']
    if current_status == STATUS_PENDING_APPROVAL:
        logger.info(f"[WorkerGraph] Scan {scan_id} is {STATUS_PENDING_APPROVAL}. Pausing worker graph.")
        return END
    
    logger.info(f"[WorkerGraph] Scan {scan_id} status is '{current_status}'. Proceeding to reporting.")
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

    checkpointer = AsyncPostgresSaver(conn=_checkpointer_conn) # type: ignore

    context_analysis_graph = build_context_analysis_agent_graph()
    coordinator_graph = build_coordinator_graph()
    
    workflow = StateGraph(WorkerState)

    workflow.add_node("retrieve_scan_data", retrieve_scan_data)
    workflow.add_node("context_analysis", context_analysis_graph.with_config(run_name="ContextAnalysisAgent"))
    workflow.add_node("coordinator", coordinator_graph.with_config(run_name="CoordinatorAgent"))
    workflow.add_node("check_approval_status", check_approval_status_node)
    workflow.add_node("run_impact_reporting", run_impact_reporting)
    workflow.add_node("save_final_report", save_final_report_node)
    workflow.add_node("handle_error", handle_error_node)

    workflow.set_entry_point("retrieve_scan_data")
    workflow.add_conditional_edges("retrieve_scan_data", should_continue, {"continue": "context_analysis", "handle_error": "handle_error"})
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