# src/app/infrastructure/workflows/worker_graph.py

import logging
from typing import TypedDict, Dict, Optional, Any, List
import uuid
import psycopg

from langgraph.graph import StateGraph, END
from langgraph.pregel import Pregel
from langgraph.checkpoint.postgres.aio import AsyncPostgresSaver

from app.infrastructure.agents.context_analysis_agent import build_context_analysis_agent_graph
from app.infrastructure.agents.coordinator_agent import build_coordinator_graph
from app.infrastructure.agents.impact_reporting_agent import build_impact_reporting_agent_graph, ImpactReportingAgentState
from app.core.schemas import WorkflowMode, VulnerabilityFinding, FixResult
from app.infrastructure.database import get_db, AsyncSessionLocal
from app.infrastructure.database import models as db_models
from app.infrastructure.database.repositories.scan_repo import ScanRepository
from app.infrastructure.llm_client import get_llm_client, AgentLLMResult
from pydantic import BaseModel
from app.config.config import settings

logger = logging.getLogger(__name__)

STATUS_PENDING_APPROVAL = "PENDING_COST_APPROVAL"
STATUS_QUEUED = "QUEUED"
STATUS_QUEUED_FOR_SCAN = "QUEUED_FOR_SCAN"
STATUS_REMEDIATION_COMPLETE = "REMEDIATION_COMPLETED"


class WorkerState(TypedDict):
    scan_id: uuid.UUID
    llm_config_id: Optional[uuid.UUID] 
    files: Optional[Dict[str, str]]
    workflow_mode: WorkflowMode
    current_scan_status: Optional[str]
    repository_map: Optional[Any]
    asvs_analysis: Optional[Dict[str, Any]]
    findings: List[VulnerabilityFinding]
    fixes: List[FixResult] 
    # This field will be populated by the patching node
    live_codebase: Optional[Dict[str, str]]
    impact_report: Optional[Dict[str, Any]]
    sarif_report: Optional[Dict[str, Any]]
    error_message: Optional[str]

# --- Pydantic model for patch correction ---
class CorrectedSnippet(BaseModel):
    corrected_original_snippet: str

# --- Graph Nodes ---

async def retrieve_scan_data(state: WorkerState) -> Dict[str, Any]:
    """
    Retrieves the scan files, configuration, and CURRENT STATUS from the database.
    This is the first step for any workflow run.
    """
    scan_id = state['scan_id']
    logger.info(f"Entering node to retrieve data and status for scan.", extra={"scan_id": str(scan_id)})
    
    async with AsyncSessionLocal() as db:
        try:
            repo = ScanRepository(db)
            scan = await repo.get_scan_with_details(scan_id)
            if not scan:
                return {"error_message": f"Scan with ID {scan_id} not found."}

            original_snapshot = next((s for s in scan.snapshots if s.snapshot_type == "ORIGINAL_SUBMISSION"), None)
            if not original_snapshot:
                return {"error_message": f"Original code snapshot not found for scan {scan_id}."}

            file_hashes = list(original_snapshot.file_map.values())
            
            files_map = {}
            if file_hashes:
                hash_to_content_map = await repo.get_source_files_by_hashes(file_hashes)
                files_map = {
                    path: hash_to_content_map.get(file_hash, "")
                    for path, file_hash in original_snapshot.file_map.items()
                }
            
            # For pre-approval, we use the main LLM. For post-approval, the coordinator uses the specialized one.
            llm_id_to_use = scan.main_llm_config_id

            return {
                "files": files_map, 
                "llm_config_id": llm_id_to_use, 
                "workflow_mode": scan.scan_type,
                "current_scan_status": scan.status, # Pass the current status for routing
                "error_message": None,
            }
        except Exception as e:
            logger.error(f"Error retrieving data for scan {scan_id}: {e}", exc_info=True, extra={"scan_id": str(scan_id)})
            return {"error_message": str(e)}

def route_by_status(state: WorkerState) -> str:
    """Routes the workflow based on the scan's current status."""
    status = state.get("current_scan_status")
    scan_id = state.get("scan_id")
    logger.info(f"Routing workflow for scan {scan_id} based on status: {status}")

    if status == STATUS_QUEUED:
        logger.info(f"-> Routing to pre-approval path for scan {scan_id}")
        return "pre_approval_path"
    elif status == STATUS_QUEUED_FOR_SCAN:
        logger.info(f"-> Routing to post-approval path for scan {scan_id}")
        return "post_approval_path"
    else:
        logger.error(f"-> Unknown or invalid status '{status}' for scan {scan_id}. Ending workflow.")
        return "handle_error"

async def patch_and_verify_node(state: WorkerState) -> Dict[str, Any]:
    """
    Verifies and applies code patches for REMEDIATE scans. Includes a retry mechanism.
    """
    scan_id = state['scan_id']
    fixes = state.get('fixes', [])
    original_files = state.get('files', {})
    llm_config_id = state.get('llm_config_id')
    
    if not original_files or not llm_config_id:
        return {"error_message": "Original files or LLM config missing for patching."}

    logger.info(f"Entering Patch & Verify node for scan {scan_id} with {len(fixes)} potential fixes.")
    live_codebase = original_files.copy()
    llm_client = await get_llm_client(llm_config_id)

    if not llm_client:
        return {"error_message": "Could not initialize LLM client for patch retries."}

    for fix in fixes:
        file_path = fix.finding.file_path
        original_snippet = fix.suggestion.original_snippet
        suggested_fix = fix.suggestion.code

        if file_path not in live_codebase:
            logger.warning(f"File '{file_path}' not in codebase, skipping fix.")
            continue

        # Try to apply the fix, with retries
        for attempt in range(4): # 1 initial attempt + 3 retries
            current_file_content = live_codebase[file_path]
            if original_snippet in current_file_content:
                live_codebase[file_path] = current_file_content.replace(original_snippet, suggested_fix, 1)
                logger.info(f"Successfully applied patch for CWE-{fix.finding.cwe} in {file_path}")
                break # Success, exit retry loop
            
            if attempt == 3: # Last attempt failed
                logger.error(f"Final attempt failed to apply patch in {file_path}. Discarding fix.")
                break

            # If not found, and not the last attempt, try to get a correction from the LLM
            logger.warning(f"Snippet not found in {file_path}. Attempting LLM correction (Attempt {attempt + 1}/3).")
            
            correction_prompt = f"""
            The following 'original_snippet' was not found in the 'source_code' provided.
            Please analyze the 'source_code' and the 'suggested_fix' to identify the correct 'original_snippet' that the fix should replace.
            The code may have been slightly modified by a previous fix. Find the logical equivalent of the original snippet.
            Respond ONLY with a JSON object containing the 'corrected_original_snippet'.

            <source_code>
            {current_file_content}
            </source_code>

            <original_snippet>
            {original_snippet}
            </original_snippet>

            <suggested_fix>
            {suggested_fix}
            </suggested_fix>
            """
            
            try:
                correction_result: AgentLLMResult = await llm_client.generate_structured_output(correction_prompt, CorrectedSnippet)
                if isinstance(correction_result.parsed_output, CorrectedSnippet):
                    original_snippet = correction_result.parsed_output.corrected_original_snippet
                    logger.info(f"Received corrected snippet from LLM: '{original_snippet[:50]}...'")
                else:
                    logger.warning("LLM failed to provide a corrected snippet.")
            except Exception as e:
                logger.error(f"Error during LLM patch correction: {e}")

    # After iterating through all fixes, save the remediated code as a new snapshot
    async with AsyncSessionLocal() as db:
        repo = ScanRepository(db)
        await repo.create_code_snapshot(scan_id, live_codebase, "POST_REMEDIATION")
        logger.info(f"Saved post-remediation code snapshot for scan {scan_id}")

    return {"live_codebase": live_codebase}


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
    logger.info("Entering node to save final reports and risk score.", extra={"scan_id": str(scan_id)})

    if not impact_report and not sarif_report:
        logger.warning(f"No reports were found in state for scan.", extra={"scan_id": str(scan_id)})

    risk_score = 0.0
    if findings:
        severity_map = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
        for f in findings:
            sev = f.severity.upper() if f.severity else "LOW"
            if sev in severity_map:
                severity_map[sev] += 1
        
        # Calculate risk score based on the new formula
        if severity_map["CRITICAL"] > 0:
            risk_score = min(10.0, 9.0 + (severity_map["CRITICAL"] * 0.1))
        elif severity_map["HIGH"] > 0:
            risk_score = min(8.9, 7.0 + (severity_map["HIGH"] * 0.1))
        elif severity_map["MEDIUM"] > 0:
            risk_score = min(6.9, 4.0 + (severity_map["MEDIUM"] * 0.1))
        elif severity_map["LOW"] > 0:
            risk_score = min(3.9, 1.0 + (severity_map["LOW"] * 0.1))
    
    final_risk_score = int(round(risk_score, 0))
    
    summary_data = {
        "summary": {
            "total_findings_count": len(findings),
            "files_analyzed_count": len(set(f.file_path for f in findings)),
            "severity_counts": severity_map,
        },
        "overall_risk_score": {
            "score": final_risk_score,
            "severity": "High" # Placeholder
        }
    }
            
    final_status = STATUS_REMEDIATION_COMPLETE if state['workflow_mode'] == 'REMEDIATE' else "COMPLETED"

    async with AsyncSessionLocal() as db:
        repo = ScanRepository(db)
        await repo.save_final_reports_and_status(
            scan_id=scan_id,
            status=final_status,
            impact_report=impact_report,    
            sarif_report=sarif_report,
            summary=summary_data,
            risk_score=final_risk_score
        )
    
    logger.info("Successfully saved final reports and risk score.", extra={"scan_id": str(scan_id)})
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
    # If the coordinator finished and set the status to PENDING_COST_APPROVAL, we should end this run.
    if state.get("current_scan_status") == STATUS_PENDING_APPROVAL:
        return END
    return "continue"

def route_after_coordinator(state: WorkerState) -> str:
    """Routes to patching, reporting, or ends the graph."""
    if state.get("error_message") or state.get("error"):
        return "handle_error"
    
    if state.get("current_scan_status") == STATUS_PENDING_APPROVAL:
        return END # Pause for cost approval
    
    if state.get("workflow_mode") == 'REMEDIATE':
        logger.info(f"Routing scan {state['scan_id']} to patch_and_verify_node.")
        return "patch_and_verify"
    else:
        logger.info(f"Routing scan {state['scan_id']} to run_impact_reporting.")
        return "run_impact_reporting"


# --- Sub-graph and Workflow Definition ---
context_analysis_graph = build_context_analysis_agent_graph()
coordinator_graph = build_coordinator_graph()
impact_reporting_graph = build_impact_reporting_agent_graph()

workflow = StateGraph(WorkerState)

workflow.add_node("retrieve_scan_data", retrieve_scan_data)
workflow.add_node("context_analysis", context_analysis_graph)
workflow.add_node("coordinator", coordinator_graph)
workflow.add_node("patch_and_verify", patch_and_verify_node) # ADDED NODE
workflow.add_node("run_impact_reporting", impact_reporting_graph)
workflow.add_node("save_final_report", save_final_report_node)
workflow.add_node("handle_error", handle_error_node)

workflow.set_entry_point("retrieve_scan_data")

workflow.add_conditional_edges(
    "retrieve_scan_data",
    route_by_status,
    {
        "pre_approval_path": "context_analysis",
        "post_approval_path": "coordinator",
        "handle_error": "handle_error"
    }
)

workflow.add_conditional_edges("context_analysis", should_continue, {
    "continue": "coordinator", "handle_error": "handle_error",
})

# This is the major routing change
workflow.add_conditional_edges(
    "coordinator",
    route_after_coordinator,
    {
        "patch_and_verify": "patch_and_verify",
        "run_impact_reporting": "run_impact_reporting",
        END: END,
        "handle_error": "handle_error",
    }
)

# New edge from the patching node
workflow.add_conditional_edges("patch_and_verify", should_continue, {
    "continue": "run_impact_reporting", "handle_error": "handle_error",
})

workflow.add_conditional_edges("run_impact_reporting", should_continue, {
    "continue": "save_final_report", "handle_error": "handle_error",
})

workflow.add_edge("save_final_report", END)
workflow.add_edge("handle_error", END)

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
    
    _workflow = workflow.compile(checkpointer=checkpointer)
    logger.info("Main worker workflow compiled and ready with PostgreSQL checkpointer.")
    return _workflow

async def close_workflow_resources():
    global _checkpointer_conn
    if _checkpointer_conn and not _checkpointer_conn.closed:
        logger.info("Closing checkpointer database connection.")
        await _checkpointer_conn.close()
        _checkpointer_conn = None