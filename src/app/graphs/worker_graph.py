# src/app/graphs/worker_graph.py
import logging
import json
import datetime
from typing import TypedDict, Dict, Any, Optional, List

from langgraph.graph import StateGraph, END
from sqlalchemy.ext.asyncio import AsyncSession

from src.app.db.database import AsyncSessionLocal
from src.app.db.models import AnalysisResult, SubmittedFile, CodeSubmission # Added SubmittedFile, CodeSubmission
from sqlalchemy.future import select # For querying

logger = logging.getLogger(__name__)

class WorkerGraphState(TypedDict):
    """State for the worker processing graph."""
    submission_id: int
    files_data: Optional[List[Dict[str, Any]]] = None # To store fetched file content
    primary_language: Optional[str] = None
    # We can add more fields here as the worker becomes more complex
    # e.g., analysis_findings, fixed_code, etc.
    final_report: Optional[Dict[str, Any]]
    db_save_status: Optional[str]
    error_message: Optional[str]


async def fetch_submission_data_node(state: WorkerGraphState) -> Dict[str, Any]:
    logger.info(f"Worker Graph: Fetching data for submission_id: {state['submission_id']}")
    submission_id = state['submission_id']
    files_data_list: List[Dict[str, Any]] = []
    primary_language: Optional[str] = None

    try:
        async with AsyncSessionLocal() as session:
            # Fetch primary language from CodeSubmission
            submission_stmt = select(CodeSubmission.primary_language).where(CodeSubmission.id == submission_id)
            submission_result = await session.execute(submission_stmt)
            primary_language = submission_result.scalar_one_or_none()

            # Fetch files
            stmt = select(SubmittedFile.filename, SubmittedFile.content, SubmittedFile.detected_language).where(
                SubmittedFile.submission_id == submission_id
            )
            results = await session.execute(stmt)
            for row in results.all():
                files_data_list.append({
                    "filename": row.filename,
                    "content": row.content,
                    "detected_language": row.detected_language
                })

        if not files_data_list:
            logger.warning(f"No files found for submission_id: {submission_id} in DB.")

        return {
            "files_data": files_data_list, 
            "primary_language": primary_language,
            "error_message": None
        }
    except Exception as e:
        logger.error(f"Error fetching submission data for {submission_id}: {e}", exc_info=True)
        return {"error_message": f"Failed to fetch submission data: {str(e)}", "files_data": []}


async def generate_dummy_report_node(state: WorkerGraphState) -> Dict[str, Any]:
    submission_id = state["submission_id"]
    files_data = state.get("files_data", [])
    logger.info(f"Worker Graph: Generating dummy report for submission_id: {submission_id}")

    num_files = len(files_data) if files_data else 0
    dummy_report = {
        "submission_id": submission_id,
        "analysis_timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "status": "Completed (Dummy Analysis)",
        "summary": f"This is a dummy analysis report for {num_files} file(s). Actual analysis pending.",
        "findings": [
            {
                "file": file_info["filename"] if files_data else "N/A",
                "line": 1,
                "type": "Dummy Finding",
                "severity": "Informational",
                "description": "This is a placeholder finding from the Sprint 1 worker."
            } for file_info in files_data[:1] # Dummy finding for first file if exists
        ] if files_data else [{"type": "Dummy Finding", "description": "No files to analyze."}],
        "recommendations": "Implement actual analysis agents in subsequent sprints."
    }
    return {"final_report": dummy_report, "error_message": state.get("error_message")}


async def save_dummy_result_node(state: WorkerGraphState) -> Dict[str, Any]:
    submission_id = state["submission_id"]
    final_report = state.get("final_report")
    error_so_far = state.get("error_message")
    logger.info(f"Worker Graph: Saving dummy result for submission_id: {submission_id}")

    if error_so_far and not final_report: # If fetching data failed
         final_report = {"error_summary": error_so_far}

    if not final_report:
        logger.error(f"No final report to save for submission_id: {submission_id}")
        return {"db_save_status": "Failed: No report generated", "error_message": error_so_far or "No report generated"}

    async with AsyncSessionLocal() as session:
        async with session.begin():
            try:
                # Check if a result already exists (e.g., from a previous partial run)
                stmt = select(AnalysisResult).where(AnalysisResult.submission_id == submission_id)
                db_result_obj = await session.execute(stmt)
                existing_result: Optional[AnalysisResult] = db_result_obj.scalar_one_or_none()

                if existing_result:
                    logger.info(f"Updating existing AnalysisResult for submission {submission_id}")
                    existing_result.report_content = final_report
                    existing_result.status = "completed_dummy"
                    existing_result.completed_at = datetime.datetime.now(datetime.timezone.utc)
                    existing_result.error_message = error_so_far 
                else:
                    logger.info(f"Creating new AnalysisResult for submission {submission_id}")
                    new_result = AnalysisResult(
                        submission_id=submission_id,
                        report_content=final_report,
                        status="completed_dummy", # Special status for dummy
                        error_message=error_so_far,
                        # original_code_snapshot and fixed_code_snapshot can be populated later
                    )
                    session.add(new_result)

                await session.commit()
                logger.info(f"Successfully saved/updated dummy AnalysisResult for submission_id: {submission_id}")
                return {"db_save_status": "Success", "error_message": error_so_far}
            except Exception as e:
                await session.rollback()
                logger.error(f"Error saving dummy AnalysisResult for {submission_id}: {e}", exc_info=True)
                return {"db_save_status": "Failed", "error_message": error_so_far or f"DB save failed: {str(e)}"}

def build_worker_graph() -> StateGraph:
    workflow = StateGraph(WorkerGraphState)
    workflow.add_node("fetch_submission_data", fetch_submission_data_node)
    workflow.add_node("generate_dummy_report", generate_dummy_report_node)
    workflow.add_node("save_dummy_result", save_dummy_result_node)

    workflow.set_entry_point("fetch_submission_data")
    workflow.add_edge("fetch_submission_data", "generate_dummy_report")
    workflow.add_edge("generate_dummy_report", "save_dummy_result")
    workflow.add_edge("save_dummy_result", END)

    app_graph = workflow.compile()
    logger.info("Basic worker graph compiled.")
    return app_graph

worker_workflow = build_worker_graph()