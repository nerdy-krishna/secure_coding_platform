# src/app/graphs/worker_graph.py

import logging
from typing import TypedDict, Dict, Optional, Any, List
import uuid

from langgraph.graph import StateGraph, END

# Agents and services
from app.agents.context_analysis_agent import build_context_analysis_agent_graph
from app.agents.coordinator_agent import build_coordinator_graph
from app.db.database import AsyncSessionLocal # FIX: Import AsyncSessionLocal instead of get_session
from app.db import crud

logger = logging.getLogger(__name__)

# --- Define the master state for the entire worker workflow ---

class WorkerState(TypedDict):
    """
    The complete state for the asynchronous worker graph.
    It accumulates data as the workflow progresses.
    """
    submission_id: uuid.UUID
    llm_config_id: Optional[uuid.UUID]
    files: Optional[Dict[str, str]]
    
    # Output from ContextAnalysisAgent
    repository_map: Optional[Any]
    analysis_summary: Optional[str]
    identified_components: Optional[List[str]]
    asvs_analysis: Optional[Dict[str, Any]]
    
    # State for the CoordinatorAgent
    relevant_agents: Optional[List[str]]
    analysis_results: list
    
    # Error handling
    error_message: Optional[str]


# --- Node Functions for the Worker Graph ---

async def retrieve_submission_data(state: WorkerState) -> Dict[str, Any]:
    """
    Node to fetch the code submission and all its files from the database.
    This is the entry point for the worker graph's logic.
    """
    submission_id = state['submission_id']
    logger.info(f"[WorkerGraph] Retrieving data for submission_id: {submission_id}")
    
    files_map: Dict[str, str] = {}
    
    # FIX: Use AsyncSessionLocal() directly to manage the session
    async with AsyncSessionLocal() as db:
        try:
            # FIX: Use the correct function name 'get_submission'
            submission = await crud.get_submission(db, submission_id)
            if not submission:
                return {"error_message": f"Submission with ID {submission_id} not found."}

            # This now uses the function we added to crud.py
            submitted_files = await crud.get_files_by_submission_id(db, submission_id)
            if not submitted_files:
                return {"error_message": f"No files found for submission ID {submission_id}."}

            for f in submitted_files:
                files_map[f.file_path] = f.content
            
            logger.info(f"[WorkerGraph] Retrieved {len(files_map)} files for submission.")

            return {
                "files": files_map,
                "llm_config_id": submission.llm_config_id,
                "error_message": None
            }
        except Exception as e:
            logger.error(f"[WorkerGraph] Error retrieving data for submission {submission_id}: {e}")
            return {"error_message": str(e)}

def should_continue(state: WorkerState) -> str:
    """
    Conditional edge. Routes to an error handler if the previous step failed.
    """
    if state.get("error_message"):
        logger.warning(f"[WorkerGraph] Error detected. Routing to error handler. Message: {state['error_message']}")
        return "handle_error"
    return "continue"

def handle_error_node(state: WorkerState) -> Dict[str, Any]:
    """
    Node to handle and log errors that occur during the workflow.
    """
    error = state.get("error_message", "An unknown error occurred.")
    submission_id = state['submission_id']
    logger.error(f"[WorkerGraph] Workflow for submission {submission_id} failed: {error}")
    return {}


# --- Build the final, runnable workflow ---

def _build_and_compile_workflow():
    """
    Constructs and compiles the full worker workflow, orchestrating multiple agents.
    """
    logger.debug("Building the main worker workflow graph...")
    
    context_analysis_graph = build_context_analysis_agent_graph()
    coordinator_graph = build_coordinator_graph()

    workflow = StateGraph(WorkerState)

    workflow.add_node("retrieve_submission_data", retrieve_submission_data)
    # FIX: Add # type: ignore to suppress Pylance error for sub-graph nodes
    workflow.add_node("context_analysis", context_analysis_graph) # type: ignore
    workflow.add_node("coordinator", coordinator_graph) # type: ignore
    workflow.add_node("handle_error", handle_error_node)

    workflow.set_entry_point("retrieve_submission_data")
    
    workflow.add_edge("retrieve_submission_data", "context_analysis")

    workflow.add_conditional_edges(
        "context_analysis",
        should_continue,
        {
            "continue": "coordinator",
            "handle_error": "handle_error"
        }
    )

    workflow.add_edge("coordinator", END)
    workflow.add_edge("handle_error", END)
    
    logger.debug("Compiling the main worker graph...")
    return workflow.compile()


# Create the final, runnable graph object
worker_workflow = _build_and_compile_workflow()
logger.info("Main worker workflow graph compiled and ready.")