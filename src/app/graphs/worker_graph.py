# src/app/graphs/worker_graph.py
import logging
from typing import TypedDict, Dict, Optional, Any

from app.agents.coordinator_agent import (
    build_coordinator_graph,
    CoordinatorState,  # Corrected: Was CoordinatorAgentState
)

logger = logging.getLogger(__name__)


class WorkerGraphState(TypedDict):
    """Overall state for the worker graph, encapsulating the entire process."""

    submission_id: int
    result: Optional[Dict]
    error: Optional[str]


async def run_analysis_workflow(state: WorkerGraphState) -> Dict[str, Any]:
    """
    This is the entry node for the main analysis workflow, managed by the Coordinator Agent.
    """
    submission_id = state["submission_id"]
    logger.info(f"Worker graph starting analysis for submission_id: {submission_id}")

    try:
        # Get the compiled coordinator graph
        coordinator_graph = build_coordinator_graph()

        # Define the initial state for the coordinator graph
        # This is where the process for a single submission begins.
        initial_state: CoordinatorState = {
            "submission_id": submission_id,
            "submission": None,
            "code_snippets_and_paths": [],
            "relevant_agents": {},
            "results": {},
            "error": None,
        }

        # Asynchronously invoke the coordinator graph to run the full analysis
        final_state = await coordinator_graph.ainvoke(initial_state)

        if final_state.get("error"):
            logger.error(
                f"Analysis for submission {submission_id} completed with an error: {final_state['error']}"
            )
            return {"result": None, "error": final_state["error"]}

        logger.info(f"Analysis for submission {submission_id} completed successfully.")
        return {"result": final_state.get("results", {}), "error": None}

    except Exception as e:
        logger.critical(
            f"A critical error occurred in the analysis workflow for submission {submission_id}: {e}",
            exc_info=True,
        )
        return {"result": None, "error": str(e)}


# The worker_workflow is a placeholder for the full graph definition.
# For now, we are directly calling the main analysis function.
# In a more complex scenario, you might build a StateGraph here as well.
worker_workflow = run_analysis_workflow
