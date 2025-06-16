import logging
from app.agents.coordinator_agent import build_coordinator_graph

logger = logging.getLogger(__name__)

def _build_and_compile_workflow():
    """
    An internal function to construct and compile the graph.
    """
    logger.debug("Building the coordinator graph for the worker...")
    
    # 1. Get the uncompiled graph definition
    graph = build_coordinator_graph()
    
    # 2. Set the entry point specifically for this worker workflow
    graph.set_entry_point("retrieve_submission")
    
    logger.debug("Compiling the worker graph...")
    # 3. Now, compile the graph to make it a runnable object
    return graph.compile()


# Create the final, runnable graph object by calling our builder function.
worker_workflow = _build_and_compile_workflow()

logger.info("Worker workflow graph compiled and ready.")