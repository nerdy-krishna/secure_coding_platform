import logging
from typing import TypedDict, List, Dict, Any, Optional
from uuid import UUID

from langchain_core.pydantic_v1 import BaseModel, Field
from langgraph.graph import StateGraph, END
from sqlalchemy.ext.asyncio import AsyncSession

from src.app.db.crud import save_llm_interaction
from src.app.db.database import get_session
from src.app.llm.llm_client import get_llm_client
from src.app.llm.providers import LLMResult

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# --- Pydantic Models for Structured Output ---

class DispatchTask(BaseModel):
    file_path: str = Field(description="The path to the file to be analyzed.")
    relevant_code_snippet: str = Field(description="The specific snippet of code that needs analysis. Can be the entire file content if necessary.")
    target_agent: str = Field(description="The specialized agent to which this task should be dispatched (e.g., 'AuthenticationAgent', 'AccessControlAgent').")
    task_context: str = Field(description="The reason or context for dispatching to this agent, based on the initial analysis.")

class DispatchPlan(BaseModel):
    tasks: List[DispatchTask] = Field(description="A list of dispatch tasks for specialized security agents.")

# --- Agent State ---

class CoordinatorAgentState(TypedDict):
    submission_id: UUID
    initial_analysis_results: List[Dict[str, Any]]
    files_data: Dict[str, str]
    dispatch_tasks: Optional[List[Dict[str, Any]]]
    error: Optional[str]

# --- Agent Nodes ---

async def create_dispatch_plan(state: CoordinatorAgentState) -> CoordinatorAgentState:
    """
    Creates a dispatch plan based on the initial analysis results from the ContextAnalysisAgent.
    """
    logger.info("CoordinatorAgent: Creating dispatch plan.")
    llm_client = get_llm_client()
    
    # Consolidate context from all files for the LLM
    consolidated_context = ""
    for result in state["initial_analysis_results"]:
        file_path = result.get('file_path')
        analysis = result.get('analysis_result', {})
        summary = analysis.get('summary', 'No summary available.')
        domains = [d.get('domain') for d in analysis.get('security_domains', [])]
        consolidated_context += f"File: {file_path}\nSummary: {summary}\nIdentified Security Domains: {', '.join(domains)}\n\n"

    prompt_template = """
    You are an expert security project manager. Your role is to create a detailed dispatch plan for a team of specialized security agents.
    Based on the provided initial analysis, which includes summaries and relevant security domains for multiple code files, create a list of specific tasks.
    For each identified security domain in each file, create a task for the corresponding specialized agent.

    **Specialized Agents Available:**
    - ArchitectureAgent (V1)
    - AuthenticationAgent (V2)
    - SessionManagementAgent (V3)
    - AccessControlAgent (V4)
    - ValidationAgent (V5)
    - CryptographyAgent (V6)
    - ErrorHandlingAgent (V7)
    - DataProtectionAgent (V8)
    - CommunicationAgent (V9)
    - CodeIntegrityAgent (V10)
    - BusinessLogicAgent (V11)
    - FileHandlingAgent (V12)
    - APISecurityAgent (V13)
    - ConfigurationAgent (V14)

    **Initial Analysis Context:**
    ---
    {consolidated_context}
    ---

    **Instructions:**
    - For each file and each of its identified security domains, create one dispatch task.
    - The `target_agent` must be one of the agents from the list above (e.g., if domain is 'Authentication', use 'AuthenticationAgent').
    - The `relevant_code_snippet` should be the full content of the file.
    - The `task_context` should explain why the task is being assigned (e.g., "Initial analysis identified potential authentication logic.").
    - If no relevant domains are identified for a file, do not create tasks for it.

    Respond with a JSON object that strictly adheres to the provided schema for the dispatch plan.
    """
    
    prompt = prompt_template.format(consolidated_context=consolidated_context)
    
    db: AsyncSession = await get_session().__anext__()
    try:
        # Pass the full content of each file to the prompt
        all_file_contents = "\n--- FILE START ---\n".join(
            f"// File: {path}\n\n{content}" for path, content in state["files_data"].items()
        )

        llm_result: LLMResult = await llm_client.generate_structured_output(prompt, DispatchPlan)

        # Correctly save the full LLM interaction result
        interaction_context = {"operation": "Create Dispatch Plan"}
        await save_llm_interaction(
            db=db,
            result=llm_result,
            submission_id=state["submission_id"],
            agent_name="CoordinatorAgent",
            interaction_context=interaction_context
        )

        if llm_result.error:
            logger.error(f"CoordinatorAgent LLM call failed: {llm_result.error}")
            return {**state, "error": llm_result.error}

        parsed_output = llm_result.parsed_output
        if not parsed_output:
            logger.error("CoordinatorAgent failed to parse LLM output.")
            return {**state, "error": "Failed to parse LLM output."}

        # Replace code snippet placeholder with actual file content for each task
        tasks = parsed_output.dict().get("tasks", [])
        for task in tasks:
            file_path = task.get("file_path")
            if file_path and file_path in state["files_data"]:
                task["relevant_code_snippet"] = state["files_data"][file_path]

        logger.info(f"CoordinatorAgent created a dispatch plan with {len(tasks)} tasks.")
        return {**state, "dispatch_tasks": tasks}

    except Exception as e:
        logger.exception(f"An unexpected error occurred in CoordinatorAgent: {e}")
        return {**state, "error": str(e)}
    finally:
        await db.close()

# --- Graph Builder ---

def build_coordinator_agent_graph():
    """
    Builds the LangGraph workflow for the Coordinator Agent.
    """
    workflow = StateGraph(CoordinatorAgentState)
    workflow.add_node("create_dispatch_plan", create_dispatch_plan)
    workflow.set_entry_point("create_dispatch_plan")
    workflow.add_edge("create_dispatch_plan", END)

    return workflow.compile()