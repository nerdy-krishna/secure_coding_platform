import json
import logging
from typing import TypedDict, List, Optional, Dict, Any
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

class SecurityDomain(BaseModel):
    domain: str = Field(description="The specific security domain identified (e.g., 'Authentication', 'Access Control', 'Cryptography').")
    reason: str = Field(description="A brief justification for why this domain is relevant to the code snippet.")

class CodeContext(BaseModel):
    summary: str = Field(description="A concise summary of the code's functionality.")
    security_domains: List[SecurityDomain] = Field(description="A list of relevant security domains for the code.")

# --- Agent State ---

class ContextAnalysisAgentState(TypedDict):
    submission_id: UUID
    file_path: str
    file_content: str
    project_context: Optional[str]
    analysis_result: Optional[Dict[str, Any]]
    error: Optional[str]

# --- Agent Nodes ---

async def analyze_code_context(state: ContextAnalysisAgentState) -> ContextAnalysisAgentState:
    """
    Analyzes the code to identify its purpose and relevant security domains using an LLM.
    """
    logger.info(f"Analyzing code context for file: {state['file_path']}")
    llm_client = get_llm_client()

    prompt_template = """
    You are an expert security analyst. Your task is to analyze the provided code snippet and identify its primary purpose and all relevant security domains based on OWASP ASVS categories.

    Code Snippet:
    ```
    {file_content}
    ```

    Project Context:
    {project_context}

    Based on the code and its context, provide:
    1. A brief summary of what the code does.
    2. A list of all applicable security domains from the following list that should be scrutinized for vulnerabilities:
       - V1: Architecture, Design and Threat Modeling
       - V2: Authentication
       - V3: Session Management
       - V4: Access Control
       - V5: Validation, Sanitization and Encoding
       - V6: Stored Cryptography
       - V7: Error Handling and Logging
       - V8: Data Protection
       - V9: Communications
       - V10: Malicious Code
       - V11: Business Logic
       - V12: File and Resources
       - V13: API and Web Service
       - V14: Configuration
    
    Respond with a JSON object that strictly adheres to the provided schema.
    """
    prompt = prompt_template.format(
        file_content=state["file_content"],
        project_context=state.get("project_context", "No additional project context provided.")
    )

    db: AsyncSession = await get_session().__anext__()
    try:
        llm_result: LLMResult = await llm_client.generate_structured_output(prompt, CodeContext)

        # Correctly save the full LLM interaction result
        interaction_context = {
            "file_name": state["file_path"],
            "operation": "Initial Context Analysis"
        }
        await save_llm_interaction(
            db=db,
            result=llm_result,
            submission_id=state["submission_id"],
            agent_name="ContextAnalysisAgent",
            interaction_context=interaction_context
        )

        if llm_result.error:
            logger.error(f"LLM call failed for {state['file_path']}: {llm_result.error}")
            return {**state, "error": llm_result.error}

        parsed_output = llm_result.parsed_output
        if not parsed_output:
            logger.error(f"Failed to parse LLM output for {state['file_path']}.")
            return {**state, "error": "Failed to parse LLM output."}
        
        analysis_data = parsed_output.dict()
        logger.info(f"Successfully analyzed context for {state['file_path']}. Domains: {[d['domain'] for d in analysis_data.get('security_domains', [])]}")
        
        return {**state, "analysis_result": analysis_data}

    except Exception as e:
        logger.exception(f"An unexpected error occurred during context analysis for {state['file_path']}: {e}")
        return {**state, "error": str(e)}
    finally:
        await db.close()


# --- Graph Builder ---

def build_context_analysis_agent_graph():
    """
    Builds the LangGraph workflow for the Context Analysis Agent.
    """
    workflow = StateGraph(ContextAnalysisAgentState)
    workflow.add_node("analyze_code_context", analyze_code_context)
    workflow.set_entry_point("analyze_code_context")
    workflow.add_edge("analyze_code_context", END)
    
    return workflow.compile()

# --- Main execution function (for standalone testing if needed) ---
async def run_agent(submission_id: UUID, file_path: str, file_content: str, project_context: Optional[str] = None):
    graph = build_context_analysis_agent_graph()
    initial_state = {
        "submission_id": submission_id,
        "file_path": file_path,
        "file_content": file_content,
        "project_context": project_context,
    }
    final_state = await graph.ainvoke(initial_state)
    return final_state