# src/app/agents/context_analysis_agent.py
import logging
from typing import Dict, Any, TypedDict, Optional, List

from langgraph.graph import StateGraph, END
from pydantic import BaseModel, Field

from ..llm.llm_client import get_llm_client

# Configure logging
logger = logging.getLogger(__name__)
AGENT_NAME = "ContextAnalysisAgent"

AGENT_DESCRIPTIONS = {
    "AccessControlAgent": "Analyzes for vulnerabilities related to user permissions, authorization, and insecure direct object references.",
    "ApiSecurityAgent": "Focuses on the security of API endpoints, including REST, GraphQL, and other web services.",
    "ArchitectureAgent": "Assesses the overall security architecture, design patterns, and data flow.",
    "AuthenticationAgent": "Scrutinizes login mechanisms, password policies, multi-factor authentication, and credential management.",
    "BusinessLogicAgent": "Looks for flaws in the application's business logic that could be exploited.",
    "CodeIntegrityAgent": "Verifies the integrity of code and dependencies to prevent tampering.",
    "CommunicationAgent": "Checks for secure data transmission, use of TLS, and protection against network-level attacks.",
    "ConfigurationAgent": "Inspects for misconfigurations in the application, server, or third-party services.",
    "CryptographyAgent": "Evaluates the use of encryption, hashing algorithms, and key management.",
    "DataProtectionAgent": "Focuses on the protection of sensitive data at rest and in transit, including PII.",
    "ErrorHandlingAgent": "Analyzes error handling routines to prevent information leakage.",
    "FileHandlingAgent": "Scrutinizes file upload, download, and processing functionality for vulnerabilities.",
    "SessionManagementAgent": "Checks for secure session handling, token management, and protection against session hijacking.",
    "ValidationAgent": "Focuses on input validation, output encoding, and prevention of injection attacks like SQLi and XSS.",
}


class AgentRelevance(BaseModel):
    is_relevant: bool = Field(
        ...,
        description="True if the agent's security domain is relevant to the code, otherwise False.",
    )
    reasoning: str = Field(
        ..., description="A brief explanation for why the agent is or is not relevant."
    )


class TaskBreakdown(BaseModel):
    AccessControlAgent: AgentRelevance
    ApiSecurityAgent: AgentRelevance
    ArchitectureAgent: AgentRelevance
    AuthenticationAgent: AgentRelevance
    BusinessLogicAgent: AgentRelevance
    CodeIntegrityAgent: AgentRelevance
    CommunicationAgent: AgentRelevance
    ConfigurationAgent: AgentRelevance
    CryptographyAgent: AgentRelevance
    DataProtectionAgent: AgentRelevance
    ErrorHandlingAgent: AgentRelevance
    FileHandlingAgent: AgentRelevance
    SessionManagementAgent: AgentRelevance
    ValidationAgent: AgentRelevance


class FullContextAnalysis(BaseModel):
    """The complete structured output for the context analysis agent."""

    analysis_summary: str = Field(
        description="A brief, one-paragraph summary of the code's functionality."
    )
    identified_components: List[str] = Field(
        description="A list of key components, frameworks, or libraries used (e.g., 'FastAPI', 'SQLAlchemy')."
    )
    asvs_analysis: TaskBreakdown = Field(
        description="The relevance analysis for each security agent based on the code."
    )


class ContextAnalysisAgentState(TypedDict):
    """
    Defines the state for the Context Analysis Agent's workflow.
    This is the state that will be passed between the nodes of its graph.
    """

    submission_id: int
    filename: str
    code_snippet: str
    language: str
    analysis_summary: Optional[str]
    identified_components: Optional[List[str]]
    asvs_analysis: Optional[Dict[str, Any]]
    error_message: Optional[str]


async def analyze_code_context_node(state: ContextAnalysisAgentState) -> Dict[str, Any]:
    """
    Analyzes the code snippet to provide a summary, identify components, and determine
    which specialized security agents are relevant for a deeper scan.
    """
    logger.info(
        f"[{AGENT_NAME}] Starting context analysis for submission ID: {state['submission_id']}, file: {state['filename']}"
    )
    code_snippet = state["code_snippet"]

    llm_client = get_llm_client()

    prompt = f"""
    You are an expert security architect. Your task is to analyze the provided code snippet.
    
    First, provide a brief, one-paragraph summary of the code's functionality in `analysis_summary`.
    Second, identify key components, frameworks, or libraries and list them in `identified_components`.
    Third, for each security agent in the `asvs_analysis` object, determine if its security domain is relevant for a detailed vulnerability scan of the given code, and provide your reasoning.

    AGENT DESCRIPTIONS:
    {AGENT_DESCRIPTIONS}

    CODE SNIPPET:
    ```
    {code_snippet}
    ```

    Respond with a single, valid JSON object that strictly adheres to the provided schema.
    """

    llm_response = await llm_client.generate_structured_output(
        prompt, FullContextAnalysis
    )

    if llm_response.error or not llm_response.parsed_output:
        error_msg = (
            llm_response.error
            or "Failed to get a valid structured response from the LLM."
        )
        logger.error(
            f"[{AGENT_NAME}] Failed to get full context analysis from LLM for file {state['filename']}: {error_msg}"
        )
        return {"error_message": error_msg}

    parsed_output = llm_response.parsed_output
    logger.info(
        f"[{AGENT_NAME}] Context analysis complete for file {state['filename']}."
    )

    return {
        "analysis_summary": parsed_output.analysis_summary,
        "identified_components": parsed_output.identified_components,
        "asvs_analysis": parsed_output.asvs_analysis.dict(),  # Convert Pydantic model to dict
        "error_message": None,
    }


def build_context_analysis_agent_graph():
    """Builds the graph for the context analysis agent."""
    workflow = StateGraph(ContextAnalysisAgentState)
    workflow.add_node("analyze_code_context", analyze_code_context_node)
    workflow.set_entry_point("analyze_code_context")
    workflow.add_edge("analyze_code_context", END)
    return workflow.compile()
