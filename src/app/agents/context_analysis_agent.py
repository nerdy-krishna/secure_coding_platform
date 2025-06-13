# src/app/agents/context_analysis_agent.py
import logging
from typing import Dict, Any
from pydantic import BaseModel, Field

# FIX: Import the factory function 'get_llm_client' instead of the non-existent 'LLMClient' class
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
    is_relevant: bool = Field(..., description="True if the agent's security domain is relevant to the code, otherwise False.")
    reasoning: str = Field(..., description="A brief explanation for why the agent is or is not relevant.")

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

async def analyze_code_context(state: Dict[str, Any]) -> Dict[str, Any]:
    """
    Analyzes the code snippet to determine which specialized security agents are relevant.
    """
    logger.info(f"[{AGENT_NAME}] Starting context analysis for submission ID: {state['submission_id']}")
    code_snippet = state["code_snippet"]
    
    # FIX: Call the factory function to get the LLM provider instance
    llm_client = get_llm_client()

    prompt = f"""
    You are an expert security architect. Your task is to analyze the provided code snippet
    and determine which of the following security domains are relevant for a detailed vulnerability analysis.
    For each domain, you must decide if it is relevant and provide a brief reasoning.

    AGENT DESCRIPTIONS:
    {AGENT_DESCRIPTIONS}

    CODE SNIPPET:
    ```
    {code_snippet}
    ```

    Based on the code, evaluate each agent's relevance.
    """

    # This method call is still correct, as the provider returned by the factory has this method.
    llm_response = await llm_client.generate_structured_output(prompt, TaskBreakdown)

    if llm_response.error or not llm_response.parsed_output:
        logger.error(f"[{AGENT_NAME}] Failed to get valid task breakdown from LLM.")
        return {"task_breakdown": {}}

    task_breakdown = llm_response.parsed_output.dict()
    logger.info(f"[{AGENT_NAME}] Context analysis complete. Relevant agents determined.")
    return {"task_breakdown": task_breakdown}