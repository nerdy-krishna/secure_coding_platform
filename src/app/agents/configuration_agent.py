# src/app/agents/configuration_agent.py
import logging
from typing import Dict, Any

from langgraph.graph import StateGraph, END

from src.app.db import crud
from src.app.db.database import AsyncSessionLocal
from src.app.llm.llm_client import get_llm_client, AgentLLMResult
from src.app.rag.rag_service import get_rag_service
from src.app.agents.schemas import (
    AnalysisResult,
    FixSuggestion,
    FixResult,
    SpecializedAgentState,
)

# Agent-specific configuration
AGENT_NAME = "ConfigurationAgent"
AGENT_DOMAIN_QUERY = "secure configuration, misconfigurations, default credentials, verbose error messages, debug mode in production, security headers, framework security settings"
logger = logging.getLogger(__name__)


# --- Agent Nodes ---

async def assess_vulnerabilities_node(state: SpecializedAgentState) -> Dict[str, Any]:
    """
    Queries the RAG for relevant guidelines and uses the LLM to find configuration vulnerabilities.
    """
    submission_id = state["submission_id"]
    filename = state["filename"]
    code_snippet = state["code_snippet"]
    logger.info(f"[{AGENT_NAME}] Assessing vulnerabilities for: {filename}")

    rag_service = get_rag_service()
    if not rag_service:
        return {"error": "Failed to get RAG service."}

    retrieved_guidelines = rag_service.query_asvs(query_texts=[AGENT_DOMAIN_QUERY], n_results=10)
    context_str = "\n".join(res['document'] for res in retrieved_guidelines[0]['results']) if retrieved_guidelines else "No specific guidelines retrieved."

    prompt = f"""
    You are a security expert specializing in {AGENT_NAME}. Analyze the following code snippet, which may be a configuration file or application code, for security misconfigurations.
    Focus on issues like hardcoded secrets, default or weak credentials, verbose error handling or debug flags enabled, missing security headers, and insecure framework defaults.
    Use the provided OWASP ASVS security guidelines for your analysis. For each vulnerability found, provide a detailed finding.

    SECURITY GUIDELINES (OWASP ASVS):
    ---
    {context_str}
    ---

    CODE SNIPPET (File: {filename}):
    ```
    {code_snippet}
    ```

    Identify security misconfigurations and respond with a structured list of findings. If no vulnerabilities are found, return an empty list.
    """
    llm_client = get_llm_client()
    llm_response: AgentLLMResult = await llm_client.generate_structured_output(prompt, AnalysisResult)

    async with AsyncSessionLocal() as db:
        await crud.save_llm_interaction(
            db, submission_id=submission_id, agent_name=AGENT_NAME, prompt=prompt,
            raw_response=llm_response.raw_output, parsed_output=llm_response.parsed_output.dict() if llm_response.parsed_output else None,
            error=llm_response.error, file_path=filename, cost=llm_response.cost
        )

    if llm_response.error or not llm_response.parsed_output:
        return {"error": f"LLM failed to produce valid analysis: {llm_response.error}"}

    for finding in llm_response.parsed_output.findings:
        finding.file_path = filename

    return {"findings": llm_response.parsed_output.findings}


async def generate_fixes_node(state: SpecializedAgentState) -> Dict[str, Any]:
    """
    For each vulnerability found, generates a secure code fix.
    """
    findings = state.get("findings", [])
    if not findings:
        return {"fixes": []}

    submission_id = state["submission_id"]
    filename = state["filename"]
    code_snippet = state["code_snippet"]
    logger.info(f"[{AGENT_NAME}] Generating fixes for {len(findings)} findings in: {filename}")
    
    llm_client = get_llm_client()
    all_fixes = []

    for finding in findings:
        prompt = f"""
        A security misconfiguration has been identified in the following code snippet from file '{filename}'.

        VULNERABLE CODE/CONFIGURATION:
        ```
        {code_snippet}
        ```

        VULNERABILITY DETAILS:
        - Description: {finding.description}
        - Line Number: {finding.line_number}
        - CWE: {finding.cwe}

        Your task is to provide a secure configuration or code replacement. This might involve removing hardcoded secrets, disabling debug mode, or adding security headers.
        Respond with a structured JSON object containing a brief description of the fix and the secure code/configuration snippet.
        """
        llm_response: AgentLLMResult = await llm_client.generate_structured_output(prompt, FixSuggestion)
        
        async with AsyncSessionLocal() as db:
            await crud.save_llm_interaction(
                db, submission_id=submission_id, agent_name=f"{AGENT_NAME}-Fixer", prompt=prompt,
                raw_response=llm_response.raw_output, parsed_output=llm_response.parsed_output.dict() if llm_response.parsed_output else None,
                error=llm_response.error, file_path=filename, cost=llm_response.cost
            )
        
        if not llm_response.error and llm_response.parsed_output:
            all_fixes.append(FixResult(finding=finding, suggestion=llm_response.parsed_output))
    
    return {"fixes": all_fixes}


# --- Graph Builder ---

def build_specialized_agent_graph():
    """Builds the LangGraph workflow for the Configuration Agent."""
    workflow = StateGraph(SpecializedAgentState)
    workflow.add_node("assess_vulnerabilities", assess_vulnerabilities_node)
    workflow.add_node("generate_fixes", generate_fixes_node)

    workflow.set_entry_point("assess_vulnerabilities")
    workflow.add_edge("assess_vulnerabilities", "generate_fixes")
    workflow.add_edge("generate_fixes", END)

    return workflow.compile()