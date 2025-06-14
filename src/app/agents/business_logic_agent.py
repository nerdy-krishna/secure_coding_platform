# src/app/agents/business_logic_agent.py
import logging
from typing import Dict, Any

from langgraph.graph import StateGraph, END

from app.db import crud
from app.db.database import AsyncSessionLocal
from app.llm.llm_client import get_llm_client, AgentLLMResult
from app.rag.rag_service import get_rag_service
from app.agents.schemas import (
    AnalysisResult,
    FixSuggestion,
    FixResult,
    SpecializedAgentState,
)

# Agent-specific configuration
AGENT_NAME = "BusinessLogicAgent"
AGENT_DOMAIN_QUERY = "business logic abuse, feature misuse, race conditions, information leakage through business flows, CWE-840, unexpected application state transitions"
logger = logging.getLogger(__name__)


# --- Agent Nodes ---


async def assess_vulnerabilities_node(state: SpecializedAgentState) -> Dict[str, Any]:
    """
    Queries the RAG for relevant guidelines and uses the LLM to find business logic vulnerabilities.
    """
    submission_id = state["submission_id"]
    filename = state["filename"]
    code_snippet = state["code_snippet"]
    logger.info(f"[{AGENT_NAME}] Assessing vulnerabilities for: {filename}")

    rag_service = get_rag_service()
    if not rag_service:
        return {"error": "Failed to get RAG service."}

    retrieved_guidelines = rag_service.query_asvs(
        query_texts=[AGENT_DOMAIN_QUERY], n_results=10
    )
    context_str = (
        "\n".join(res["document"] for res in retrieved_guidelines[0]["results"])
        if retrieved_guidelines
        else "No specific guidelines retrieved."
    )

    prompt = f"""
    You are a security expert specializing in {AGENT_NAME}. Analyze the following code snippet for vulnerabilities related to the application's business logic.
    Focus on flaws that would allow an attacker to misuse features, cause unintended state changes, or exploit the intended workflow (e.g., bypassing payment steps, exploiting race conditions, etc.).
    Use the provided OWASP ASVS security guidelines for your analysis. For each vulnerability found, provide a detailed finding.

    SECURITY GUIDELINES (OWASP ASVS):
    ---
    {context_str}
    ---

    CODE SNIPPET (File: {filename}):
    ```
    {code_snippet}
    ```

    Identify business logic security vulnerabilities and respond with a structured list of findings. If no vulnerabilities are found, return an empty list.
    """
    llm_client = get_llm_client()
    llm_response: AgentLLMResult = await llm_client.generate_structured_output(
        prompt, AnalysisResult
    )

    async with AsyncSessionLocal() as db:
        await crud.save_llm_interaction(
            db,
            submission_id=submission_id,
            agent_name=AGENT_NAME,
            prompt=prompt,
            raw_response=llm_response.raw_output,
            parsed_output=llm_response.parsed_output.dict()
            if llm_response.parsed_output
            else None,
            error=llm_response.error,
            file_path=filename,
            cost=llm_response.cost,
        )

    if llm_response.error or not llm_response.parsed_output:
        return {"error": f"LLM failed to produce valid analysis: {llm_response.error}"}

    for finding in llm_response.parsed_output.findings:
        finding.file_path = filename

    return {"findings": llm_response.parsed_output.findings}


async def generate_fixes_node(state: SpecializedAgentState) -> Dict[str, Any]:
    """
    For each vulnerability found, generates a conceptual fix, as business logic fixes are often not simple code replacements.
    """
    findings = state.get("findings", [])
    if not findings:
        return {"fixes": []}

    submission_id = state["submission_id"]
    filename = state["filename"]
    code_snippet = state["code_snippet"]
    logger.info(
        f"[{AGENT_NAME}] Generating fixes for {len(findings)} findings in: {filename}"
    )

    llm_client = get_llm_client()
    all_fixes = []

    for finding in findings:
        prompt = f"""
        A business logic vulnerability has been identified in the following code snippet from file '{filename}'.

        VULNERABLE CODE CONTEXT:
        ```
        {code_snippet}
        ```

        VULNERABILITY DETAILS:
        - Description: {finding.description}
        - Line Number: {finding.line_number}
        - CWE: {finding.cwe}

        Your task is to provide a conceptual remediation for this business logic flaw. The fix may involve code changes, but should primarily focus on correcting the logical process.
        Describe the fix and, if applicable, provide a code snippet illustrating the corrected logic.
        Respond with a structured JSON object.
        """
        llm_response: AgentLLMResult = await llm_client.generate_structured_output(
            prompt, FixSuggestion
        )

        async with AsyncSessionLocal() as db:
            await crud.save_llm_interaction(
                db,
                submission_id=submission_id,
                agent_name=f"{AGENT_NAME}-Fixer",
                prompt=prompt,
                raw_response=llm_response.raw_output,
                parsed_output=llm_response.parsed_output.dict()
                if llm_response.parsed_output
                else None,
                error=llm_response.error,
                file_path=filename,
                cost=llm_response.cost,
            )

        if not llm_response.error and llm_response.parsed_output:
            all_fixes.append(
                FixResult(finding=finding, suggestion=llm_response.parsed_output)
            )

    return {"fixes": all_fixes}


# --- Graph Builder ---


def build_specialized_agent_graph():
    """Builds the LangGraph workflow for the Business Logic Agent."""
    workflow = StateGraph(SpecializedAgentState)
    workflow.add_node("assess_vulnerabilities", assess_vulnerabilities_node)
    workflow.add_node("generate_fixes", generate_fixes_node)

    workflow.set_entry_point("assess_vulnerabilities")
    workflow.add_edge("assess_vulnerabilities", "generate_fixes")
    workflow.add_edge("generate_fixes", END)

    return workflow.compile()
