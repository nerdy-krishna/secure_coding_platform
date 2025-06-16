# src/app/agents/authentication_agent.py
import logging
from typing import List, Dict, Any, cast

from langgraph.graph import StateGraph, END

from app.db import crud
from app.db.database import AsyncSessionLocal

# Import AgentLLMResult instead of LLMResult
from app.llm.llm_client import get_llm_client, AgentLLMResult
from app.rag.rag_service import get_rag_service

from app.agents.schemas import (
    AnalysisResult,
    FixSuggestion,
    FixResult,
    SpecializedAgentState,
    LLMInteraction, # Added import
)

AGENT_NAME = "AuthenticationAgent"
AGENT_DOMAIN_QUERY = "authentication, password policies, credential management, session tokens, multi-factor authentication (MFA), secure login, token-based auth, OAuth, JWT"
logger = logging.getLogger(__name__)


async def assess_vulnerabilities_node(state: SpecializedAgentState) -> Dict[str, Any]:
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
    You are a security expert specializing in {AGENT_NAME}. Analyze the following code snippet for vulnerabilities related to our domain.
    Use the provided security guidelines for your analysis. For each vulnerability found, provide a detailed finding.

    SECURITY GUIDELINES (OWASP ASVS):
    ---
    {context_str}
    ---

    CODE SNIPPET (File: {filename}):
    ```
    {code_snippet}
    ```

    Identify vulnerabilities and respond with a structured list of findings. If no vulnerabilities are found, return an empty list.
    """
    llm_config_id = state.get("llm_config_id")
    if not llm_config_id:
        return {"error": f"[{AGENT_NAME}] LLM configuration ID not provided."}

    llm_client = await get_llm_client(llm_config_id=llm_config_id)
    if not llm_client:
        return {"error": f"[{AGENT_NAME}] Failed to initialize LLM client with config ID {llm_config_id}."}
        
    # Use the correct type hint: AgentLLMResult
    llm_response: AgentLLMResult = await llm_client.generate_structured_output(
        prompt, AnalysisResult
    )

    parsed_output_dict = None
    if llm_response.parsed_output:
        # Assuming llm_response.parsed_output is a Pydantic model (AnalysisResult instance)
        parsed_output_dict = llm_response.parsed_output.dict()

    interaction = LLMInteraction(
        submission_id=submission_id,
        agent_name=AGENT_NAME,
        prompt=prompt,
        raw_response=llm_response.raw_output,
        parsed_output=parsed_output_dict,
        error=llm_response.error,
        file_path=filename,
        cost=llm_response.cost,
    )
    async with AsyncSessionLocal() as db:
        await crud.save_llm_interaction(db, interaction_data=interaction)

    if llm_response.error or not llm_response.parsed_output:
        return {"error": f"LLM failed to produce valid analysis: {llm_response.error}"}

    # Cast parsed_output to AnalysisResult for Pylance
    analysis_result = cast(AnalysisResult, llm_response.parsed_output)
    for finding in analysis_result.findings:
        finding.file_path = filename

    return {"findings": analysis_result.findings}


async def generate_fixes_node(state: SpecializedAgentState) -> Dict[str, Any]:
    findings = state.get("findings", [])
    if not findings:
        return {"fixes": []}

    submission_id = state["submission_id"]
    filename = state["filename"]
    code_snippet = state["code_snippet"]
    logger.info(
        f"[{AGENT_NAME}] Generating fixes for {len(findings)} findings in: {filename}"
    )

    all_fixes: List[FixResult] = []

    for finding in findings:
        prompt = f"""
        A security vulnerability has been identified in the following code snippet from file '{filename}'.

        VULNERABLE CODE:
        ```
        {code_snippet}
        ```

        VULNERABILITY DETAILS:
        - Description: {finding.description}
        - Line Number: {finding.line_number}
        - CWE: {finding.cwe}

        Your task is to provide a secure code replacement for the vulnerable part.
        Respond with a structured JSON object containing a brief description of the fix and the secure code snippet.
        """
        llm_config_id = state.get("llm_config_id")
        if not llm_config_id:
            logger.warning(f"[{AGENT_NAME}] LLM configuration ID not provided for fix generation. Skipping.")
            return {"fixes": []}

        fixer_llm_client = await get_llm_client(llm_config_id=llm_config_id)
        if not fixer_llm_client:
            logger.warning(f"[{AGENT_NAME}] Failed to initialize LLM client for fix generation with config ID {llm_config_id}. Skipping.")
            return {"fixes": []}

        # Use the correct type hint: AgentLLMResult
        llm_response: AgentLLMResult = await fixer_llm_client.generate_structured_output(
            prompt, FixSuggestion
        )

        parsed_output_dict = None
        if llm_response.parsed_output:
            # Assuming llm_response.parsed_output is a Pydantic model (FixSuggestion instance)
            parsed_output_dict = llm_response.parsed_output.dict()

        interaction = LLMInteraction(
            submission_id=submission_id,
            agent_name=f"{AGENT_NAME}-Fixer",
            prompt=prompt,
            raw_response=llm_response.raw_output,
            parsed_output=parsed_output_dict,
            error=llm_response.error,
            file_path=filename,
            cost=llm_response.cost,
        )
        async with AsyncSessionLocal() as db:
            await crud.save_llm_interaction(db, interaction_data=interaction)

        if not llm_response.error and llm_response.parsed_output:
            # Cast parsed_output to FixSuggestion for Pylance
            fix_suggestion = cast(FixSuggestion, llm_response.parsed_output)
            all_fixes.append(
                FixResult(finding=finding, suggestion=fix_suggestion)
            )

    return {"fixes": all_fixes}


def build_specialized_agent_graph():
    """Builds the LangGraph workflow for the Authentication Agent."""
    workflow = StateGraph(SpecializedAgentState)
    workflow.add_node("assess_vulnerabilities", assess_vulnerabilities_node)
    workflow.add_node("generate_fixes", generate_fixes_node)

    workflow.set_entry_point("assess_vulnerabilities")
    workflow.add_edge("assess_vulnerabilities", "generate_fixes")
    workflow.add_edge("generate_fixes", END)

    return workflow.compile()
