# src/app/infrastructure/agents/communication_agent.py

import logging
from typing import Dict, Any, cast, List

from langgraph.graph import StateGraph, END
from pydantic import BaseModel, Field

from app.infrastructure.database.repositories.scan_repo import ScanRepository
from app.infrastructure.database import AsyncSessionLocal
from app.infrastructure.llm_client import get_llm_client, AgentLLMResult
from app.infrastructure.rag.rag_client import get_rag_service
from app.core.schemas import (
    SpecializedAgentState,
    LLMInteraction,
    RemediationResult,
    FixResult,
    VulnerabilityFinding,
)

# --- Agent-specific Configuration ---
AGENT_NAME = "CommunicationAgent"
AGENT_PROMPT_NAME = "Secure Communication"
AGENT_DOMAIN_QUERY = "secure communication, TLS, SSL, HTTPS, certificate validation, weak ciphers, transport layer security, data in transit, network security protocols"
logger = logging.getLogger(__name__)


# --- Pydantic models for structured LLM responses ---


class RemediateResponse(BaseModel):
    """The expected output when running in 'remediate' mode."""

    results: List[RemediationResult] = Field(
        description="A list of vulnerability findings and their corresponding fixes."
    )


class AuditResponse(BaseModel):
    """The expected output when running in 'audit' mode."""

    findings: List[VulnerabilityFinding] = Field(
        description="A list of vulnerability findings without any fixes."
    )


async def analysis_node(state: SpecializedAgentState) -> Dict[str, Any]:
    """
    A single, unified node that performs analysis based on the workflow_mode.
    It can either run a read-only audit or find and fix vulnerabilities.
    """
    scan_id = state["scan_id"]
    filename = state["filename"]
    code_bundle = state["code_snippet"]
    mode = state["workflow_mode"]

    logger.info(
        f"[{AGENT_NAME}] Assessing file in '{mode}' mode.",
        extra={"scan_id": str(scan_id), "source_file_path": filename, "mode": mode}
    )

    rag_service = get_rag_service()
    if not rag_service:
        logger.error(f"[{AGENT_NAME}] Failed to get RAG service.", extra={"scan_id": str(scan_id), "source_file_path": filename})
        return {"error": "Failed to get RAG service."}

    retrieved_guidelines = rag_service.query_asvs(
        query_texts=[AGENT_DOMAIN_QUERY], n_results=10
    )
    documents = retrieved_guidelines.get("documents")
    if documents and documents[0]:
        context_str = "\n".join(documents[0])
    else:
        context_str = "No relevant security guidelines found."

    # Select the appropriate prompt and response model based on the workflow mode
    if mode == "audit":
        prompt = f"""
        You are a security expert specializing in {AGENT_PROMPT_NAME}.
        Your task is to perform a read-only audit of the provided code bundle.
        Analyze the code for vulnerabilities related to your domain, using the provided security guidelines.
        For each vulnerability found, provide a detailed finding with a concise 'title'. Do NOT suggest code fixes.
        <SECURITY_GUIDELINES>
        {context_str}
        </SECURITY_GUIDELINES>

        <CODE_BUNDLE>
        {code_bundle}
        </CODE_BUNDLE>

        Respond ONLY with a valid JSON object that conforms to the specified schema.
        """
        response_model = AuditResponse
    else:  # mode == "remediate"
        prompt = f"""
        You are a security expert specializing in {AGENT_PROMPT_NAME}.
        Your task is to find vulnerabilities and provide complete, secure code replacements.
        Analyze the code in the <CODE_BUNDLE> using the provided <SECURITY_GUIDELINES>.
        For each vulnerability you identify:
        1.  Provide a detailed 'finding' object, including a concise 'title'.
        2.  Provide a 'suggestion' object that includes the 'original_snippet' of code to be replaced and the new 'code' that fixes the vulnerability.
        <SECURITY_GUIDELINES>
        {context_str}
        </SECURITY_GUIDELINES>

        <CODE_BUNDLE>
        {code_bundle}
        </CODE_BUNDLE>

        Respond ONLY with a valid JSON object that conforms to the specified schema. Each result must contain both the finding and the suggestion.
        """
        response_model = RemediateResponse

    llm_config_id = state.get("llm_config_id")
    if not llm_config_id:
        logger.error(f"[{AGENT_NAME}] LLM configuration ID not provided.", extra={"scan_id": str(scan_id)})
        return {"error": "LLM configuration ID not provided."}

    llm_client = await get_llm_client(llm_config_id=llm_config_id)
    if not llm_client:
        logger.error(f"[{AGENT_NAME}] Failed to initialize LLM client.", extra={"scan_id": str(scan_id)})
        return {"error": "Failed to initialize LLM client."}

    llm_response: AgentLLMResult = await llm_client.generate_structured_output(
        prompt, response_model
    )

    # Log the entire interaction for traceability
    parsed_output_dict = (
        llm_response.parsed_output.model_dump() if llm_response.parsed_output else None
    )
    prompt_context_for_log = { "code_bundle": code_bundle, "security_guidelines": context_str }
    interaction = LLMInteraction(
        scan_id=scan_id,
        agent_name=AGENT_NAME,
        prompt_template_name=AGENT_PROMPT_NAME,
        prompt_context=prompt_context_for_log,
        raw_response=llm_response.raw_output,
        parsed_output=parsed_output_dict,
        error=llm_response.error,
        file_path=filename,
        cost=llm_response.cost,
        input_tokens=llm_response.prompt_tokens,
        output_tokens=llm_response.completion_tokens,
        total_tokens=llm_response.total_tokens,
    )
    async with AsyncSessionLocal() as db:
        repo = ScanRepository(db)
        await repo.save_llm_interaction(interaction_data=interaction)

    if llm_response.error or not llm_response.parsed_output:
        logger.error(
            f"[{AGENT_NAME}] LLM failed to produce valid analysis for file.",
            extra={"scan_id": str(scan_id), "source_file_path": filename, "error": llm_response.error}
        )
        return {"error": f"LLM failed to produce valid analysis: {llm_response.error}"}

    # Process the response based on the mode
    findings = []
    fixes = []
    if mode == "audit":
        audit_result = cast(AuditResponse, llm_response.parsed_output)
        for finding in audit_result.findings:
            finding.file_path = filename
            findings.append(finding)
    else:  # mode == "remediate"
        remediate_result = cast(RemediateResponse, llm_response.parsed_output)
        for result in remediate_result.results:
            result.finding.file_path = filename
            findings.append(result.finding)
            fixes.append(
                FixResult(finding=result.finding, suggestion=result.suggestion)
            )

    logger.info(
        f"[{AGENT_NAME}] Completed analysis for file.",
        extra={"scan_id": str(scan_id), "source_file_path": filename, "findings_found": len(findings), "fixes_found": len(fixes)}
    )
    return {"findings": findings, "fixes": fixes}


def build_specialized_agent_graph():
    """Builds the simplified, single-step graph for the specialized agent."""
    workflow = StateGraph(SpecializedAgentState)
    workflow.add_node("analysis_node", analysis_node)
    workflow.set_entry_point("analysis_node")
    workflow.add_edge("analysis_node", END)
    return workflow.compile()
