# src/app/infrastructure/agents/generic_specialized_agent.py
import logging
from typing import Dict, Any, cast, List

from langgraph.graph import StateGraph, END
from pydantic import BaseModel, Field

from app.infrastructure.database.repositories.scan_repo import ScanRepository
from app.infrastructure.database.repositories.prompt_template_repo import PromptTemplateRepository
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

async def analysis_node(state: SpecializedAgentState, config: Dict[str, Any]) -> Dict[str, Any]:
    """
    A single, unified node that performs analysis based on the workflow_mode.
    It is parameterized by the agent_name and domain_query from the config.
    """
    agent_config = config.get("configurable", {})
    agent_name = agent_config.get("agent_name")
    domain_query = agent_config.get("domain_query")

    if not agent_name or not domain_query:
        return {"error": "analysis_node requires 'agent_name' and 'domain_query' in its config."}

    scan_id = state["scan_id"]
    filename = state["filename"]
    code_bundle = state["code_snippet"]
    # The scan_type from the DB (e.g., 'AUDIT_AND_REMEDIATE') determines the agent's behavior
    scan_type = state["workflow_mode"] 
    
    # Determine the prompt_template_type based on the internal workflow_mode
    if scan_type == "remediate":
        template_type = "DETAILED_REMEDIATION"
    else: # "audit"
        template_type = "QUICK_AUDIT"
        
    logger.info(
        f"[{agent_name}] Assessing file '{filename}' with template type '{template_type}'.",
        extra={"scan_id": str(scan_id), "source_file_path": filename}
    )

    # 1. Get security context from RAG service
    rag_service = get_rag_service()
    if not rag_service:
        error_msg = f"[{agent_name}] Failed to get RAG service."
        logger.error(error_msg, extra={"scan_id": str(scan_id)})
        return {"error": error_msg}

    retrieved_guidelines = rag_service.query_asvs(query_texts=[domain_query], n_results=10)
    documents = retrieved_guidelines.get("documents")
    context_str = "\n".join(documents[0]) if documents and documents[0] else "No relevant security guidelines found."

    # 2. Get the prompt template from the database
    async with AsyncSessionLocal() as db:
        prompt_repo = PromptTemplateRepository(db)
        prompt_template = await prompt_repo.get_template_by_name_and_type(agent_name, template_type)

    if not prompt_template:
        error_msg = f"No prompt template found for agent '{agent_name}' with type '{template_type}'."
        logger.error(error_msg, extra={"scan_id": str(scan_id)})
        return {"error": error_msg}

    prompt_text = prompt_template.template_text.format(
        security_guidelines=context_str,
        code_bundle=code_bundle
    )
    
    response_model = RemediateResponse if template_type == "DETAILED_REMEDIATION" else AuditResponse

    # 3. Get LLM client and generate response
    llm_config_id = state.get("llm_config_id")
    if not llm_config_id:
        return {"error": f"[{agent_name}] LLM configuration ID not provided."}

    llm_client = await get_llm_client(llm_config_id=llm_config_id)
    if not llm_client:
        return {"error": f"[{agent_name}] Failed to initialize LLM client."}

    llm_response: AgentLLMResult = await llm_client.generate_structured_output(
        prompt_text, response_model
    )

    # 4. Log the interaction
    parsed_output_dict = llm_response.parsed_output.model_dump() if llm_response.parsed_output else None
    prompt_context_for_log = {"code_bundle_length": len(code_bundle), "security_guidelines_length": len(context_str)}
    interaction = LLMInteraction(
        scan_id=scan_id,
        agent_name=agent_name,
        prompt_template_name=prompt_template.name,
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
        return {"error": f"[{agent_name}] LLM failed to produce valid analysis: {llm_response.error}"}

    # 5. Process the response
    findings = []
    fixes = []
    if template_type == "QUICK_AUDIT":
        audit_result = cast(AuditResponse, llm_response.parsed_output)
        for finding in audit_result.findings:
            finding.file_path = filename
            findings.append(finding)
    else:  # DETAILED_REMEDIATION
        remediate_result = cast(RemediateResponse, llm_response.parsed_output)
        for result in remediate_result.results:
            result.finding.file_path = filename
            findings.append(result.finding)
            fixes.append(
                FixResult(finding=result.finding, suggestion=result.suggestion)
            )

    logger.info(
        f"[{agent_name}] Completed analysis for file '{filename}'. Findings: {len(findings)}, Fixes: {len(fixes)}",
        extra={"scan_id": str(scan_id)}
    )
    return {"findings": findings, "fixes": fixes}


def build_generic_specialized_agent_graph():
    """Builds the simplified, single-step graph for any specialized agent."""
    workflow = StateGraph(SpecializedAgentState)
    workflow.add_node("analysis_node", analysis_node) # type: ignore
    workflow.set_entry_point("analysis_node")
    workflow.add_edge("analysis_node", END)
    return workflow.compile()   