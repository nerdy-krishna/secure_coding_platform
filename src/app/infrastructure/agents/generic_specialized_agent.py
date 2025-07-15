# src/app/infrastructure/agents/generic_specialized_agent.py
import logging
from typing import Dict, Any, Optional, cast, List

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
    FixSuggestion,
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

class CorrectedSnippet(BaseModel):
    """A Pydantic model for the snippet correction call."""
    corrected_original_snippet: str

async def analysis_node(state: SpecializedAgentState, config: Dict[str, Any]) -> Dict[str, Any]:
    """
    A single, unified node that performs analysis based on the workflow_mode.
    """
    agent_config = config.get("configurable", {})
    agent_name = agent_config.get("agent_name")
    domain_query = agent_config.get("domain_query")

    if not agent_name or not domain_query:
        return {"error": "analysis_node requires 'agent_name' and 'domain_query' in its config."}

    scan_id = state["scan_id"]
    filename = state["filename"]
    code_bundle = state["code_snippet"]
    workflow_mode = state["workflow_mode"]
    
    template_type = "DETAILED_REMEDIATION" if workflow_mode == "remediate" else "QUICK_AUDIT"
        
    logger.info(
        f"[{agent_name}] Assessing '{filename}' with template type '{template_type}'.",
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
    findings: List[VulnerabilityFinding] = []
    fixes: List[FixResult] = []

    if workflow_mode == "audit":
        audit_result = cast(AuditResponse, llm_response.parsed_output)
        for finding in audit_result.findings:
            finding.file_path = filename
            finding.agent_name = agent_name
            findings.append(finding)
    else:  # 'remediate' mode
        remediate_result = cast(RemediateResponse, llm_response.parsed_output)
        for result in remediate_result.results:
            result.finding.file_path = filename
            result.finding.agent_name = agent_name
            
            # Snippet Verification & Retry Logic
            code_for_verification = state.get("file_content_for_verification")
            verified_suggestion = None
            if code_for_verification:
                verified_suggestion = await _verify_and_correct_snippet(
                    llm_client=llm_client,
                    code_to_search=code_for_verification,
                    suggestion=result.suggestion,
                )
            else:
                logger.warning(f"[{agent_name}] Missing full file content for verification. Skipping snippet check.")


            if verified_suggestion:
                result.suggestion = verified_suggestion
                fixes.append(
                    FixResult(finding=result.finding, suggestion=result.suggestion)
                )
            else:
                logger.warning(
                    f"[{agent_name}] Could not verify snippet for CWE {result.finding.cwe} "
                    f"in {filename} after retries. Discarding fix."
                )
            
            # Always add the finding, even if the fix was discarded
            findings.append(result.finding)

    logger.info(
        f"[{agent_name}] Completed analysis for file '{filename}'. "
        f"Findings: {len(findings)}, Verified Fixes: {len(fixes)}",
        extra={"scan_id": str(scan_id)}
    )
    return {"findings": findings, "fixes": fixes}

async def _verify_and_correct_snippet(
    llm_client: Any, code_to_search: str, suggestion: FixSuggestion
) -> Optional[FixSuggestion]:
    """
    Verifies a snippet exists and attempts to correct it using an LLM if it doesn't.
    Returns the verified/corrected suggestion or None if it fails.
    """
    original_snippet = suggestion.original_snippet
    for attempt in range(4): # 1 initial try + 3 retries
        if original_snippet in code_to_search:
            suggestion.original_snippet = original_snippet # Ensure the latest version is set
            return suggestion

        if attempt == 3:
            break # Failed last attempt

        logger.warning(f"Snippet not found. Retrying with LLM correction (Attempt {attempt + 1}/3).")
        correction_prompt = f"""
        The following 'original_snippet' was not found in the 'source_code'.
        Please analyze the 'source_code' and the 'suggested_fix' to identify the correct 'original_snippet' that the fix should replace.
        The code may have been slightly modified. Find the logical equivalent.
        Respond ONLY with a JSON object containing the 'corrected_original_snippet'.

        <source_code>
        {code_to_search}
        </source_code>

        <original_snippet>
        {original_snippet}
        </original_snippet>

        <suggested_fix>
        {suggestion.code}
        </suggested_fix>
        """
        try:
            correction_result = await llm_client.generate_structured_output(correction_prompt, CorrectedSnippet)
            if isinstance(correction_result.parsed_output, CorrectedSnippet):
                original_snippet = correction_result.parsed_output.corrected_original_snippet
                logger.info(f"Received corrected snippet from LLM: '{original_snippet[:60]}...'")
            else:
                logger.warning("LLM failed to provide a corrected snippet on this attempt.")
        except Exception as e:
            logger.error(f"Error during LLM snippet correction: {e}")

    return None

def build_generic_specialized_agent_graph():
    """Builds the simplified, single-step graph for any specialized agent."""
    workflow = StateGraph(SpecializedAgentState)
    workflow.add_node("analysis_node", analysis_node) # type: ignore
    workflow.set_entry_point("analysis_node")
    workflow.add_edge("analysis_node", END)
    return workflow.compile()   