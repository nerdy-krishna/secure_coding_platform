import logging
import re
import cvss
from typing import Dict, Any, Optional, cast, List

from langgraph.graph import StateGraph, END
from pydantic import BaseModel, Field

from app.infrastructure.database.repositories.scan_repo import ScanRepository
from app.infrastructure.database.repositories.prompt_template_repo import (
    PromptTemplateRepository,
)
from app.infrastructure.database import AsyncSessionLocal
from app.infrastructure.llm_client import get_llm_client, LLMClient
from app.infrastructure.rag.rag_client import get_rag_service
from app.core.schemas import (
    SpecializedAgentState,
    LLMInteraction,
    FixResult,
    VulnerabilityFinding,
    FixSuggestion,
)

logger = logging.getLogger(__name__)

# --- Pydantic models for structured LLM responses ---


class InitialFinding(BaseModel):
    title: str = Field(description="A concise, one-line title for the vulnerability.")
    description: str = Field(
        description="A detailed description of the vulnerability found, explaining the root cause."
    )
    severity: str = Field(
        description="The assessed severity (e.g., 'High', 'Medium', 'Low')."
    )
    confidence: str = Field(
        description="The confidence level of the finding (e.g., 'High', 'Medium', 'Low')."
    )
    line_number: int = Field(
        description="The line number in the code where the vulnerability occurs."
    )
    cvss_vector: str = Field(
        description="The full CVSS 3.1 vector string, e.g., 'CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:L/A:N'."
    )
    remediation: str = Field(
        description="A detailed explanation of how to fix the vulnerability."
    )
    references: List[str] = Field(
        default_factory=list, description="A list of URLs or reference links."
    )
    keywords: List[str] = Field(
        description="A list of technical keywords that characterize the vulnerability (e.g., 'sql-injection', 'user-input', 'database')."
    )
    fix: Optional[FixSuggestion] = Field(
        default=None, description="The suggested code fix, if in remediate mode."
    )


class InitialAnalysisResponse(BaseModel):
    findings: List[InitialFinding]


class CweSelectionResponse(BaseModel):
    cwe_id: str = Field(
        description="The most appropriate CWE ID from the provided list, e.g., 'CWE-89'."
    )


class CorrectedSnippet(BaseModel):
    corrected_original_snippet: str


async def _get_cwe_from_description(
    llm_client: LLMClient, finding: InitialFinding
) -> Optional[str]:
    """
    Uses RAG and a constrained LLM call to determine the most accurate CWE.
    """
    rag_service = get_rag_service()
    if not rag_service:
        return None

    query_text = f"{finding.title}: {finding.description}"
    try:
        rag_results = rag_service.query_cwe_collection(
            query_texts=[query_text], n_results=3
        )

        ids = rag_results.get("ids", [[]])[0]
        distances = rag_results.get("distances", [[]])[0]
        metadatas = rag_results.get("metadatas", [[]])[0]

        if not ids or not distances:
            return None

        # If the top result is a very close match, use it directly.
        if distances[0] < 0.25:
            return ids[0]

        # Otherwise, ask the LLM to choose from the top candidates.
        candidate_strs = [
            f"- {id}: {meta.get('name')}" for id, meta in zip(ids, metadatas)
        ]
        candidates_text = "\n".join(candidate_strs)

        prompt = f"""
        Based on the following vulnerability description, select the most appropriate CWE ID from the provided list of candidates.
        
        VULNERABILITY:
        Title: {finding.title}
        Description: {finding.description}

        CANDIDATES:
        {candidates_text}

        Respond ONLY with a valid JSON object containing the single best 'cwe_id'.
        """
        response = await llm_client.generate_structured_output(
            prompt, CweSelectionResponse
        )
        if response.parsed_output and isinstance(
            response.parsed_output, CweSelectionResponse
        ):
            return response.parsed_output.cwe_id

    except Exception as e:
        logger.error(
            f"Error during CWE assignment for '{finding.title}': {e}", exc_info=True
        )

    return None


async def analysis_node(
    state: SpecializedAgentState, config: Dict[str, Any]
) -> Dict[str, Any]:
    """
    A single, unified node that performs analysis, generates CVSS/CWE, and suggests fixes.
    """
    agent_config = config.get("configurable", {})
    agent_name = agent_config.get("name")
    agent_description = agent_config.get("description")
    domain_query = agent_config.get("domain_query", {})

    logger.info(f"DEBUG: [{agent_name}] domain_query: {domain_query}")

    if not agent_name or not domain_query or not agent_description:
        return {
            "error": "analysis_node requires 'name', 'description', and 'domain_query' in its config."
        }

    scan_id = state["scan_id"]
    filename = state["filename"]
    code_bundle = state["code_snippet"]
    workflow_mode = state["workflow_mode"]

    template_type = (
        "DETAILED_REMEDIATION" if workflow_mode == "remediate" else "QUICK_AUDIT"
    )
    response_model = InitialAnalysisResponse

    logger.info(
        f"[{agent_name}] Assessing '{filename}' with template type '{template_type}'.",
        extra={"scan_id": str(scan_id), "source_file_path": filename},
    )

    rag_service = get_rag_service()
    if not rag_service:
        return {"error": f"[{agent_name}] Failed to get RAG service."}

    query_keywords = domain_query.get("keywords", "")
    metadata_filter = domain_query.get("metadata_filter")

    # Transform the filter for ChromaDB's '$in' or '$eq' operators
    # Enforce that agents only see 'scan_ready' documents (e.g. ASVS, Custom)
    # and not 'Chat Only' docs (e.g. Proactive Controls, Cheatsheets) unless explicitly requested?
    # For now, we enforce scan_ready=True for all agents using this node.

    # Base condition: scan_ready must be True
    and_conditions: List[Dict[str, Any]] = [{"scan_ready": {"$eq": True}}]

    if metadata_filter:
        for key, value in metadata_filter.items():
            if isinstance(value, list):
                if len(value) == 1:
                    # Use a simple $eq for single-item lists
                    and_conditions.append({key: {"$eq": value[0]}})
                else:
                    # Build a list of $eq clauses for an $or operation
                    or_clauses = [{key: {"$eq": item}} for item in value]
                    and_conditions.append({"$or": or_clauses})
            else:
                # Handle non-list values as a simple equality check
                and_conditions.append({key: {"$eq": value}})

    # If we have multiple conditions, wrap them in an $and
    if len(and_conditions) > 1:
        chroma_where_filter = {"$and": and_conditions}
    else:
        # Should be just the scan_ready check
        chroma_where_filter = and_conditions[0]

    retrieved_guidelines = rag_service.query_guidelines(
        query_texts=[query_keywords], n_results=10, where=chroma_where_filter
    )
    documents = retrieved_guidelines.get("documents", [[]])[0]
    logger.info(
        f"[{agent_name}] RAG query retrieved {len(documents)} documents for context."
    )

    # Determine language from filename
    language_map = {
        ".py": "PYTHON",
        ".js": "JAVASCRIPT",
        ".ts": "TYPESCRIPT",
        ".java": "JAVA",
        ".cs": "C#",
        ".go": "GO",
        ".cpp": "C++",
        ".c": "C",
        ".php": "PHP",
        ".rb": "RUBY",
        ".rs": "RUST",
        ".swift": "SWIFT",
        ".kt": "KOTLIN",
        ".sh": "BASH",
        ".sql": "SQL",
        ".tf": "TERRAFORM",
    }
    file_ext = "." + filename.split(".")[-1].lower() if "." in filename else ""
    target_lang = language_map.get(file_ext, "GENERIC")

    vulnerability_patterns = []
    secure_patterns = []
    if documents:
        for doc in documents:
            # 1. Extract Generic Patterns (Handle old and new headers)
            vp_match = re.search(
                r"\*\*Vulnerability Pattern \(.*?\):\*\*(.*?)(?=\*\*Secure Pattern|\[\[|\Z)",
                doc,
                re.DOTALL,
            )
            sp_match = re.search(
                r"\*\*Secure Pattern \(.*?\):\*\*(.*?)(?=\[\[|\Z)", doc, re.DOTALL
            )

            gen_vp = vp_match.group(1).strip() if vp_match else ""
            gen_sp = sp_match.group(1).strip() if sp_match else ""

            # 2. Extract Language-Specific Patterns
            lang_vp = ""
            lang_sp = ""
            if target_lang != "GENERIC":
                lang_header = f"[[{target_lang} PATTERNS]]"
                lang_match = re.search(
                    re.escape(lang_header) + r"(.*?)(?=\[\[|\Z)", doc, re.DOTALL
                )
                if lang_match:
                    lang_block = lang_match.group(1)
                    # Extract Vulnerable/Secure code blocks within the language section
                    # Format: Vulnerable:\n```\n...\n```\nSecure:\n```\n...\n```
                    lvp = re.search(r"Vulnerable:\s*```(.*?)```", lang_block, re.DOTALL)
                    lsp = re.search(r"Secure:\s*```(.*?)```", lang_block, re.DOTALL)

                    if lvp:
                        lang_vp = lvp.group(1).strip()
                    if lsp:
                        lang_sp = lsp.group(1).strip()

            # 3. Prioritize: Use Language specific if available, else Generic
            final_vp = lang_vp if lang_vp else gen_vp
            final_sp = lang_sp if lang_sp else gen_sp

            if final_vp:
                vulnerability_patterns.append(final_vp)
            if final_sp:
                secure_patterns.append(final_sp)

    vulnerability_patterns_str = (
        "\n- ".join(vulnerability_patterns)
        if vulnerability_patterns
        else "No specific vulnerability patterns found."
    )
    secure_patterns_str = (
        "\n- ".join(secure_patterns)
        if secure_patterns
        else "No specific secure patterns found."
    )

    async with AsyncSessionLocal() as db:
        prompt_repo = PromptTemplateRepository(db)
        prompt_template = await prompt_repo.get_template_by_name_and_type(
            agent_name, template_type
        )

    if not prompt_template:
        return {
            "error": f"No prompt template found for agent '{agent_name}' with type '{template_type}'."
        }

    domain_scoping_instruction = f"You are an expert security auditor specializing in the following domain: '{agent_description}'. Your sole focus is on vulnerabilities related to this domain. Do not report findings outside of this specific scope. IMPORTANT: If you suggest a fix, the 'fix' code MUST be different from the original code. Do not return a 'fix' that is identical to the source. If the provided code snippet lacks sufficient context to confidently identify a vulnerability or generate a correct fix, skip it rather than guessing. PRESERVE COMMENTS: When generating a fix, you MUST preserve all existing comments unless they pose a security risk. SCAN COMMENTS: Pay special attention to comments for hardcoded secrets, TODOs indicating security flaws, or sensitive data - these SHOULD be reported."

    prompt_text = (
        f"{domain_scoping_instruction}\n\n"
        + prompt_template.template_text.format(
            vulnerability_patterns=vulnerability_patterns_str,
            secure_patterns=secure_patterns_str,
            code_bundle=code_bundle,
        )
    )

    logger.debug(f"[{agent_name}] Final prompt_text:\n{prompt_text}")

    llm_config_id = state.get("llm_config_id")
    if not llm_config_id:
        return {"error": f"[{agent_name}] LLM configuration ID not provided."}

    llm_client = await get_llm_client(llm_config_id=llm_config_id)
    if not llm_client:
        return {"error": f"[{agent_name}] Failed to initialize LLM client."}

    llm_response = await llm_client.generate_structured_output(
        prompt_text, response_model
    )

    # ... logging logic ...
    parsed_output_dict = (
        llm_response.parsed_output.model_dump() if llm_response.parsed_output else None
    )
    prompt_context_for_log = {
        "code_bundle_length": len(code_bundle),
        "vulnerability_patterns_length": len(vulnerability_patterns_str),
        "secure_patterns_length": len(secure_patterns_str),
    }
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
        return {
            "error": f"[{agent_name}] LLM failed to produce valid analysis: {llm_response.error}"
        }

    final_findings: List[VulnerabilityFinding] = []
    final_fixes: List[FixResult] = []
    initial_results = cast(InitialAnalysisResponse, llm_response.parsed_output)

    for initial_finding in initial_results.findings:
        cwe = await _get_cwe_from_description(llm_client, initial_finding)

        cvss_score = None
        try:
            cvss_score = cvss.CVSS3(initial_finding.cvss_vector).base_score
        except Exception as e:
            logger.warning(
                f"[{agent_name}] Failed to parse CVSS vector '{initial_finding.cvss_vector}': {e}"
            )

        finding_obj = VulnerabilityFinding(
            cwe=cwe or "CWE-Unknown",
            title=initial_finding.title,
            description=initial_finding.description,
            severity=initial_finding.severity,
            line_number=initial_finding.line_number,
            remediation=initial_finding.remediation,
            confidence=initial_finding.confidence,
            references=initial_finding.references,
            file_path=filename,
            agent_name=agent_name,
            cvss_vector=initial_finding.cvss_vector,
            cvss_score=float(cvss_score) if cvss_score is not None else None,
        )

        if workflow_mode == "remediate" and initial_finding.fix:
            # --- STRICT DIFF CHECK ---
            if (
                initial_finding.fix.code.strip()
                == initial_finding.fix.original_snippet.strip()
            ):
                logger.warning(
                    f"[{agent_name}] Discarding fix for {initial_finding.title} because the suggested fix is identical to the original snippet."
                )
                continue
            # --- END STRICT DIFF CHECK ---

            code_for_verification = state.get("file_content_for_verification")
            verified_suggestion = await _verify_and_correct_snippet(
                llm_client=llm_client,
                code_to_search=code_for_verification or "",
                suggestion=initial_finding.fix,
            )
            if verified_suggestion:
                finding_obj.fixes = verified_suggestion
                final_fixes.append(
                    FixResult(finding=finding_obj, suggestion=verified_suggestion)
                )
            else:
                logger.warning(
                    f"[{agent_name}] Discarding fix for CWE {cwe} in {filename} due to snippet verification failure."
                )

        final_findings.append(finding_obj)

    logger.info(
        f"[{agent_name}] Completed analysis for '{filename}'. Findings: {len(final_findings)}, Fixes: {len(final_fixes)}"
    )
    return {"findings": final_findings, "fixes": final_fixes}


async def _verify_and_correct_snippet(
    llm_client: LLMClient, code_to_search: str, suggestion: FixSuggestion
) -> Optional[FixSuggestion]:
    # ... This function remains the same as before ...
    original_snippet = suggestion.original_snippet
    for attempt in range(4):  # 1 initial try + 3 retries
        if original_snippet in code_to_search:
            suggestion.original_snippet = (
                original_snippet  # Ensure the latest version is set
            )
            return suggestion

        if attempt == 3:
            break  # Failed last attempt

        logger.warning(
            f"Snippet not found. Retrying with LLM correction (Attempt {attempt + 1}/3)."
        )
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
            correction_result = await llm_client.generate_structured_output(
                correction_prompt, CorrectedSnippet
            )
            if isinstance(correction_result.parsed_output, CorrectedSnippet):
                original_snippet = (
                    correction_result.parsed_output.corrected_original_snippet
                )
                logger.info(
                    f"Received corrected snippet from LLM: '{original_snippet[:60]}...'"
                )
            else:
                logger.warning(
                    "LLM failed to provide a corrected snippet on this attempt."
                )
        except Exception as e:
            logger.error(f"Error during LLM snippet correction: {e}")

    return None


def build_generic_specialized_agent_graph():
    """Builds the simplified, single-step graph for any specialized agent."""
    workflow = StateGraph(SpecializedAgentState)
    workflow.add_node("analysis_node", analysis_node)  # type: ignore
    workflow.set_entry_point("analysis_node")
    workflow.add_edge("analysis_node", END)
    return workflow.compile()
