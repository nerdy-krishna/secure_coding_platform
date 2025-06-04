import logging
import json
import re
from typing import TypedDict, List, Optional, Dict, Any

from langgraph.graph import StateGraph, END
from ..llm.llm_client import get_llm_client
from ..llm.providers import LLMResult
from ..db.crud import save_llm_interaction  # For logging LLM calls
from ..utils.cost_estimation import estimate_openai_cost  # For estimating cost


# Assuming a common SecurityAgentState definition or defining it if specific
# This should match the one used by ValidationAgent and expected by worker_graph
class SecurityAgentState(TypedDict):
    submission_id: int
    code_snippet: str
    language: str
    filename: str  # For context in logging and agent
    framework: Optional[str]
    task_context: Optional[Dict[str, Any]]  # Context from CoordinatorAgent
    findings: Optional[List[Dict[str, Any]]]
    fixed_code_snippet: Optional[str]
    explanation: Optional[str]
    error: Optional[str]
    asvs_mapping: Optional[List[Dict[str, str]]]
    cwe_mapping: Optional[List[Dict[str, str]]]


logger = logging.getLogger(__name__)

# --- Constants for ASVS V1 Architecture (from collated_code.txt) ---
ASVS_V1_GUIDELINES = """
V1.1 Secure Software Development Lifecycle:
    - Verify use of secure software development lifecycle
    - Verify threat modeling for all design changes
    - Verify secure design principles are applied
    - Verify security is addressed throughout all lifecycle phases

V1.2 Authentication Architecture:
    - Verify centralized authentication mechanisms
    - Verify decoupling of authentication logic
    - Verify components are properly separated
    - Verify authentication is secure by design

V1.3 Session Management Architecture:
    - Verify server-side session management
    - Verify secure session handling techniques
    - Verify protection against session attacks

V1.4 Access Control Architecture:
    - Verify principle of least privilege
    - Verify "deny by default" is applied
    - Verify access control failures are logged
    - Verify secure handling of access control decisions

V1.5 Input and Output Architecture:
    - Verify input validation and output encoding
    - Verify encoding and escaping are appropriate
    - Verify defense in depth for sensitive operations
    - Verify parameterized interfaces where possible

V1.6 Cryptographic Architecture:
    - Verify cryptographic module is used for sensitive operations
    - Verify no sensitive data in logs/cache
    - Verify cryptographic keys are securely managed
    - Verify secrets are properly protected

V1.7 Error, Logging, and Auditing Architecture:
    - Verify centralized error handling
    - Verify no sensitive data in logs
    - Verify appropriate logging for security events
    - Verify consistent time source for logs

V1.8 Data Protection and Privacy Architecture:
    - Verify sensitive data properly classified
    - Verify data minimization techniques
    - Verify proper controls for sensitive data
    - Verify compliance with privacy regulations

V1.9 Communications Architecture:
    - Verify encrypted communications for sensitive data
    - Verify proper use of TLS
    - Verify secure channel setup

V1.10 Malicious Software Architecture:
    - Verify upload validation and handling
    - Verify virus scanning or sandboxing
    - Verify prevention of code execution

V1.11 Business Logic Architecture:
    - Verify business logic flows prevent exploitation
    - Verify proper sequence enforcement
    - Verify protection against business logic attacks

V1.12 Secure File Upload Architecture:
    - Verify secure file handling
    - Verify validation of uploaded content
    - Verify secure storage of uploads

V1.14 Configuration Architecture:
    - Verify secure application deployment
    - Verify automated security check during build
    - Verify secure and repeatable environments
"""  # Combined citation for the guideline block

ARCHITECTURE_CWE_MAP = {
    "missing authentication": "CWE-306",
    "improper authentication": "CWE-287",
    "authorization bypass": "CWE-285",
    "broken access control": "CWE-284",
    "sensitive data exposure": "CWE-200",
    "insufficient cryptography": "CWE-327",
    "hardcoded secrets": "CWE-798",
    "misplaced trust": "CWE-501",  # Trust Boundary Violation
    "insecure components": "CWE-1104",  # Use of Unmaintained Third Party Components
    "insufficient logging": "CWE-778",
    "insecure design": "CWE-657",  # Violation of Secure Design Principles
    "cross-site scripting": "CWE-79",  # Often an output/design issue
    "sql injection": "CWE-89",  # Can be an architectural flaw if not using proper data access layers
    "path traversal": "CWE-22",
    "security misconfiguration": "CWE-16",  # More generic, was CWE-1021 in agent, use broader one
}


# --- Helper Functions (similar to ValidationAgent) ---
def _extract_json_from_llm_response(
    response_text: str,
) -> Optional[List[Dict[Any, Any]]]:
    if not response_text:
        return None
    try:
        match = re.search(r"(\[[\s\S]*\])", response_text)
        if match:
            return json.loads(match.group(1))
        match_obj = re.search(r"(\{[\s\S]*\})", response_text)
        if match_obj:
            loaded_json = json.loads(match_obj.group(1))
            if isinstance(loaded_json, list):
                return loaded_json
            elif (
                isinstance(loaded_json, dict)
                and "findings" in loaded_json
                and isinstance(loaded_json["findings"], list)
            ):
                return loaded_json["findings"]
            else:
                logger.warning(
                    "LLM returned a single JSON object for findings, expected array. Wrapping it."
                )
                return [loaded_json]
    except json.JSONDecodeError as e:
        logger.error(
            f"JSONDecodeError in _extract_json_from_llm_response (ArchitectureAgent): {e}. Response: {response_text[:500]}"
        )
    return None


def _identify_cwe_mappings(findings: List[Dict[str, Any]]) -> List[Dict[str, str]]:
    cwe_mappings = []
    for finding in findings:
        description = finding.get("description", "").lower()
        recommendation = finding.get("recommendation", "").lower()
        text_to_check = description + " " + recommendation
        mapped_cwe = False
        for keyword, cwe_id in ARCHITECTURE_CWE_MAP.items():
            if keyword in text_to_check:
                cwe_mappings.append(
                    {"description": finding.get("description", ""), "cwe_id": cwe_id}
                )
                mapped_cwe = True
                break
        if not mapped_cwe:
            logger.debug(
                f"No direct CWE keyword match for architecture finding: {description}"
            )
    return cwe_mappings


# --- Node Functions ---


async def assess_vulnerabilities_node(state: SecurityAgentState) -> Dict[str, Any]:
    submission_id = state["submission_id"]
    filename = state["filename"]
    code_snippet = state["code_snippet"]
    language = state["language"]
    framework = state.get("framework")
    task_context = state.get("task_context", {})  # Kept
    agent_name_for_logging = "ArchitectureAgent_Assess"

    logger.info(
        f"ArchitectureAgent Node: assess_vulnerabilities for '{filename}' (Submission: {submission_id})"
    )

    if not code_snippet:
        return {"findings": [], "error": "Missing code snippet for ArchitectureAgent."}

    asvs_guidance_for_prompt = (
        ASVS_V1_GUIDELINES  # Already defined in your existing file
    )

    # The _identify_architecture_patterns helper was in your original collated_code.txt for this agent.
    # We can call it here if its output is useful for the prompt. For now, assuming it's for broader context.
    # architecture_info = _identify_architecture_patterns(code_snippet, language) # You might use this
    # arch_type = architecture_info["architecture_type"]
    # detected_patterns = architecture_info["detected_patterns"]
    # components = architecture_info["components"]
    # architecture_context_from_detection = f"\nDetected architectural pattern: {arch_type}. Indicators: {', '.join(detected_patterns)}. Components: {', '.join(components[:5])}..." if arch_type != "Unknown" else ""

    framework_context_str = f"The code is in {language}."
    if framework:
        framework_context_str += f" It appears to use the {framework} framework."

    trigger_context_str = ""
    expected_trigger_area = "V1_Architecture"
    if task_context:
        trigger_area = task_context.get("triggering_area")
        if trigger_area and expected_trigger_area in trigger_area:
            likelihood = task_context.get("likelihood_from_context_analysis", "N/A")
            evidence = task_context.get("evidence_from_context_analysis", "N/A")
            key_elements_ctx = task_context.get(
                "key_elements_from_context_analysis", []
            )
            trigger_context_str = (
                f"\nInitial analysis for '{expected_trigger_area}' (this agent's focus) suggests relevance is '{likelihood}'. "
                f"Initial evidence: '{evidence}'. Key elements highlighted: {key_elements_ctx}. "
                f"Please verify and conduct a detailed assessment for architectural vulnerabilities based on this context."
            )
        elif trigger_area:
            trigger_context_str = f"\nBroader context: Initial analysis highlighted '{trigger_area}' with likelihood '{task_context.get('likelihood_from_context_analysis', 'N/A')}' as relevant for this file. Consider this while focusing on its architecture."
        # Add specific architecture info if available in task_context
        if task_context.get(
            "architecture_type_from_context"
        ):  # e.g. "microservice", "monolith"
            trigger_context_str += f"\nContextual hint on architecture type: {task_context.get('architecture_type_from_context')}"

    prompt = f"""
    Analyze the following {language} code snippet from file '{filename}' for security vulnerabilities related to OWASP ASVS V1 (Architecture, Design and Threat Modeling).
    {framework_context_str}
    {trigger_context_str}
    Focus on identifying flaws in the overall structure, component interactions, trust boundaries, tier separation, and adherence to secure design principles (like centralized auth/access control, defense in depth). Consider how this specific code snippet contributes to or violates secure architectural patterns.

    Refer to these ASVS V1 Guidelines:
    {asvs_guidance_for_prompt}

    Code Snippet:
    ```{language}
    {code_snippet}
    ```

    Task:
    1. Identify specific architectural vulnerabilities evident in or implied by this snippet.
    2. For each vulnerability found, provide:
        - "description": A concise description of the architectural weakness.
        - "severity": Estimated severity (High, Medium, Low).
        - "line_start": Approximate starting line number (or "N/A" if purely architectural and not tied to specific lines in this snippet).
        - "line_end": Approximate ending line number (or "N/A").
        - "recommendation": A specific recommendation for fixing the architectural vulnerability. This might involve changes to this snippet or broader system design changes.
        - "asvs_id": The primary ASVS V1 requirement ID it violates (e.g., "V1.1.2", "V1.4.1").
    3. If no architectural vulnerabilities are found in this specific snippet, return an empty array.
    4. Return ONLY a valid JSON array of objects, where each object represents a single vulnerability.
    """
    llm = get_llm_client()
    llm_result: Optional[LLMResult] = None
    findings_output: Optional[List[Dict[Any, Any]]] = []
    error_output: Optional[str] = None

    try:
        llm_result = await llm.generate(prompt)
        if llm_result.status == "success" and llm_result.content:
            parsed_findings = _extract_json_from_llm_response(llm_result.content)
            if parsed_findings is not None:
                findings_output = parsed_findings
                logger.info(
                    f"ArchitectureAgent successfully assessed '{filename}', found {len(findings_output)} potential issues."
                )
            else:
                error_output = "Failed to parse JSON findings from LLM response for ArchitectureAgent assessment."
                logger.error(
                    f"{error_output} LLM raw response: {llm_result.content[:500]}"
                )
        else:
            error_output = (
                llm_result.error
                or "LLM call failed or returned no content for ArchitectureAgent assessment."
            )
            logger.error(
                f"ArchitectureAgent assessment LLM call failed for '{filename}': {error_output}"
            )

    except Exception as e:
        logger.exception(
            f"Exception during ArchitectureAgent assessment for '{filename}': {e}"
        )
        error_output = f"Exception during assessment: {str(e)}"
        if llm_result is None:
            llm_result = LLMResult(status="failed", error=error_output)
        elif llm_result.status != "failed":
            llm_result.status = "failed"
            llm_result.error = error_output

    if llm_result:
        cost = estimate_openai_cost(
            model_name=llm_result.model_name,
            input_tokens=llm_result.input_tokens,
            output_tokens=llm_result.output_tokens,
        )
        await save_llm_interaction(
            submission_id=submission_id,
            agent_name=agent_name_for_logging,
            prompt=prompt,
            result=llm_result,
            estimated_cost=cost,
            status="failed" if error_output else "success",
            error_message=error_output,
            interaction_context={
                "filename": filename,
                "agent_task_context": task_context,
            },
        )

    return {"findings": findings_output, "error": error_output}


async def generate_fixes_node(state: SecurityAgentState) -> Dict[str, Any]:
    submission_id = state["submission_id"]
    filename = state["filename"]
    code_snippet = state["code_snippet"]
    language = state["language"]
    findings = state.get("findings") or []
    task_context = state.get(
        "task_context", {}
    )  # For additional context if needed for fixes
    agent_name_for_logging = "ArchitectureAgent_Fix"

    logger.info(
        f"ArchitectureAgent Node: generate_fixes for '{filename}' (Submission: {submission_id})"
    )

    if not findings:
        return {
            "fixed_code_snippet": code_snippet,
            "explanation": "No architectural vulnerabilities were identified in this snippet to provide specific code fixes. Architectural changes often require broader context beyond this snippet.",
            "error": None,
        }

    issues_json = json.dumps(findings, indent=2)

    architecture_type_context = ""
    if task_context and task_context.get(
        "file_summary_from_context_analysis"
    ):  # From Coordinator's context
        architecture_type_context = f"The code is part of a system described as: {task_context.get('file_summary_from_context_analysis')}."

    prompt = f"""
    The following {language} code snippet from file '{filename}' has been identified with architectural weaknesses.
    {architecture_type_context}
    Your task is to provide specific improvements to THIS SNIPPET if possible to mitigate the issues, or provide clear guidance on how this snippet should be refactored or how it relates to broader necessary architectural changes.

    Original Code Snippet:
    ```{language}
    {code_snippet}
    ```

    Identified Architectural Vulnerabilities (related to this snippet or its role):
    {issues_json}

    Instructions:
    1.  Review the original code and the identified vulnerabilities.
    2.  If direct fixes can be made to THIS snippet to improve its role within a secure architecture (e.g., better encapsulation, reduced coupling to sensitive components, adherence to specific design patterns suggested by findings), provide the "fixed_code".
    3.  If the primary issues require changes outside this specific snippet (e.g., implementing a centralized authentication service, redesigning data flows, introducing new security components), clearly explain these broader architectural changes in the "explanation". In such cases, the "fixed_code" for this snippet might remain largely unchanged or show only minor adjustments reflecting its new role or interface.
    4.  The "explanation" should clearly state what was changed in the snippet (if anything) and outline any necessary broader architectural changes with justifications.
    5.  Return ONLY a single valid JSON object with two keys: "fixed_code" (string, the modified snippet or original if no direct change was suitable for this isolated snippet) and "explanation" (string).
    """

    llm = get_llm_client()
    llm_result: Optional[LLMResult] = None
    fixed_code_output = code_snippet
    explanation_output = "Fix generation for architectural issues failed or was not applicable to this specific snippet without broader context."
    error_output: Optional[str] = None
    parsed_fix_object: Optional[Dict[str, str]] = None

    try:
        llm_result = await llm.generate(prompt)
        if llm_result.status == "success" and llm_result.content:
            try:
                parsed_fix_object = json.loads(llm_result.content)
                if not (
                    isinstance(parsed_fix_object, dict)
                    and "fixed_code" in parsed_fix_object
                    and "explanation" in parsed_fix_object
                ):
                    parsed_fix_object = None
            except json.JSONDecodeError:
                parsed_fix_object = None

            if parsed_fix_object is None and llm_result.content:
                match = re.search(
                    r"(\{\s*\"fixed_code\":[\s\S]*,\s*\"explanation\":[\s\S]*\s*\})",
                    llm_result.content,
                    re.DOTALL,
                )
                if match:
                    try:
                        parsed_fix_object = json.loads(match.group(1))
                    except json.JSONDecodeError as e_inner:
                        logger.error(
                            f"Failed to parse extracted JSON for architecture fix: {e_inner}"
                        )

            if (
                parsed_fix_object
                and "fixed_code" in parsed_fix_object
                and "explanation" in parsed_fix_object
            ):
                fixed_code_output = parsed_fix_object["fixed_code"]
                explanation_output = parsed_fix_object["explanation"]
                logger.info(
                    f"ArchitectureAgent successfully generated fix/guidance for '{filename}'."
                )
            else:
                error_output = "Failed to parse 'fixed_code' and 'explanation' from LLM response for ArchitectureAgent fix."
                logger.error(
                    f"{error_output} LLM raw response: {llm_result.content[:500]}"
                )
                explanation_output = error_output
        else:
            error_output = (
                llm_result.error
                or "LLM call failed or returned no content for ArchitectureAgent fix."
            )
            logger.error(
                f"ArchitectureAgent fix LLM call failed for '{filename}': {error_output}"
            )
            explanation_output = error_output

    except Exception as e:
        logger.exception(
            f"Exception during ArchitectureAgent fix generation for '{filename}': {e}"
        )
        error_output = f"Exception during fix generation: {str(e)}"
        explanation_output = error_output
        if llm_result is None:
            llm_result = LLMResult(status="failed", error=error_output)
        elif llm_result.status != "failed":
            llm_result.status = "failed"
            llm_result.error = error_output

    if llm_result:
        cost = estimate_openai_cost(
            model_name=llm_result.model_name,
            input_tokens=llm_result.input_tokens,
            output_tokens=llm_result.output_tokens,
        )
        await save_llm_interaction(
            submission_id=submission_id,
            agent_name=agent_name_for_logging,
            prompt=prompt,
            result=llm_result,
            estimated_cost=cost,
            status="failed" if error_output else "success",
            error_message=error_output,
            interaction_context={
                "filename": filename,
                "findings_sent_for_fix": findings,
            },
        )

    return {
        "fixed_code_snippet": fixed_code_output,
        "explanation": explanation_output,
        "error": error_output,
    }


async def map_to_standards_node(state: SecurityAgentState) -> Dict[str, Any]:
    findings = state.get("findings") or []
    logger.info(
        f"ArchitectureAgent Node: map_to_standards for '{state['filename']}' (Submission: {state['submission_id']})"
    )

    asvs_mappings = []
    if findings:
        for finding in findings:
            asvs_id = finding.get("asvs_id")
            if asvs_id:
                asvs_mappings.append(
                    {"description": finding.get("description", ""), "asvs_id": asvs_id}
                )
            else:
                logger.warning(
                    f"Finding in ArchitectureAgent for '{state['filename']}' is missing 'asvs_id': {finding.get('description')}"
                )

    cwe_mappings = _identify_cwe_mappings(findings)
    logger.info(
        f"Mapped {len(cwe_mappings)} findings to CWEs for ArchitectureAgent on '{state['filename']}'."
    )

    return {
        "asvs_mapping": asvs_mappings,
        "cwe_mapping": cwe_mappings,
        "error": state.get("error"),  # Pass through
    }


# --- Graph Construction ---
def build_architecture_agent_graph() -> Any:
    graph = StateGraph(SecurityAgentState)
    graph.add_node("assess_vulnerabilities", assess_vulnerabilities_node)
    graph.add_node("generate_fixes", generate_fixes_node)
    graph.add_node("map_to_standards", map_to_standards_node)

    graph.set_entry_point("assess_vulnerabilities")
    graph.add_edge("assess_vulnerabilities", "generate_fixes")
    graph.add_edge("generate_fixes", "map_to_standards")
    graph.add_edge("map_to_standards", END)

    compiled_graph = graph.compile()
    logger.info("ArchitectureAgent graph compiled successfully.")
    return compiled_graph
