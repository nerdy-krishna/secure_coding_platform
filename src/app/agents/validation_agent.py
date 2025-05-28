import logging
import json
import re
from typing import TypedDict, List, Optional, Dict, Any

from langgraph.graph import StateGraph, END
from ..llm.llm_client import get_llm_client
from ..llm.providers import LLMResult
from ..db.crud import save_llm_interaction
from ..utils.cost_estimation import estimate_openai_cost


# SecurityAgentState is expected to be defined in a common place or passed correctly.
# For now, let's redefine it here if it's specific to these agents.
# If it's identical to the one in worker_graph, we can consider a common types file later.
class SecurityAgentState(TypedDict):
    submission_id: int  # Added for logging context
    code_snippet: str
    language: str
    filename: str  # Added for logging context and for the agent if needed
    framework: Optional[str]
    task_context: Optional[Dict[str, Any]]  # Context from CoordinatorAgent
    findings: Optional[List[Dict[str, Any]]]
    fixed_code_snippet: Optional[str]
    explanation: Optional[str]
    error: Optional[str]
    asvs_mapping: Optional[List[Dict[str, str]]]
    cwe_mapping: Optional[List[Dict[str, str]]]


logger = logging.getLogger(__name__)

# --- Constants for ASVS V5 Validation, Sanitization and Encoding ---
ASVS_V5_GUIDELINES = """
V5.1 Input Validation:
    - V5.1.1 Verify that all input is validated using positive validation (allow-lists).
    - V5.1.2 Verify that variable typing, range, length, and format are enforced on all inputs.
    - V5.1.3 Verify that all input data is validated on the server-side.
    - V5.1.4 Verify that structured data is strongly typed and validated against a defined schema.
    - V5.1.5 Verify that validation of untrusted data is based on the assumption that it is malicious.
    - V5.1.6 Verify that URL inputs are validated, e.g. to ensure they are mapped to an expected function rather than a file path.

V5.2 Sanitization and Sandboxing:
    - V5.2.1 Verify that output encoding is contextual and relevant for the output interpreter. (Moved to V5.3 but often related)
    - V5.2.2 Verify that untrusted HTML input is appropriately sanitized using a library or framework.
    - V5.2.3 Verify that URL redirects and forwards only allow whitelisted destinations, or show a warning.
    - V5.2.4 Verify that when user-supplied data is sent to an OS command, it is appropriately validated and shell metacharacters are escaped.
    - V5.2.5 Verify that when user-supplied data is used in SQL queries, it is appropriately validated and parameterized queries or ORMs are used.
    - V5.2.6 Verify that user-supplied data is appropriately validated and sanitized before being used in LDAP, XPath, NoSQL queries, or SMTP/IMAP commands.
    - V5.2.7 Verify that user-supplied data is appropriately validated before being used to create or interact with XML parsers, to prevent XXE.

V5.3 Output Encoding and Injection Prevention:
    - V5.3.1 Verify that context-aware output encoding is applied to user-controllable data.
    - V5.3.2 Verify that output encoding is applied just before the content is sent to the interpreter.
    - V5.3.3 Verify that data selection or database queries are not built by concatenating unsanitized user input.
    - V5.3.4 Verify that the application protects against reflected, stored, and DOM based XSS.
    - V5.3.5 Verify that HTTP responses have Content-Type headers that specify a secure character set (e.g., UTF-8).
    - V5.3.6 Verify that Content Security Policy (CSP) is used to mitigate XSS.

V5.4 Memory, String, and Unmanaged Code: (Less common for typical web app code, but good to keep)
    - V5.4.1 Verify that code uses secure memory copying and handling functions.
    - V5.4.2 Verify that buffer overflow protection mechanisms are used.
    - V5.4.3 Verify that code protects against user-supplied format strings.

V5.5 Deserialization Prevention:
    - V5.5.1 Verify that serialized objects use integrity checks or encryption if the content is sensitive.
    - V5.5.2 Verify that deserialization of untrusted data is avoided or protected.
    - V5.5.3 Verify that strict type constraints are applied during deserialization.
"""

VALIDATION_CWE_MAP = {
    "sql injection": "CWE-89",
    "xss": "CWE-79",
    "cross-site scripting": "CWE-79",
    "command injection": "CWE-77",  # Also CWE-78 for OS command injection
    "os command injection": "CWE-78",
    "insecure deserialization": "CWE-502",
    "xxe": "CWE-611",
    "path traversal": "CWE-22",
    "directory traversal": "CWE-22",
    "ldap injection": "CWE-90",
    "xpath injection": "CWE-91",  # Often overlaps with XML Injection
    "xml injection": "CWE-91",
    "missing validation": "CWE-20",
    "improper input validation": "CWE-20",
    "format string": "CWE-134",
    "nosql injection": "CWE-943",
    "unsafe redirect": "CWE-601",
    "open redirect": "CWE-601",
    "buffer overflow": "CWE-120",  # Generic, more specific ones exist
    "untrusted data": "CWE-20",
    "output encoding": "CWE-116",  # Improper Encoding or Escaping of Output
    "reflected xss": "CWE-79",
    "stored xss": "CWE-79",
    "dom xss": "CWE-79",
}

# Language-specific input handling and validation functions/libraries (condensed example)
INPUT_VALIDATION_PATTERNS = {
    "python": {
        "core": ["input(", "eval(", "exec("],
        "django": ["request.POST", "request.GET"],
        "flask": ["request.form", "request.args"],
    },
    "javascript": {
        "core": ["eval(", "innerHTML", "document.write("],
        "express": ["req.body", "req.query"],
    },
}


# --- Helper Functions ---
def _extract_json_from_llm_response(
    response_text: str,
) -> Optional[List[Dict[Any, Any]]]:
    if not response_text:
        return None
    try:
        # Try to find a JSON array directly
        match = re.search(r"(\[[\s\S]*\])", response_text)
        if match:
            return json.loads(match.group(1))

        # Fallback for object if array not found (though prompt asks for array)
        match_obj = re.search(r"(\{[\s\S]*\})", response_text)
        if match_obj:
            loaded_json = json.loads(match_obj.group(1))
            if isinstance(loaded_json, list):  # Should ideally be a list of findings
                return loaded_json
            elif (
                isinstance(loaded_json, dict)
                and "findings" in loaded_json
                and isinstance(loaded_json["findings"], list)
            ):
                return loaded_json["findings"]  # If LLM wrapped it
            else:  # If it's a single finding object, wrap it in a list
                logger.warning(
                    "LLM returned a single JSON object, expected array. Wrapping it."
                )
                return [loaded_json]

    except json.JSONDecodeError as e:
        logger.error(
            f"JSONDecodeError in _extract_json_from_llm_response: {e}. Response: {response_text[:500]}"
        )
    return None


def _identify_cwe_mappings(findings: List[Dict[str, Any]]) -> List[Dict[str, str]]:
    cwe_mappings = []
    for finding in findings:
        description = finding.get("description", "").lower()
        recommendation = finding.get("recommendation", "").lower()
        text_to_check = description + " " + recommendation
        mapped_cwe = False
        for keyword, cwe_id in VALIDATION_CWE_MAP.items():
            if keyword in text_to_check:
                cwe_mappings.append(
                    {"description": finding.get("description", ""), "cwe_id": cwe_id}
                )
                mapped_cwe = True
                break
        if not mapped_cwe:
            logger.debug(f"No direct CWE keyword match for finding: {description}")
    return cwe_mappings


# --- Node Functions ---


async def assess_vulnerabilities_node(state: SecurityAgentState) -> Dict[str, Any]:
    submission_id = state["submission_id"]
    filename = state["filename"]
    code_snippet = state["code_snippet"]
    language = state["language"]
    framework = state.get("framework")
    task_context = state.get("task_context", {})  # Kept
    agent_name_for_logging = "ValidationAgent_Assess"

    logger.info(
        f"ValidationAgent Node: assess_vulnerabilities for '{filename}' (Submission: {submission_id})"
    )

    if not code_snippet:
        return {"findings": [], "error": "Missing code snippet for ValidationAgent."}

    asvs_guidance_for_prompt = ASVS_V5_GUIDELINES  # Defined in your existing agent file

    # Using INPUT_VALIDATION_PATTERNS (defined in your existing agent file)
    lang_patterns = INPUT_VALIDATION_PATTERNS.get(language.lower(), {})
    core_patterns = lang_patterns.get("core", [])
    framework_patterns = (
        lang_patterns.get(framework.lower(), [])
        if framework and framework.lower() in lang_patterns
        else []
    )
    relevant_patterns = list(set(core_patterns + framework_patterns))
    pattern_context_str = ""
    if relevant_patterns:
        detected_patterns_in_code = [
            p
            for p in relevant_patterns
            if re.search(
                r"\b" + re.escape(p).replace("\\*", ".*") + r"\b",
                code_snippet,
                re.IGNORECASE,
            )
        ]
        if detected_patterns_in_code:
            pattern_context_str = f"The code may use input/output handling patterns like: {', '.join(detected_patterns_in_code[:5])}. Focus on whether these are used securely."

    framework_context_str = f"The code is in {language}."
    if framework:
        framework_context_str += f" It seems to use the {framework} framework. Consider its specific validation/sanitization/encoding utilities."

    trigger_context_str = ""
    expected_trigger_area = "V5_Validation"
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
                f"Please verify and conduct a detailed assessment for validation, sanitization, and encoding vulnerabilities based on this context."
            )
        elif trigger_area:
            trigger_context_str = f"\nBroader context: Initial analysis highlighted '{trigger_area}' with likelihood '{task_context.get('likelihood_from_context_analysis', 'N/A')}' as relevant for this file. Consider this while focusing on validation, sanitization, and encoding."

    prompt = f"""
    Analyze the following {language} code snippet from file '{filename}' for security vulnerabilities related to OWASP ASVS V5 (Validation, Sanitization, and Encoding).
    {framework_context_str}
    {pattern_context_str}
    {trigger_context_str}
    Focus on identifying issues such as Cross-Site Scripting (XSS - reflected, stored, DOM), SQL Injection, Command Injection, Path Traversal, Unsafe Deserialization, missing or improper input validation (type, length, format, business rules), inadequate output encoding for the context (HTML, JS, CSS, URL), and insecure memory handling if applicable.

    Refer to these ASVS V5 Guidelines:
    {asvs_guidance_for_prompt}

    Code Snippet:
    ```{language}
    {code_snippet}
    ```

    Task:
    1. Identify specific vulnerabilities related to input validation, sanitization, output encoding, deserialization, or memory handling.
    2. For each vulnerability found, provide:
        - "description": A concise description of the weakness (e.g., "Reflected XSS due to unsanitized 'query' parameter in HTML output.").
        - "severity": Estimated severity (High, Medium, Low).
        - "line_start": Approximate starting line number of the vulnerable code.
        - "line_end": Approximate ending line number.
        - "recommendation": A specific recommendation for fixing the vulnerability (e.g., "Encode 'query' parameter using HTML entity encoding before rendering.", "Use parameterized queries instead of string concatenation for SQL.").
        - "asvs_id": The primary ASVS V5 requirement ID it violates (e.g., "V5.1.3", "V5.3.4", "V5.5.2").
    3. If no such vulnerabilities are found in this snippet, return an empty array.
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
                    f"ValidationAgent successfully assessed '{filename}', found {len(findings_output)} potential issues."
                )
            else:
                error_output = "Failed to parse JSON findings from LLM response for ValidationAgent assessment."
                logger.error(
                    f"{error_output} LLM raw response: {llm_result.content[:500]}"
                )
        else:
            error_output = (
                llm_result.error
                or "LLM call failed or returned no content for ValidationAgent assessment."
            )
            logger.error(
                f"ValidationAgent assessment LLM call failed for '{filename}': {error_output}"
            )

    except Exception as e:
        logger.exception(
            f"Exception during ValidationAgent assessment for '{filename}': {e}"
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
    agent_name_for_logging = "ValidationAgent_Fix"

    logger.info(
        f"ValidationAgent Node: generate_fixes for '{filename}' (Submission: {submission_id})"
    )

    if not findings:
        return {
            "fixed_code_snippet": code_snippet,
            "explanation": "No validation vulnerabilities were identified to fix.",
            "error": None,
        }

    issues_json = json.dumps(findings, indent=2)
    prompt = f"""
    The following {language} code snippet from file '{filename}' has validation, sanitization, or encoding vulnerabilities.
    Your task is to provide a fixed version of the code and an explanation of the fixes.

    Original Code Snippet:
    ```{language}
    {code_snippet}
    ```

    Identified Vulnerabilities:
    {issues_json}

    Instructions:
    1.  Review the original code and vulnerabilities.
    2.  Provide a complete, fixed version of the code snippet addressing ALL listed vulnerabilities.
        Focus on applying secure coding practices:
        - For Input Validation: Implement strict type, length, format, and range checks. Use allow-lists where possible.
        - For SQL Injection: Use parameterized queries or ORM methods that inherently prevent SQLi.
        - For XSS: Apply context-aware output encoding (e.g., HTML entity encoding for HTML context, JavaScript escaping for script context, URL encoding for URL parameters). Use appropriate libraries or framework features if available.
        - For Command Injection: Avoid direct OS command execution with user input. If unavoidable, use structured APIs that handle argument separation and strictly validate/sanitize all inputs.
        - For Path Traversal: Canonicalize paths (e.g., using `os.path.abspath`) and ensure they are within an allowed base directory. Validate all parts of user-supplied path components.
        - For Unsafe Deserialization: Avoid deserializing untrusted data. If necessary, use safer serialization formats or implement strict type checking and integrity verification during deserialization.
    3.  After the fixed code, provide a brief, clear "explanation" of key changes and why they improve security, referencing the types of vulnerabilities addressed.
    4.  Return ONLY a single valid JSON object with two keys: "fixed_code" (string) and "explanation" (string).
    """

    llm = get_llm_client()
    llm_result: Optional[LLMResult] = None
    fixed_code_output = code_snippet
    explanation_output = (
        "Fix generation for validation issues failed or was not applicable."
    )
    error_output: Optional[str] = None
    parsed_fix_object: Optional[Dict[str, str]] = (
        None  # To store the successfully parsed JSON object
    )

    try:
        llm_result = await llm.generate(prompt)
        if llm_result.status == "success" and llm_result.content:
            try:
                # Attempt to parse the entire content as JSON first
                parsed_fix_object = json.loads(llm_result.content)
                if not (
                    isinstance(parsed_fix_object, dict)
                    and "fixed_code" in parsed_fix_object
                    and "explanation" in parsed_fix_object
                ):
                    # If direct parse is a dict but not the right structure, try regex
                    parsed_fix_object = None  # Reset before trying regex
            except json.JSONDecodeError:
                parsed_fix_object = None  # Ensure it's None if direct parse fails

            if (
                parsed_fix_object is None and llm_result.content
            ):  # If direct parse failed or yielded wrong structure, try regex
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
                            f"Failed to parse extracted JSON for validation fix: {e_inner}"
                        )
                        # parsed_fix_object remains None

            if (
                parsed_fix_object
                and "fixed_code" in parsed_fix_object
                and "explanation" in parsed_fix_object
            ):
                fixed_code_output = parsed_fix_object["fixed_code"]
                explanation_output = parsed_fix_object["explanation"]
                logger.info(
                    f"ValidationAgent successfully generated fix for '{filename}'."
                )
            else:
                error_output = "Failed to parse 'fixed_code' and 'explanation' from LLM response for ValidationAgent fix."
                logger.error(
                    f"{error_output} LLM raw response: {llm_result.content[:500]}"
                )
                explanation_output = (
                    error_output  # Provide error in explanation if fix parsing failed
                )
        else:
            error_output = (
                llm_result.error
                or "LLM call failed or returned no content for ValidationAgent fix."
            )
            logger.error(
                f"ValidationAgent fix LLM call failed for '{filename}': {error_output}"
            )
            explanation_output = error_output

    except Exception as e:
        logger.exception(
            f"Exception during ValidationAgent fix generation for '{filename}': {e}"
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
        f"ValidationAgent Node: map_to_standards for '{state['filename']}' (Submission: {state['submission_id']})"
    )

    asvs_mappings = []
    if findings:
        for finding in findings:
            asvs_id = finding.get("asvs_id")
            if asvs_id:  # ASVS ID should already be in the finding from assessment node
                asvs_mappings.append(
                    {"description": finding.get("description", ""), "asvs_id": asvs_id}
                )
            else:
                logger.warning(
                    f"Finding in ValidationAgent for '{state['filename']}' is missing 'asvs_id': {finding.get('description')}"
                )

    cwe_mappings = _identify_cwe_mappings(findings)
    logger.info(
        f"Mapped {len(cwe_mappings)} findings to CWEs for ValidationAgent on '{state['filename']}'."
    )

    return {
        "asvs_mapping": asvs_mappings,  # ASVS mappings are implicitly from findings
        "cwe_mapping": cwe_mappings,
        "error": state.get("error"),  # Pass through any existing error
    }


# --- Graph Construction ---
def build_validation_agent_graph() -> Any:
    """Builds and returns the compiled LangGraph for the ValidationAgent."""
    graph = StateGraph(SecurityAgentState)

    graph.add_node("assess_vulnerabilities", assess_vulnerabilities_node)
    graph.add_node("generate_fixes", generate_fixes_node)
    graph.add_node("map_to_standards", map_to_standards_node)

    graph.set_entry_point("assess_vulnerabilities")
    graph.add_edge("assess_vulnerabilities", "generate_fixes")
    graph.add_edge("generate_fixes", "map_to_standards")
    graph.add_edge("map_to_standards", END)

    compiled_graph = graph.compile()
    logger.info("ValidationAgent graph compiled successfully.")
    return compiled_graph
