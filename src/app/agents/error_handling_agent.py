import logging
import json
import re
from typing import TypedDict, List, Optional, Dict, Any

from langgraph.graph import StateGraph, END
from ..llm.llm_client import get_llm_client
from ..llm.providers import LLMResult
from ..db.crud import save_llm_interaction
from ..utils.cost_estimation import estimate_openai_cost


class SecurityAgentState(TypedDict):
    submission_id: int
    code_snippet: str
    language: str
    filename: str
    framework: Optional[str]
    task_context: Optional[Dict[str, Any]]
    findings: Optional[List[Dict[str, Any]]]
    fixed_code_snippet: Optional[str]
    explanation: Optional[str]
    error: Optional[str]
    asvs_mapping: Optional[List[Dict[str, str]]]
    cwe_mapping: Optional[List[Dict[str, str]]]


logger = logging.getLogger(__name__)

# --- Constants for ASVS V7 Error Handling and Logging (from collated_code.txt) ---
ASVS_V7_GUIDELINES = """
V7.1 Log Content:
    - Verify application logs do not store sensitive data
    - Sanitize data before storing in logs (PII, credentials, payment details, tokens)
    - Ensure logs are in a format consumable by log management solutions
    - Include enough detail for forensic analysis and incident response

V7.2 Log Processing:
    - Verify logs are transmitted or stored securely
    - Verify all high-value transactions have audit trails
    - Verify log monitoring/analysis systems are in place
    - Ensure logs are protected from injection attacks

V7.3 Error Handling:
    - Verify generic error messages are returned to users (no sensitive info)
    - Verify exceptions are caught within security controls
    - Prevent debug information from leaking in production
    - Verify error handling logic denies access by default
    - Verify all API and controller methods handle exceptions properly
    - Implement centralized error handling architecture
"""

ERROR_HANDLING_CWE_MAP = {
    "information exposure": "CWE-209",  # Information Exposure Through an Error Message
    "sensitive data in logs": "CWE-532",  # Insertion of Sensitive Information into Log File
    "debug information leak": "CWE-489",  # Active Debug Code (leading to info leak)
    "stack trace exposure": "CWE-209",  # Often reveals stack traces
    "improper exception handling": "CWE-755",  # Improper Handling of Exceptional Conditions
    "uncaught exception": "CWE-248",
    "log injection": "CWE-117",  # Improper Output Neutralization for Logs
    "missing error handling": "CWE-391",  # Unchecked Error Condition
    "verbose errors": "CWE-209",
    "swallowed exception": "CWE-390",  # Detection of Error Condition Without Action
    "insufficient logging": "CWE-778",
}  # Adapted slightly


# --- Helper Functions ---
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
                    "LLM returned a single JSON object for findings (ErrorHandlingAgent), expected array. Wrapping it."
                )
                return [loaded_json]
    except json.JSONDecodeError as e:
        logger.error(
            f"JSONDecodeError in _extract_json_from_llm_response (ErrorHandlingAgent): {e}. Response: {response_text[:500]}"
        )
    return None


def _identify_cwe_mappings(findings: List[Dict[str, Any]]) -> List[Dict[str, str]]:
    cwe_mappings = []
    for finding in findings:
        description = finding.get("description", "").lower()
        recommendation = finding.get("recommendation", "").lower()
        text_to_check = description + " " + recommendation
        mapped_cwe = False
        for keyword, cwe_id in ERROR_HANDLING_CWE_MAP.items():
            if keyword in text_to_check:
                cwe_mappings.append(
                    {"description": finding.get("description", ""), "cwe_id": cwe_id}
                )
                mapped_cwe = True
                break
        if not mapped_cwe:
            logger.debug(
                f"No direct CWE keyword match for error handling finding: {description}"
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
    agent_name_for_logging = "ErrorHandlingAgent_Assess"

    logger.info(
        f"ErrorHandlingAgent Node: assess_vulnerabilities for '{filename}' (Submission: {submission_id})"
    )

    if not code_snippet:
        return {"findings": [], "error": "Missing code snippet for ErrorHandlingAgent."}

    asvs_guidance_for_prompt = ASVS_V7_GUIDELINES  # Defined in your existing agent file

    framework_context_str = f"The code is in {language}."
    if framework:
        framework_context_str += f" It might be using the {framework} framework. Consider {framework}-specific error handling (e.g., global exception handlers, logging configurations like log4j, logback, Python's logging module)."

    lang_specific_error_handling_keywords = {
        "python": "try, except, finally, raise, logging.error, traceback, sys.exc_info, assert",
        "java": "try, catch, finally, throw, throws, System.err.println, Logger.getLogger, slf4j",
        "javascript": "try, catch, finally, throw, console.error, window.onerror, Promise.catch",
        "php": "try, catch, finally, throw, trigger_error, error_log, set_error_handler, display_errors",
        "csharp": "try, catch, finally, throw, Debug.WriteLine, Trace.WriteLine, ILogger",
        "ruby": "begin, rescue, ensure, raise, logger.error, Rails.logger",
        "go": "if err != nil, panic, recover, log.Fatalf, errors.New",
    }
    error_pattern_context = ""
    keywords_for_lang = lang_specific_error_handling_keywords.get(language.lower(), [])
    if keywords_for_lang:
        detected_keywords = [
            kw
            for kw in keywords_for_lang.split(", ")
            if re.search(r"\b" + re.escape(kw) + r"\b", code_snippet)
        ]
        if detected_keywords:
            error_pattern_context = f"The code may use {language} error handling patterns like: {', '.join(list(set(detected_keywords[:5])))}. Check if they are used securely."

    trigger_context_str = ""
    expected_trigger_area = "V7_ErrorHandling"
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
                f"Please verify and conduct a detailed assessment for error handling and logging vulnerabilities based on this context."
            )
        elif trigger_area:
            trigger_context_str = f"\nBroader context: Initial analysis highlighted '{trigger_area}' with likelihood '{task_context.get('likelihood_from_context_analysis', 'N/A')}' as relevant for this file. Consider this while focusing on error handling and logging."

    prompt = f"""
    Analyze the following {language} code snippet from file '{filename}' for security vulnerabilities related to OWASP ASVS V7 (Error Handling and Logging).
    {framework_context_str}
    {error_pattern_context}
    {trigger_context_str}
    Focus on identifying issues like exposure of sensitive information (stack traces, system details, PII) in error messages or logs, missing or improper exception handling (e.g., swallowing exceptions, overly broad catch blocks), logging of sensitive data (credentials, session IDs, PII), lack of sufficient logging for security-relevant events (logins, failures, access control decisions), and potential for log injection.

    Refer to these ASVS V7 Guidelines:
    {asvs_guidance_for_prompt}

    Code Snippet:
    ```{language}
    {code_snippet}
    ```

    Task:
    1. Identify specific vulnerabilities related to error handling and logging.
    2. For each vulnerability found, provide:
        - "description": A concise description of the weakness (e.g., "Stack trace exposed to user on error", "Sensitive user ID logged in cleartext").
        - "severity": Estimated severity (High, Medium, Low).
        - "line_start": Approximate starting line number of the vulnerable code.
        - "line_end": Approximate ending line number.
        - "recommendation": A specific recommendation for fixing the vulnerability (e.g., "Implement a generic error page for users and log detailed errors internally.", "Mask or omit user ID from log messages.").
        - "asvs_id": The primary ASVS V7 requirement ID it violates (e.g., "V7.1.1", "V7.3.2").
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
                    f"ErrorHandlingAgent successfully assessed '{filename}', found {len(findings_output)} potential issues."
                )
            else:
                error_output = "Failed to parse JSON findings from LLM response for ErrorHandlingAgent assessment."
                logger.error(
                    f"{error_output} LLM raw response: {llm_result.content[:500]}"
                )
        else:
            error_output = (
                llm_result.error
                or "LLM call failed or returned no content for ErrorHandlingAgent assessment."
            )
            logger.error(
                f"ErrorHandlingAgent assessment LLM call failed for '{filename}': {error_output}"
            )

    except Exception as e:
        logger.exception(
            f"Exception during ErrorHandlingAgent assessment for '{filename}': {e}"
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
    agent_name_for_logging = "ErrorHandlingAgent_Fix"

    logger.info(
        f"ErrorHandlingAgent Node: generate_fixes for '{filename}' (Submission: {submission_id})"
    )

    if not findings:
        return {
            "fixed_code_snippet": code_snippet,
            "explanation": "No error handling or logging vulnerabilities were identified to fix.",
            "error": None,
        }

    issues_json = json.dumps(findings, indent=2)
    prompt = f"""
    The following {language} code snippet from file '{filename}' has error handling and logging vulnerabilities.
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
        Focus on implementing generic error messages for users while logging detailed error information (stack traces, context) securely on the server-side. Ensure sensitive data (like PII, credentials, tokens) is NOT logged or is appropriately masked/redacted. Implement specific exception handling rather than overly broad try-catch blocks where possible. Ensure security-relevant events are logged with sufficient detail.
    3.  After the fixed code, provide a brief, clear "explanation" of key changes and why they improve error handling and logging security.
    4.  Return ONLY a single valid JSON object with two keys: "fixed_code" (string) and "explanation" (string).
    """

    llm = get_llm_client()
    llm_result: Optional[LLMResult] = None
    fixed_code_output = code_snippet
    explanation_output = (
        "Fix generation for error handling/logging issues failed or was not applicable."
    )
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
                            f"Failed to parse extracted JSON for error handling fix: {e_inner}"
                        )

            if (
                parsed_fix_object
                and "fixed_code" in parsed_fix_object
                and "explanation" in parsed_fix_object
            ):
                fixed_code_output = parsed_fix_object["fixed_code"]
                explanation_output = parsed_fix_object["explanation"]
                logger.info(
                    f"ErrorHandlingAgent successfully generated fix for '{filename}'."
                )
            else:
                error_output = "Failed to parse 'fixed_code' and 'explanation' from LLM response for ErrorHandlingAgent fix."
                logger.error(
                    f"{error_output} LLM raw response: {llm_result.content[:500]}"
                )
                explanation_output = error_output
        else:
            error_output = (
                llm_result.error
                or "LLM call failed or returned no content for ErrorHandlingAgent fix."
            )
            logger.error(
                f"ErrorHandlingAgent fix LLM call failed for '{filename}': {error_output}"
            )
            explanation_output = error_output

    except Exception as e:
        logger.exception(
            f"Exception during ErrorHandlingAgent fix generation for '{filename}': {e}"
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
        f"ErrorHandlingAgent Node: map_to_standards for '{state['filename']}' (Submission: {state['submission_id']})"
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
                    f"Finding in ErrorHandlingAgent for '{state['filename']}' is missing 'asvs_id': {finding.get('description')}"
                )

    cwe_mappings = _identify_cwe_mappings(findings)
    logger.info(
        f"Mapped {len(cwe_mappings)} findings to CWEs for ErrorHandlingAgent on '{state['filename']}'."
    )

    return {
        "asvs_mapping": asvs_mappings,
        "cwe_mapping": cwe_mappings,
        "error": state.get("error"),
    }


# --- Graph Construction ---
def build_error_handling_agent_graph() -> (
    StateGraph
):  # Function name was incorrect in collated_code
    graph = StateGraph(SecurityAgentState)
    graph.add_node("assess_vulnerabilities", assess_vulnerabilities_node)
    graph.add_node("generate_fixes", generate_fixes_node)
    graph.add_node("map_to_standards", map_to_standards_node)

    graph.set_entry_point("assess_vulnerabilities")
    graph.add_edge("assess_vulnerabilities", "generate_fixes")
    graph.add_edge("generate_fixes", "map_to_standards")
    graph.add_edge("map_to_standards", END)

    compiled_graph = graph.compile()
    logger.info("ErrorHandlingAgent graph compiled successfully.")
    return compiled_graph
