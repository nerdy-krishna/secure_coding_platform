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

# --- Constants for ASVS V10 Code Integrity / Malicious Code (from collated_code.txt) ---
ASVS_V10_GUIDELINES = """
V10.1 Code Integrity Controls:
    - Verify that a code analysis tool is in use to detect potentially malicious code
    - Verify that all malicious activity is adequately sandboxed/isolated
    - Verify that the application source code and libraries don't contain backdoors
    - Verify that the application doesn't request unnecessary permissions
    - Verify that no sensitive data is sent to external systems without user approval

V10.2 Malicious Code Search:
    - Check for time bombs, logic bombs, backdoors, trojan code
    - Verify code is free from unauthorized code obfuscation or encoding
    - Search for potentially malicious code like eval(), system calls with untrusted input
    - Identify code that might evade security controls
    - Detect suspicious dependencies or unexpected network connections

V10.3 Application Integrity:
    - Verify digital signatures or checksums for critical resources
    - Ensure secure update mechanisms
    - Protect against dependency confusion or supply chain attacks
    - Implement runtime protection against tampering
    - Ensure the application doesn't download untrusted code
"""

CODE_INTEGRITY_CWE_MAP = {
    "backdoor": "CWE-506",  # Embedded Malicious Code
    "malicious code": "CWE-506",
    "eval injection": "CWE-95",  # Improper Neutralization of Directives in Dynamically Evaluated Code ('eval')
    "command injection": "CWE-77",  # Also CWE-78 for OS Command Injection
    "logic bomb": "CWE-511",
    "time bomb": "CWE-511",
    "trojan": "CWE-506",
    "obfuscated code": "CWE-684",  # Provision of Unsafe Obfuscated Code
    "unnecessary permission": "CWE-272",  # Least Privilege Violation
    "dynamic code execution": "CWE-94",  # Improper Control of Generation of Code ('Code Injection') or CWE-95
    "suspicious dependency": "CWE-1104",  # Use of Unmaintained Third Party Components (can lead to supply chain issues)
    "unapproved library": "CWE-1104",  # Or CWE-1290 if it's about untrusted sources
    "remote code execution": "CWE-94",
    "unsafe deserialization": "CWE-502",  # Often leads to malicious code execution
    "supply chain attack": "CWE-1352",  # Supply Chain Security Control Issues
    "code tampering": "CWE-494",  # Download of Code Without Integrity Check
}  # Adapted slightly

DANGEROUS_FUNCTIONS = {  # from collated_code.txt
    "python": [
        "eval",
        "exec",
        "os.system",
        "subprocess.call",
        "pickle.loads",
        "yaml.load",
        "__import__",
        "input",
    ],
    "javascript": [
        "eval",
        "Function",
        "setTimeout",
        "setInterval",
        "document.write",
        "innerHTML",
        "dangerouslySetInnerHTML",
    ],
    "java": [
        "ClassLoader.loadClass",
        "Runtime.exec",
        "ProcessBuilder.start",
        "System.loadLibrary",
        "ObjectInputStream.readObject",
        "ScriptEngine.eval",
    ],
    "php": [
        "eval",
        "system",
        "exec",
        "shell_exec",
        "passthru",
        "popen",
        "proc_open",
        "unserialize",
        "include",
        "require",
    ],
    "csharp": [
        "Process.Start",
        "Assembly.Load",
        "BinaryFormatter.Deserialize",
        "DynamicInvoke",
        "Activator.CreateInstance",
        "ScriptControl.Eval",
    ],
    "ruby": [
        "eval",
        "system",
        "exec",
        "`",
        "Kernel.fork",
        "IO.popen",
        "Marshal.load",
        "YAML.load",
    ],  # Added backticks
    "go": [
        "os/exec.Command",
        "syscall.Exec",
        "plugin.Open",
        "unsafe.Pointer",
        "reflect.Call",
    ],
}


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
                    "LLM returned a single JSON object for findings (CodeIntegrityAgent), expected array. Wrapping it."
                )
                return [loaded_json]
    except json.JSONDecodeError as e:
        logger.error(
            f"JSONDecodeError in _extract_json_from_llm_response (CodeIntegrityAgent): {e}. Response: {response_text[:500]}"
        )
    return None


def _identify_cwe_mappings(findings: List[Dict[str, Any]]) -> List[Dict[str, str]]:
    cwe_mappings = []
    for finding in findings:
        description = finding.get("description", "").lower()
        recommendation = finding.get("recommendation", "").lower()
        text_to_check = description + " " + recommendation
        mapped_cwe = False
        for keyword, cwe_id in CODE_INTEGRITY_CWE_MAP.items():
            if keyword in text_to_check:
                cwe_mappings.append(
                    {"description": finding.get("description", ""), "cwe_id": cwe_id}
                )
                mapped_cwe = True
                break
        if not mapped_cwe:
            logger.debug(
                f"No direct CWE keyword match for code integrity finding: {description}"
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
    agent_name_for_logging = "CodeIntegrityAgent_Assess"

    logger.info(
        f"CodeIntegrityAgent Node: assess_vulnerabilities for '{filename}' (Submission: {submission_id})"
    )

    if not code_snippet:
        return {"findings": [], "error": "Missing code snippet for CodeIntegrityAgent."}

    asvs_guidance_for_prompt = ASVS_V10_GUIDELINES

    dangerous_funcs_for_lang = DANGEROUS_FUNCTIONS.get(language.lower(), [])
    dangerous_func_context = ""
    if dangerous_funcs_for_lang:
        detected_dangerous_funcs = [
            f
            for f in dangerous_funcs_for_lang
            if re.search(r"\b" + re.escape(f) + r"\b", code_snippet)
        ]
        if detected_dangerous_funcs:
            dangerous_func_context = f"The code may use potentially dangerous functions/patterns like: {', '.join(detected_dangerous_funcs)}. Pay close attention to their usage context and input sources."

    framework_context_str = f"The code is in {language}."
    if framework:
        framework_context_str += f" It might be using the {framework} framework."

    trigger_context_str = ""
    expected_trigger_area = (
        "V10_MaliciousCode"  # Or "V10_CodeIntegrity" if your mapping uses that
    )
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
                f"Please verify and conduct a detailed assessment for code integrity/malicious code vulnerabilities based on this context."
            )
        elif trigger_area:
            trigger_context_str = f"\nBroader context: Initial analysis highlighted '{trigger_area}' with likelihood '{task_context.get('likelihood_from_context_analysis', 'N/A')}' as relevant for this file. Consider this while focusing on code integrity."

    prompt = f"""
    Analyze the following {language} code snippet from file '{filename}' for security vulnerabilities related to OWASP ASVS V10 (Malicious Code / Code Integrity).
    {framework_context_str}
    {dangerous_func_context}
    {trigger_context_str}
    Focus on identifying potential backdoors, logic bombs, use of 'eval' or system commands with untrusted input, unauthorized code obfuscation, suspicious dependencies, or any code that might allow for arbitrary code execution or evasion of security controls.

    Refer to these ASVS V10 Guidelines:
    {asvs_guidance_for_prompt}

    Code Snippet:
    ```{language}
    {code_snippet}
    ```

    Task:
    1. Identify specific vulnerabilities related to code integrity or potentially malicious code.
    2. For each vulnerability found, provide:
        - "description": A concise description of the weakness.
        - "severity": Estimated severity (High, Medium, Low - consider High for most direct malicious code vectors).
        - "line_start": Approximate starting line number of the vulnerable code.
        - "line_end": Approximate ending line number.
        - "recommendation": A specific recommendation for fixing or mitigating the vulnerability.
        - "asvs_id": The primary ASVS V10 requirement ID it violates (e.g., "V10.2.1", "V10.1.3").
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
                    f"CodeIntegrityAgent successfully assessed '{filename}', found {len(findings_output)} potential issues."
                )
            else:
                error_output = "Failed to parse JSON findings from LLM response for CodeIntegrityAgent assessment."
                logger.error(
                    f"{error_output} LLM raw response: {llm_result.content[:500]}"
                )
        else:
            error_output = (
                llm_result.error
                or "LLM call failed or returned no content for CodeIntegrityAgent assessment."
            )
            logger.error(
                f"CodeIntegrityAgent assessment LLM call failed for '{filename}': {error_output}"
            )

    except Exception as e:
        logger.exception(
            f"Exception during CodeIntegrityAgent assessment for '{filename}': {e}"
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
    agent_name_for_logging = "CodeIntegrityAgent_Fix"

    logger.info(
        f"CodeIntegrityAgent Node: generate_fixes for '{filename}' (Submission: {submission_id})"
    )

    if not findings:
        return {
            "fixed_code_snippet": code_snippet,
            "explanation": "No code integrity vulnerabilities were identified to fix.",
            "error": None,
        }

    issues_json = json.dumps(findings, indent=2)
    prompt = f"""
    The following {language} code snippet from file '{filename}' has code integrity or potential malicious code vulnerabilities.
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
        Focus on removing or neutralizing malicious patterns, replacing unsafe functions like 'eval' or direct system calls with safer alternatives (e.g., data validation, sandboxed execution if absolutely necessary and no other alternative exists), and ensuring inputs to sensitive functions are strictly validated and sanitized.
    3.  If a dependency is suspicious, the fix might involve recommending its removal or replacement, rather than a code change in this snippet.
    4.  After the fixed code, provide a brief, clear "explanation" of key changes and why they improve code integrity.
    5.  Return ONLY a single valid JSON object with two keys: "fixed_code" (string) and "explanation" (string).
    """

    llm = get_llm_client()
    llm_result: Optional[LLMResult] = None
    fixed_code_output = code_snippet
    explanation_output = (
        "Fix generation for code integrity issues failed or was not applicable."
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
                parsed_fix_object is None
            ):  # If direct parse failed or yielded wrong structure
                # Fallback to regex for embedded JSON object
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
                            f"Failed to parse extracted JSON for code integrity fix: {e_inner}"
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
                    f"CodeIntegrityAgent successfully generated fix for '{filename}'."
                )
            else:
                error_output = "Failed to parse 'fixed_code' and 'explanation' from LLM response for CodeIntegrityAgent fix."
                logger.error(
                    f"{error_output} LLM raw response: {llm_result.content[:500]}"
                )
                explanation_output = (
                    error_output  # Provide error in explanation if fix parsing failed
                )
        else:
            error_output = (
                llm_result.error
                or "LLM call failed or returned no content for CodeIntegrityAgent fix."
            )
            logger.error(
                f"CodeIntegrityAgent fix LLM call failed for '{filename}': {error_output}"
            )
            explanation_output = error_output

    except Exception as e:
        logger.exception(
            f"Exception during CodeIntegrityAgent fix generation for '{filename}': {e}"
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
            },  # Log findings sent for fix
        )

    return {
        "fixed_code_snippet": fixed_code_output,
        "explanation": explanation_output,
        "error": error_output,
    }


async def map_to_standards_node(state: SecurityAgentState) -> Dict[str, Any]:
    findings = state.get("findings") or []
    logger.info(
        f"CodeIntegrityAgent Node: map_to_standards for '{state['filename']}' (Submission: {state['submission_id']})"
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
                    f"Finding in CodeIntegrityAgent for '{state['filename']}' is missing 'asvs_id': {finding.get('description')}"
                )

    cwe_mappings = _identify_cwe_mappings(findings)
    logger.info(
        f"Mapped {len(cwe_mappings)} findings to CWEs for CodeIntegrityAgent on '{state['filename']}'."
    )

    return {
        "asvs_mapping": asvs_mappings,
        "cwe_mapping": cwe_mappings,
        "error": state.get("error"),
    }


# --- Graph Construction ---
def build_code_integrity_agent_graph() -> Any:
    graph = StateGraph(SecurityAgentState)
    graph.add_node("assess_vulnerabilities", assess_vulnerabilities_node)
    graph.add_node("generate_fixes", generate_fixes_node)
    graph.add_node("map_to_standards", map_to_standards_node)

    graph.set_entry_point("assess_vulnerabilities")
    graph.add_edge("assess_vulnerabilities", "generate_fixes")
    graph.add_edge("generate_fixes", "map_to_standards")
    graph.add_edge("map_to_standards", END)

    compiled_graph = graph.compile()
    logger.info("CodeIntegrityAgent graph compiled successfully.")
    return compiled_graph
