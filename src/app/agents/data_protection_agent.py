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

# --- Constants for ASVS V8 Data Protection (from collated_code.txt) ---
ASVS_V8_GUIDELINES = """
V8.1 General Data Protection:
    - Identify sensitive data and apply appropriate controls
    - Store/transmit sensitive data using encryption
    - Minimize sensitive data exposure
    - Disable caching for sensitive responses
    - Apply data protection regulations requirements

V8.2 Client-side Data Protection:
    - Encrypt sensitive data client-side with proper key management
    - Store minimum data with appropriate controls
    - Clear browser storage when session ends
    - Implement controls to prevent leakage of sensitive data to other sites

V8.3 Sensitive Private Data:
    - Protect sensitive information (PII, health, financial data)
    - Apply minimum necessary collection principle
    - Mask, encrypt, or hash sensitive data
    - Comply with data protection regulations (GDPR, CCPA, etc.)
    - Apply specific controls for personal data storage

V8.4 Memory, Cache and Log Protection:
    - Clear sensitive variables when no longer required
    - Prevent leak of sensitive data to logs
    - Guard against memory dumps and core dumps of sensitive data
    - Apply secure disposal when data is no longer needed
"""

DATA_PROTECTION_CWE_MAP = {
    "cleartext storage": "CWE-312",
    "cleartext transmission": "CWE-319",
    "insufficient protection": "CWE-311",  # Missing Encryption of Sensitive Data
    "hardcoded secret": "CWE-798",  # For hardcoded keys/secrets used for data protection
    "missing encryption": "CWE-311",
    "information exposure": "CWE-200",
    "sensitive data exposure": "CWE-200",
    "pii exposure": "CWE-359",  # Exposure of Privately Identifiable Information
    "caching sensitive data": "CWE-524",  # Use of Cache Containing Sensitive Information
    "insecure storage": "CWE-922",  # Insecure Storage of Sensitive Information
    "data leak": "CWE-200",  # Can also be CWE-359 for PII
    "memory leak of sensitive data": "CWE-200",  # If it leads to exposure; otherwise CWE-401/404 for memory mgmt
    "personal data handling": "CWE-359",
    "plaintext password storage": "CWE-257",  # Storing Passwords in a Recoverable Format (more specific than 312 for passwords)
    "sensitive data in logs": "CWE-532",
}  # Adapted slightly

SENSITIVE_DATA_PATTERNS = [  # from collated_code.txt
    "password",
    "passwd",
    "pwd",
    "secret",
    "token",
    "api_key",
    "apikey",
    "key",
    "credential",
    "auth",
    "ssn",
    "social",
    "dob",
    "birth",
    "credit_card",
    "card_number",  # more specific
    "cvv",
    "ccv",
    "banking",
    "account_number",
    "routing_number",
    "swift",
    "iban",
    "personal_identifiable_information",
    "private_key",
    "sensitive",
    "pii",
    "health_record",
    "medical_record",
    "phi",
    "hipaa",
    "license_plate",
    "driver_license",
]


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
                    "LLM returned a single JSON object for findings (DataProtectionAgent), expected array. Wrapping it."
                )
                return [loaded_json]
    except json.JSONDecodeError as e:
        logger.error(
            f"JSONDecodeError in _extract_json_from_llm_response (DataProtectionAgent): {e}. Response: {response_text[:500]}"
        )
    return None


def _identify_cwe_mappings(findings: List[Dict[str, Any]]) -> List[Dict[str, str]]:
    cwe_mappings = []
    for finding in findings:
        description = finding.get("description", "").lower()
        recommendation = finding.get("recommendation", "").lower()
        text_to_check = description + " " + recommendation
        mapped_cwe = False
        for keyword, cwe_id in DATA_PROTECTION_CWE_MAP.items():
            if keyword in text_to_check:
                cwe_mappings.append(
                    {"description": finding.get("description", ""), "cwe_id": cwe_id}
                )
                mapped_cwe = True
                break
        if not mapped_cwe:
            logger.debug(
                f"No direct CWE keyword match for data protection finding: {description}"
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
    agent_name_for_logging = "DataProtectionAgent_Assess"

    logger.info(
        f"DataProtectionAgent Node: assess_vulnerabilities for '{filename}' (Submission: {submission_id})"
    )

    if not code_snippet:
        return {
            "findings": [],
            "error": "Missing code snippet for DataProtectionAgent.",
        }

    asvs_guidance_for_prompt = ASVS_V8_GUIDELINES  # Defined in your existing agent file

    detected_sensitive_patterns = [
        p
        for p in SENSITIVE_DATA_PATTERNS
        if re.search(r"\b" + re.escape(p) + r"\b", code_snippet, re.IGNORECASE)
    ]
    sensitive_pattern_context = ""
    if detected_sensitive_patterns:
        unique_hits = list(set(detected_sensitive_patterns))
        sensitive_pattern_context = f"The code appears to handle potentially sensitive data indicated by terms like: {', '.join(unique_hits[:7])} (and possibly others). Focus on how this data is stored, transmitted, logged, cached, and disposed of."

    framework_context_str = f"The code is in {language}."
    if framework:
        framework_context_str += f" It might be using the {framework} framework; consider any framework-specific data protection features or requirements (e.g., encryption libraries, secure storage APIs)."

    data_classification_context = task_context.get(
        "data_classification", "general sensitive data, including PII if present."
    )
    if not data_classification_context:  # Ensure a default
        data_classification_context = (
            "general sensitive data, including PII if present."
        )

    trigger_context_str = ""
    expected_trigger_area = "V8_DataProtection"
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
                f"Please verify and conduct a detailed assessment for data protection vulnerabilities based on this context, considering data classification as '{data_classification_context}'."
            )
        elif trigger_area:
            trigger_context_str = f"\nBroader context: Initial analysis highlighted '{trigger_area}' with likelihood '{task_context.get('likelihood_from_context_analysis', 'N/A')}' as relevant for this file. Consider this while focusing on data protection, with data classification as '{data_classification_context}'."
        else:  # If no specific trigger_area, still mention data classification
            trigger_context_str = f"\nConsider data classification as '{data_classification_context}' when assessing data protection measures."

    prompt = f"""
    Analyze the following {language} code snippet from file '{filename}' for security vulnerabilities related to OWASP ASVS V8 (Data Protection).
    {framework_context_str}
    {sensitive_pattern_context}
    {trigger_context_str}
    Focus on identifying issues such as storage or transmission of sensitive data (PII, financial, health, credentials, secrets) in cleartext or with weak/improper encryption, inadequate key management for data at rest/in transit, logging or caching of sensitive information, violations of data minimization, insecure data disposal, and lack of protection for sensitive data in memory.

    Refer to these ASVS V8 Guidelines:
    {asvs_guidance_for_prompt}

    Code Snippet:
    ```{language}
    {code_snippet}
    ```

    Task:
    1. Identify specific vulnerabilities related to data protection.
    2. For each vulnerability found, provide:
        - "description": A concise description of the data protection weakness (e.g., "PII (email address) stored in log files without masking", "Database connection string with plaintext password found in code").
        - "severity": Estimated severity (High, Medium, Low - typically High or Medium for direct sensitive data exposure).
        - "line_start": Approximate starting line number of the vulnerable code.
        - "line_end": Approximate ending line number.
        - "recommendation": A specific recommendation for fixing the vulnerability (e.g., "Encrypt sensitive data at rest using AES-256-GCM.", "Remove or mask email addresses from log output.", "Store database credentials in environment variables or a secrets manager.").
        - "asvs_id": The primary ASVS V8 requirement ID it violates (e.g., "V8.1.2", "V8.3.1").
    3. If no data protection vulnerabilities are found in this snippet, return an empty array.
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
                    f"DataProtectionAgent successfully assessed '{filename}', found {len(findings_output)} potential issues."
                )
            else:
                error_output = "Failed to parse JSON findings from LLM response for DataProtectionAgent assessment."
                logger.error(
                    f"{error_output} LLM raw response: {llm_result.content[:500]}"
                )
        else:
            error_output = (
                llm_result.error
                or "LLM call failed or returned no content for DataProtectionAgent assessment."
            )
            logger.error(
                f"DataProtectionAgent assessment LLM call failed for '{filename}': {error_output}"
            )

    except Exception as e:
        logger.exception(
            f"Exception during DataProtectionAgent assessment for '{filename}': {e}"
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
    agent_name_for_logging = "DataProtectionAgent_Fix"

    logger.info(
        f"DataProtectionAgent Node: generate_fixes for '{filename}' (Submission: {submission_id})"
    )

    if not findings:
        return {
            "fixed_code_snippet": code_snippet,
            "explanation": "No data protection vulnerabilities were identified to fix.",
            "error": None,
        }

    issues_json = json.dumps(findings, indent=2)
    prompt = f"""
    The following {language} code snippet from file '{filename}' has data protection vulnerabilities.
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
        Focus on applying strong encryption (e.g., AES-256-GCM) for sensitive data at rest and ensuring TLS for data in transit. If sensitive data is logged, modify the code to remove, mask, or redact it. For hardcoded secrets, replace them with placeholders indicating retrieval from secure storage (e.g., 'config.get_secret("db_password")' or 'os.environ.get("API_KEY")'). Address insecure caching of sensitive data by disabling caching or using appropriate cache-control headers.
    3.  After the fixed code, provide a brief, clear "explanation" of key changes and why they improve data protection.
    4.  Return ONLY a single valid JSON object with two keys: "fixed_code" (string) and "explanation" (string).
    """

    llm = get_llm_client()
    llm_result: Optional[LLMResult] = None
    fixed_code_output = code_snippet
    explanation_output = (
        "Fix generation for data protection issues failed or was not applicable."
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
                            f"Failed to parse extracted JSON for data protection fix: {e_inner}"
                        )

            if (
                parsed_fix_object
                and "fixed_code" in parsed_fix_object
                and "explanation" in parsed_fix_object
            ):
                fixed_code_output = parsed_fix_object["fixed_code"]
                explanation_output = parsed_fix_object["explanation"]
                logger.info(
                    f"DataProtectionAgent successfully generated fix for '{filename}'."
                )
            else:
                error_output = "Failed to parse 'fixed_code' and 'explanation' from LLM response for DataProtectionAgent fix."
                logger.error(
                    f"{error_output} LLM raw response: {llm_result.content[:500]}"
                )
                explanation_output = error_output
        else:
            error_output = (
                llm_result.error
                or "LLM call failed or returned no content for DataProtectionAgent fix."
            )
            logger.error(
                f"DataProtectionAgent fix LLM call failed for '{filename}': {error_output}"
            )
            explanation_output = error_output

    except Exception as e:
        logger.exception(
            f"Exception during DataProtectionAgent fix generation for '{filename}': {e}"
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
        f"DataProtectionAgent Node: map_to_standards for '{state['filename']}' (Submission: {state['submission_id']})"
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
                    f"Finding in DataProtectionAgent for '{state['filename']}' is missing 'asvs_id': {finding.get('description')}"
                )

    cwe_mappings = _identify_cwe_mappings(findings)
    logger.info(
        f"Mapped {len(cwe_mappings)} findings to CWEs for DataProtectionAgent on '{state['filename']}'."
    )

    return {
        "asvs_mapping": asvs_mappings,
        "cwe_mapping": cwe_mappings,
        "error": state.get("error"),
    }


# --- Graph Construction ---
def build_data_protection_agent_graph() -> Any:
    graph = StateGraph(SecurityAgentState)
    graph.add_node("assess_vulnerabilities", assess_vulnerabilities_node)
    graph.add_node("generate_fixes", generate_fixes_node)
    graph.add_node("map_to_standards", map_to_standards_node)

    graph.set_entry_point("assess_vulnerabilities")
    graph.add_edge("assess_vulnerabilities", "generate_fixes")
    graph.add_edge("generate_fixes", "map_to_standards")
    graph.add_edge("map_to_standards", END)

    compiled_graph = graph.compile()
    logger.info("DataProtectionAgent graph compiled successfully.")
    return compiled_graph
