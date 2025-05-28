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

# --- Constants for ASVS V9 Communications Security (from collated_code.txt) ---
ASVS_V9_GUIDELINES = """
V9.1 Client Communications Security:
    - Use TLS to protect all communications between client and server
    - Keep TLS configurations updated with current best practices (strong ciphers, protocols)
    - Prefer server certificate verification (at both ends)
    - Use proper TLS connection parameters and settings
    - Specify character encodings for all connections
    - Disable fallback to insecure protocols

V9.2 Server Communications Security:
    - Use up-to-date TLS configurations between server components
    - Verify server connections with trusted certificates
    - Use strong encryption and proper key management
    - Apply network segmentation or encryption for backend communications
    - Separate sensitive data transfers from regular communications

V9.3 Certificate and Key Management:
    - Use strong PKI (Public Key Infrastructure) implementations
    - Maintain proper lifecycle of keys and certificates
    - Validate certificate paths and revocation status
    - Use strong randomization for cryptographic operations
    - Avoid hardcoded secrets and default/test certificates
    - Store certificates securely with proper access controls
"""

COMMUNICATION_CWE_MAP = {
    "insecure transmission": "CWE-319",
    "missing tls": "CWE-319",
    "cleartext http": "CWE-319",
    "weak tls": "CWE-327",  # Use of a Broken or Risky Cryptographic Algorithm
    "weak cipher": "CWE-327",
    "improper certificate validation": "CWE-295",
    "missing certificate validation": "CWE-295",
    "hostname verification": "CWE-297",  # Improper Validation of Certificate with Host Mismatch
    "ssl configuration": "CWE-326",  # Inadequate Encryption Strength
    "hardcoded certificate": "CWE-798",  # If a private key/cert is hardcoded
    "certificate pinning bypass": "CWE-295",  # If pinning is done but can be bypassed
    "mixed content": "CWE-311",  # Missing Encryption of Sensitive Data (for HTTP resources on HTTPS page)
    "insecure protocol fallback": "CWE-757",  # Selection of Less-Secure Algorithm During Negotiation
    "downgrade attack": "CWE-757",  # Can also be CWE-300 for channel accessible by non-endpoint
    "http instead of https": "CWE-319",
    "insecure connection": "CWE-300",  # Channel Accessible by Non-Endpoint
    "expired certificate": "CWE-298",  # Improper Data Validation (for certificate expiry)
    "self-signed certificate": "CWE-295",  # Often leads to this
}  # Adapted slightly

COMMUNICATION_LIBRARIES = {  # from collated_code.txt
    "python": [
        "requests",
        "urllib",
        "httplib",
        "http.client",
        "aiohttp",
        "urllib3",
        "socket",
        "ssl",
        "websocket",
    ],
    "java": [
        "HttpURLConnection",
        "HttpClient",
        "RestTemplate",
        "OkHttp",
        "HostnameVerifier",
        "SSLContext",
        "TrustManager",
        "SSLSocketFactory",
    ],
    "javascript": [
        "fetch",
        "XMLHttpRequest",
        "axios",
        "http",
        "https",
        "request",
        "got",
        "superagent",
        "WebSocket",
    ],
    "php": [
        "curl",
        "file_get_contents",
        "fopen",
        "stream_socket_client",
        "fsockopen",
        "SoapClient",
        "openssl_verify",
    ],
    "csharp": [
        "HttpClient",
        "WebClient",
        "WebRequest",
        "RestSharp",
        "ServicePointManager",
        "X509Certificate",
        "SslStream",
    ],
    "ruby": [
        "Net::HTTP",
        "RestClient",
        "Faraday",
        "HTTParty",
        "open-uri",
        "OpenSSL::SSL",
    ],
    "go": [
        "net/http",
        "tls.Config",
        "http.Transport",
        "http.Client",
        "crypto/tls",
        "InsecureSkipVerify",
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
                    "LLM returned a single JSON object for findings (CommAgent), expected array. Wrapping it."
                )
                return [loaded_json]
    except json.JSONDecodeError as e:
        logger.error(
            f"JSONDecodeError in _extract_json_from_llm_response (CommunicationAgent): {e}. Response: {response_text[:500]}"
        )
    return None


def _identify_cwe_mappings(findings: List[Dict[str, Any]]) -> List[Dict[str, str]]:
    cwe_mappings = []
    for finding in findings:
        description = finding.get("description", "").lower()
        recommendation = finding.get("recommendation", "").lower()
        text_to_check = description + " " + recommendation
        mapped_cwe = False
        for keyword, cwe_id in COMMUNICATION_CWE_MAP.items():
            if keyword in text_to_check:
                cwe_mappings.append(
                    {"description": finding.get("description", ""), "cwe_id": cwe_id}
                )
                mapped_cwe = True
                break
        if not mapped_cwe:
            logger.debug(
                f"No direct CWE keyword match for communication finding: {description}"
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
    agent_name_for_logging = "CommunicationAgent_Assess"

    logger.info(
        f"CommunicationAgent Node: assess_vulnerabilities for '{filename}' (Submission: {submission_id})"
    )

    if not code_snippet:
        return {"findings": [], "error": "Missing code snippet for CommunicationAgent."}

    asvs_guidance_for_prompt = ASVS_V9_GUIDELINES

    libs_for_lang = COMMUNICATION_LIBRARIES.get(language.lower(), [])
    lib_context_str = (
        f"Look for usage of common {language} communication libraries/modules: {', '.join(libs_for_lang)}."
        if libs_for_lang
        else ""
    )

    framework_context_str = f"The code is in {language}."
    if framework:
        framework_context_str += f" It might be using the {framework} framework; consider its specific TLS/SSL configuration or HTTP client setup."

    trigger_context_str = ""
    expected_trigger_area = "V9_Communication"
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
                f"Please verify and conduct a detailed assessment for communication security vulnerabilities based on this context."
            )
        elif trigger_area:
            trigger_context_str = f"\nBroader context: Initial analysis highlighted '{trigger_area}' with likelihood '{task_context.get('likelihood_from_context_analysis', 'N/A')}' as relevant for this file. Consider this while focusing on communication security."

    prompt = f"""
    Analyze the following {language} code snippet from file '{filename}' for security vulnerabilities related to OWASP ASVS V9 (Communications Security).
    {framework_context_str}
    {lib_context_str}
    {trigger_context_str}
    Focus on identifying issues such as use of insecure protocols (e.g., HTTP instead of HTTPS), weak TLS configurations (outdated protocols, weak ciphers), missing or improper certificate validation (including hostname verification), and insecure handling of cryptographic keys or certificates related to communication.

    Refer to these ASVS V9 Guidelines:
    {asvs_guidance_for_prompt}

    Code Snippet:
    ```{language}
    {code_snippet}
    ```

    Task:
    1. Identify specific vulnerabilities related to communication security.
    2. For each vulnerability found, provide:
        - "description": A concise description of the communication security weakness.
        - "severity": Estimated severity (High, Medium, Low).
        - "line_start": Approximate starting line number of the vulnerable code.
        - "line_end": Approximate ending line number.
        - "recommendation": A specific recommendation for fixing the vulnerability (e.g., enforce HTTPS, use strong TLS config, validate certificates properly).
        - "asvs_id": The primary ASVS V9 requirement ID it violates (e.g., "V9.1.1", "V9.3.2").
    3. If no communication security vulnerabilities are found in this snippet, return an empty array.
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
                    f"CommunicationAgent successfully assessed '{filename}', found {len(findings_output)} potential issues."
                )
            else:
                error_output = "Failed to parse JSON findings from LLM response for CommunicationAgent assessment."
                logger.error(
                    f"{error_output} LLM raw response: {llm_result.content[:500]}"
                )
        else:
            error_output = (
                llm_result.error
                or "LLM call failed or returned no content for CommunicationAgent assessment."
            )
            logger.error(
                f"CommunicationAgent assessment LLM call failed for '{filename}': {error_output}"
            )

    except Exception as e:
        logger.exception(
            f"Exception during CommunicationAgent assessment for '{filename}': {e}"
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
    agent_name_for_logging = "CommunicationAgent_Fix"

    logger.info(
        f"CommunicationAgent Node: generate_fixes for '{filename}' (Submission: {submission_id})"
    )

    if not findings:
        return {
            "fixed_code_snippet": code_snippet,
            "explanation": "No communication security vulnerabilities were identified to fix.",
            "error": None,
        }

    issues_json = json.dumps(findings, indent=2)
    # language_recommendations was in original collated, but might not be needed if prompt is specific enough
    # If needed:
    # language_recommendations = ""
    # if language.lower() in COMMUNICATION_LIBRARIES: # Assuming COMMUNICATION_LIBRARIES is defined
    #     language_recommendations = f"\nWhen fixing, use secure {language} practices for communication security, potentially involving libraries like: {', '.join(COMMUNICATION_LIBRARIES.get(language.lower(),[]))}."

    prompt = f"""
    The following {language} code snippet from file '{filename}' has communication security vulnerabilities.
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
        Focus on enforcing HTTPS/TLS for all connections, configuring strong TLS (protocols and ciphers), implementing proper server certificate validation (including hostname checks), and securely handling any client certificates if applicable.
    3.  If specific libraries for {language} (e.g., requests with verify=True in Python, proper SSLContext in Java) are relevant, use them.
    4.  After the fixed code, provide a brief, clear "explanation" of key changes and why they improve communication security.
    5.  Return ONLY a single valid JSON object with two keys: "fixed_code" (string) and "explanation" (string).
    """

    llm = get_llm_client()
    llm_result: Optional[LLMResult] = None
    fixed_code_output = code_snippet
    explanation_output = (
        "Fix generation for communication security issues failed or was not applicable."
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
                            f"Failed to parse extracted JSON for communication fix: {e_inner}"
                        )

            if (
                parsed_fix_object
                and "fixed_code" in parsed_fix_object
                and "explanation" in parsed_fix_object
            ):
                fixed_code_output = parsed_fix_object["fixed_code"]
                explanation_output = parsed_fix_object["explanation"]
                logger.info(
                    f"CommunicationAgent successfully generated fix for '{filename}'."
                )
            else:
                error_output = "Failed to parse 'fixed_code' and 'explanation' from LLM response for CommunicationAgent fix."
                logger.error(
                    f"{error_output} LLM raw response: {llm_result.content[:500]}"
                )
                explanation_output = error_output
        else:
            error_output = (
                llm_result.error
                or "LLM call failed or returned no content for CommunicationAgent fix."
            )
            logger.error(
                f"CommunicationAgent fix LLM call failed for '{filename}': {error_output}"
            )
            explanation_output = error_output

    except Exception as e:
        logger.exception(
            f"Exception during CommunicationAgent fix generation for '{filename}': {e}"
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
        f"CommunicationAgent Node: map_to_standards for '{state['filename']}' (Submission: {state['submission_id']})"
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
                    f"Finding in CommunicationAgent for '{state['filename']}' is missing 'asvs_id': {finding.get('description')}"
                )

    cwe_mappings = _identify_cwe_mappings(findings)
    logger.info(
        f"Mapped {len(cwe_mappings)} findings to CWEs for CommunicationAgent on '{state['filename']}'."
    )

    return {
        "asvs_mapping": asvs_mappings,
        "cwe_mapping": cwe_mappings,
        "error": state.get("error"),
    }


# --- Graph Construction ---
def build_communication_agent_graph() -> Any:
    graph = StateGraph(SecurityAgentState)
    graph.add_node("assess_vulnerabilities", assess_vulnerabilities_node)
    graph.add_node("generate_fixes", generate_fixes_node)
    graph.add_node("map_to_standards", map_to_standards_node)

    graph.set_entry_point("assess_vulnerabilities")
    graph.add_edge("assess_vulnerabilities", "generate_fixes")
    graph.add_edge("generate_fixes", "map_to_standards")
    graph.add_edge("map_to_standards", END)

    compiled_graph = graph.compile()
    logger.info("CommunicationAgent graph compiled successfully.")
    return compiled_graph
