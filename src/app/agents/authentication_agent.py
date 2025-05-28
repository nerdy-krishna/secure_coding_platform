import logging
import json
import re
from typing import TypedDict, List, Optional, Dict, Any

from langgraph.graph import StateGraph, END
from ..llm.llm_client import get_llm_client
from ..llm.providers import LLMResult
from ..db.crud import save_llm_interaction
from ..utils.cost_estimation import estimate_openai_cost


# Assuming a common SecurityAgentState definition
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

# --- Constants for ASVS V2 Authentication (from collated_code.txt) ---
ASVS_V2_GUIDELINES = """
V2.1 Password Security:
    - Verify minimum password strength/complexity requirements
    - Verify password length of at least 12 characters
    - Verify no password truncation
    - Verify ability to paste passwords (no paste blocking)
    - Verify ability to change passwords
    - Verify password change requires current and new password
    - Verify password changes validate against password history
    - Verify password strength meter guidance

V2.2 General Authenticator Security:
    - Verify anti-automation controls against brute force
    - Verify credential rotation after suspected compromise
    - Verify resistance to offline attacks (proper hashing)
    - Verify resistance to other party disclosure (no plaintext or reversible encryption)
    - Verify absence of default credentials
    - Verify protection against duplicate authentication credentials

V2.3 Authenticator Lifecycle:
    - Verify credential issuance, recovery, and changes are secure
    - Verify device-issued/biometric authenticator registration is secure
    - Verify renewal instructions are sent with adequate time
    - Verify account enumeration is not possible in login, password recovery, or registration 

V2.4 Credential Storage:
    - Verify passwords are stored with sufficient protection (strong adaptive hashing)
    - Verify salt is at least 32 bits and chosen arbitrarily
    - Verify work factor/iteration count is as large as possible
    - Verify salt is unique for each credential

V2.5 Credential Recovery:
    - Verify forgotten password functions don't reveal password existence
    - Verify secure password recovery mechanisms (avoid sending original password)
    - Verify account unlock uses secure mechanisms
    - Verify forgotten password and account recovery doesn't reveal account validity

V2.7 Out of Band Verifiers:
    - Verify SMS or voice calls are only used as second factors
    - Verify resilience against social engineering (e.g., SIM swaps)
    - Verify physical out of band verifiers are protected against cloning
    - Verify randomness of one-time verification codes

V2.8 Single or Multi-Factor One-time Verifiers:
    - Verify time-based OTP validity period
    - Verify physical single-factor OTP devices can be revoked
    - Verify high-value transactions use multi-factor authentication
    - Verify step-up authentication for sensitive operations
    - Verify impersonation resistance for phishing protection
"""

AUTHENTICATION_CWE_MAP = {
    "weak password": "CWE-521",
    "password storage": "CWE-916",  # Was CWE-257, CWE-916 is more specific to insufficient effort
    "default credentials": "CWE-798",
    "brute force": "CWE-307",
    "plaintext password": "CWE-312",  # Was CWE-256, CWE-312 is broader for cleartext storage
    "insecure authentication": "CWE-287",
    "hardcoded credential": "CWE-798",
    "missing authentication": "CWE-306",
    "password recovery": "CWE-640",
    "account enumeration": "CWE-203",  # Was CWE-200, CWE-203 is more specific
    "credential exposure": "CWE-522",
    "multi-factor": "CWE-308",  # Use of Single-factor Authentication
    "password complexity": "CWE-521",
    "credential reuse": "CWE-288",  # Authentication Bypass Using an Alternate Path or Channel (more general than just reuse)
    "session fixation": "CWE-384",  # Often related to initial auth
}

AUTH_PATTERNS = {  # From collated_code.txt
    "python": {
        "django": [
            "authenticate",
            "login",
            "logout",
            "User",
            "UserManager",
            "password_validation",
            "make_password",
            "check_password",
        ],
        "flask": [
            "Flask-Login",
            "login_user",
            "logout_user",
            "current_user",
            "login_required",
            "UserMixin",
            "werkzeug.security",
        ],
        "fastapi": [
            "OAuth2PasswordBearer",
            "get_current_user",
            "verify_password",
            "create_access_token",
            "HTTPBearer",
            "Depends(fastapi_users.current_user)",
        ],
        "core": ["hashlib", "bcrypt", "passlib", "secrets", "pbkdf2_hmac"],
    },
    "javascript": {
        "express": [
            "passport",
            "jwt",
            "bcrypt",
            "jsonwebtoken",
            "authenticate",
            "strategy",
            "deserializeUser",
        ],
        "core": [
            "localStorage.getItem('token')",
            "sessionStorage.getItem('token')",
            "Authorization: Bearer",
            "crypto.subtle",
            "argon2",
            "scrypt",
        ],
    },
    "java": {
        "spring": [
            "SecurityConfig",
            "WebSecurityConfigurerAdapter",
            "AuthenticationManager",
            "UserDetailsService",
            "@Secured",
            "PasswordEncoder",
            "BCryptPasswordEncoder",
        ],
        "jee": [
            "login-config",
            "auth-method",
            "security-constraint",
            "Principal",
            "isUserInRole",
            "@RolesAllowed",
        ],
        "core": [
            "MessageDigest",
            "SecureRandom",
            "Cipher",
            "KeyStore",
            "Basic Auth",
            "JAAS",
        ],
    },
    "php": {
        "laravel": [
            "Auth::",
            "Hash::make",
            "bcrypt(",
            "Fortify",
            "Sanctum",
            "Passport",
            "Password::",
        ],
        "symfony": [
            "security.yaml",
            "UserInterface",
            "UserProviderInterface",
            "PasswordHasher",
            "GuardAuthenticator",
        ],
        "core": [
            "password_hash(",
            "password_verify(",
            "hash_equals(",
            "session_start(",
        ],
    },
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
                    "LLM returned a single JSON object for findings (AuthAgent), expected array. Wrapping it."
                )
                return [loaded_json]
    except json.JSONDecodeError as e:
        logger.error(
            f"JSONDecodeError in _extract_json_from_llm_response (AuthenticationAgent): {e}. Response: {response_text[:500]}"
        )
    return None


def _identify_cwe_mappings(findings: List[Dict[str, Any]]) -> List[Dict[str, str]]:
    cwe_mappings = []
    for finding in findings:
        description = finding.get("description", "").lower()
        recommendation = finding.get("recommendation", "").lower()
        text_to_check = description + " " + recommendation
        mapped_cwe = False
        for keyword, cwe_id in AUTHENTICATION_CWE_MAP.items():
            if keyword in text_to_check:
                cwe_mappings.append(
                    {"description": finding.get("description", ""), "cwe_id": cwe_id}
                )
                mapped_cwe = True
                break
        if not mapped_cwe:
            logger.debug(f"No direct CWE keyword match for auth finding: {description}")
    return cwe_mappings


# --- Node Functions ---
async def assess_vulnerabilities_node(state: SecurityAgentState) -> Dict[str, Any]:
    submission_id = state["submission_id"]
    filename = state["filename"]
    code_snippet = state["code_snippet"]
    language = state["language"]
    framework = state.get("framework")
    task_context = state.get("task_context", {})  # This line is kept
    agent_name_for_logging = "AuthenticationAgent_Assess"

    logger.info(
        f"AuthenticationAgent Node: assess_vulnerabilities for '{filename}' (Submission: {submission_id})"
    )

    if not code_snippet:
        return {
            "findings": [],
            "error": "Missing code snippet for AuthenticationAgent.",
        }

    asvs_guidance_for_prompt = ASVS_V2_GUIDELINES

    auth_patterns_lang = AUTH_PATTERNS.get(language.lower(), {})
    core_auth_patterns = auth_patterns_lang.get("core", [])
    framework_auth_patterns = (
        auth_patterns_lang.get(framework.lower(), []) if framework else []
    )
    relevant_auth_patterns = core_auth_patterns + framework_auth_patterns
    pattern_context_str = (
        f"Key {language} authentication patterns/libraries to look for: {', '.join(relevant_auth_patterns)}."
        if relevant_auth_patterns
        else ""
    )

    framework_context_str = f"The code is in {language}."
    if framework:
        framework_context_str += f" It seems to use the {framework} framework."

    trigger_context_str = ""
    expected_trigger_area = "V2_Authentication"  # Specific to this agent
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
                f"Please verify and conduct a detailed assessment for authentication vulnerabilities based on this context."
            )
        elif trigger_area:  # Context provided but not directly for this agent
            trigger_context_str = f"\nBroader context: Initial analysis highlighted '{trigger_area}' with likelihood '{task_context.get('likelihood_from_context_analysis', 'N/A')}' as relevant for this file. Consider this while focusing on authentication."

    prompt = f"""
    Analyze the following {language} code snippet from file '{filename}' for security vulnerabilities related to OWASP ASVS V2 (Authentication).
    {framework_context_str}
    {pattern_context_str}
    {trigger_context_str}
    Focus on how the code handles user credentials, password storage, authentication mechanisms (MFA, OTPs), session generation upon login, account recovery, and brute-force protections.

    Refer to these ASVS V2 Guidelines:
    {asvs_guidance_for_prompt}

    Code Snippet:
    ```{language}
    {code_snippet}
    ```

    Task:
    1. Identify specific vulnerabilities related to authentication.
    2. For each vulnerability found, provide:
        - "description": A concise description of the authentication weakness.
        - "severity": Estimated severity (High, Medium, Low).
        - "line_start": Approximate starting line number of the vulnerable code.
        - "line_end": Approximate ending line number.
        - "recommendation": A specific recommendation for fixing the vulnerability.
        - "asvs_id": The primary ASVS V2 requirement ID it violates (e.g., "V2.1.2", "V2.4.1").
    3. If no authentication vulnerabilities are found in this snippet, return an empty array.
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
                    f"AuthenticationAgent successfully assessed '{filename}', found {len(findings_output)} potential issues."
                )
            else:
                error_output = "Failed to parse JSON findings from LLM response for AuthenticationAgent assessment."
                logger.error(
                    f"{error_output} LLM raw response: {llm_result.content[:500]}"
                )
        else:
            error_output = (
                llm_result.error
                or "LLM call failed or returned no content for AuthenticationAgent assessment."
            )
            logger.error(
                f"AuthenticationAgent assessment LLM call failed for '{filename}': {error_output}"
            )

    except Exception as e:
        logger.exception(
            f"Exception during AuthenticationAgent assessment for '{filename}': {e}"
        )
        error_output = f"Exception during assessment: {str(e)}"
        if llm_result is None:
            llm_result = LLMResult(status="failed", error=error_output)
        elif (
            llm_result.status != "failed"
        ):  # Ensure status reflects exception if call itself succeeded
            llm_result.status = "failed"
            llm_result.error = error_output

    if llm_result:  # llm_result should always be defined here due to the except block.
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
    agent_name_for_logging = "AuthenticationAgent_Fix"

    logger.info(
        f"AuthenticationAgent Node: generate_fixes for '{filename}' (Submission: {submission_id})"
    )

    if not findings:
        return {
            "fixed_code_snippet": code_snippet,
            "explanation": "No authentication vulnerabilities were identified to fix.",
            "error": None,
        }

    issues_json = json.dumps(findings, indent=2)
    prompt = f"""
    The following {language} code snippet from file '{filename}' has authentication vulnerabilities.
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
        Focus on secure password hashing (e.g., Argon2id, bcrypt, scrypt, PBKDF2 with strong parameters), proper salt handling, secure credential storage, robust session generation upon login, protection against account enumeration, and implementation of rate limiting/lockout mechanisms.
    3.  After the fixed code, provide a brief, clear "explanation" of key changes and why they improve security.
    4.  Return ONLY a single valid JSON object with two keys: "fixed_code" (string) and "explanation" (string).
    """

    llm = get_llm_client()
    llm_result: Optional[LLMResult] = None
    fixed_code_output = code_snippet
    explanation_output = (
        "Fix generation for authentication issues failed or was not applicable."
    )
    error_output: Optional[str] = None
    parsed_fix_object: Optional[Dict[str, str]] = None

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
                            f"Failed to parse extracted JSON for authentication fix: {e_inner}"
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
                    f"AuthenticationAgent successfully generated fix for '{filename}'."
                )
            else:
                error_output = "Failed to parse 'fixed_code' and 'explanation' from LLM response for AuthenticationAgent fix."
                logger.error(
                    f"{error_output} LLM raw response: {llm_result.content[:500]}"
                )
                explanation_output = error_output
        else:
            error_output = (
                llm_result.error
                or "LLM call failed or returned no content for AuthenticationAgent fix."
            )
            logger.error(
                f"AuthenticationAgent fix LLM call failed for '{filename}': {error_output}"
            )
            explanation_output = error_output

    except Exception as e:
        logger.exception(
            f"Exception during AuthenticationAgent fix generation for '{filename}': {e}"
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
        f"AuthenticationAgent Node: map_to_standards for '{state['filename']}' (Submission: {state['submission_id']})"
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
                    f"Finding in AuthenticationAgent for '{state['filename']}' is missing 'asvs_id': {finding.get('description')}"
                )

    cwe_mappings = _identify_cwe_mappings(findings)
    logger.info(
        f"Mapped {len(cwe_mappings)} findings to CWEs for AuthenticationAgent on '{state['filename']}'."
    )

    return {
        "asvs_mapping": asvs_mappings,
        "cwe_mapping": cwe_mappings,
        "error": state.get("error"),
    }


# --- Graph Construction ---
def build_authentication_agent_graph() -> Any:
    graph = StateGraph(SecurityAgentState)
    graph.add_node("assess_vulnerabilities", assess_vulnerabilities_node)
    graph.add_node("generate_fixes", generate_fixes_node)
    graph.add_node("map_to_standards", map_to_standards_node)

    graph.set_entry_point("assess_vulnerabilities")
    graph.add_edge("assess_vulnerabilities", "generate_fixes")
    graph.add_edge("generate_fixes", "map_to_standards")
    graph.add_edge("map_to_standards", END)

    compiled_graph = graph.compile()
    logger.info("AuthenticationAgent graph compiled successfully.")
    return compiled_graph
