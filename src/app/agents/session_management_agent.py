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

# --- Constants for ASVS V3 Session Management (from collated_code.txt) ---
ASVS_V3_GUIDELINES = """
V3.1 Session Management Security Controls (Fundamental):
    - Generate new session tokens on login
    - Use cryptographically secure random generators
    - Set session timeout periods
    - Generate new token on authentication state changes

V3.2 Session Termination (Logout):
    - Provide accessible logout functionality
    - Invalidate sessions on logout, idle timeouts
    - Terminate sessions at trusted clients

V3.3 Session Timeout:
    - Enforce idle timeout (15-30 minutes)
    - Set absolute session lifetimes
    - Ensure timeout for high-value applications

V3.4 Session ID Protection:
    - Use sufficient entropy session identifiers
    - Store tokens securely
    - Use secure transport (HTTPS)

V3.5 Session Binding:
    - Validate session ID for each request
    - Protect against fixation, session hijacking

V3.6 Cookie-based Controls:
    - Set cookie attributes: HttpOnly, Secure, SameSite=Lax
    - Use cookie prefixes for sensitive cookies

V3.7 Token-based Protections:
    - Implement CSRF protections
    - Use Bearer Tokens with proper validation

V3.8 Prevention of Session Attacks:
    - Regenerate session ID on privilege changes
    - Use multi-factor authentication for sensitive operations
"""

SESSION_MANAGEMENT_CWE_MAP = {
    "session fixation": "CWE-384",
    "session hijacking": "CWE-613",  # Insufficient Session Expiration can lead to hijacking
    "insufficient entropy": "CWE-331",
    "insecure storage": "CWE-539",  # Information Exposure Through Persistent Cookies
    "missing httponly": "CWE-1004",  # Sensitive Cookie Without 'HttpOnly' Flag
    "missing secure flag": "CWE-614",  # Sensitive Cookie in HTTPS Session Without 'Secure' Attribute
    "missing samesite": "CWE-1275",  # Sensitive Cookie with Improper SameSite Attribute
    "csrf": "CWE-352",
    "session timeout": "CWE-613",
    "logout functionality": "CWE-613",  # Relates to proper session termination
    "cookie": "CWE-565",  # Reliance on Cookies without Validation and Integrity Checking
    "predictable session id": "CWE-330",  # Use of Insufficiently Random Values
}

AUTH_PATTERNS = {
    "python": {
        "django": ["authenticate", "login", "logout", "User", "UserManager", "password_validation", "make_password", "check_password", "SessionStore", "request.session"],
        "flask": ["Flask-Login", "login_user", "logout_user", "current_user", "login_required", "UserMixin", "werkzeug.security", "session", "g.user"],
        "fastapi": ["OAuth2PasswordBearer", "get_current_user", "verify_password", "create_access_token", "HTTPBearer", "Depends(fastapi_users.current_user)", "Session", "Cookie"],
        "core": ["hashlib", "bcrypt", "passlib", "secrets", "pbkdf2_hmac", "itsdangerous", "SimpleCookie"],
    },
    "javascript": {
        "express": ["passport", "jwt", "bcrypt", "jsonwebtoken", "authenticate", "strategy", "deserializeUser", "req.session", "express-session", "cookie-parser"],
        "core": ["localStorage.getItem", "sessionStorage.getItem", "document.cookie", "Authorization: Bearer", "crypto.subtle", "argon2", "scrypt", "jsonwebtoken.sign", "jsonwebtoken.verify"],
    },
    "java": {
        "spring": ["SecurityConfig", "WebSecurityConfigurerAdapter", "AuthenticationManager", "UserDetailsService", "@Secured", "PasswordEncoder", "BCryptPasswordEncoder", "HttpSession", "rememberMe"],
        "jee": ["login-config", "auth-method", "security-constraint", "Principal", "isUserInRole", "@RolesAllowed", "HttpServletRequest.getSession", "Cookie"],
        "core": ["MessageDigest", "SecureRandom", "Cipher", "KeyStore", "Basic Auth", "JAAS"],
    },
    "php": {
        "laravel": ["Auth::", "Hash::make", "bcrypt(", "Fortify", "Sanctum", "Passport", "Password::", "session(" , "request()->session()", "Cookie::"],
        "symfony": ["security.yaml", "UserInterface", "UserProviderInterface", "PasswordHasher", "GuardAuthenticator", "SessionInterface", "hasPreviousSession"],
        "core": ["password_hash(", "password_verify(", "hash_equals(", "session_start(", "$_SESSION", "$_COOKIE", "setcookie("],
    },
    # Add other languages from your AUTH_PATTERNS definition if needed by SessionManagementAgent
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
                    "LLM returned a single JSON object for findings (SessionAgent), expected array. Wrapping it."
                )
                return [loaded_json]
    except json.JSONDecodeError as e:
        logger.error(
            f"JSONDecodeError in _extract_json_from_llm_response (SessionManagementAgent): {e}. Response: {response_text[:500]}"
        )
    return None


def _identify_cwe_mappings(findings: List[Dict[str, Any]]) -> List[Dict[str, str]]:
    cwe_mappings = []
    for finding in findings:
        description = finding.get("description", "").lower()
        recommendation = finding.get("recommendation", "").lower()
        text_to_check = description + " " + recommendation
        mapped_cwe = False
        for keyword, cwe_id in SESSION_MANAGEMENT_CWE_MAP.items():
            if keyword in text_to_check:
                cwe_mappings.append(
                    {"description": finding.get("description", ""), "cwe_id": cwe_id}
                )
                mapped_cwe = True
                break
        if not mapped_cwe:
            logger.debug(
                f"No direct CWE keyword match for session management finding: {description}"
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
    agent_name_for_logging = "SessionManagementAgent_Assess"

    logger.info(
        f"SessionManagementAgent Node: assess_vulnerabilities for '{filename}' (Submission: {submission_id})"
    )

    if not code_snippet:
        return {
            "findings": [],
            "error": "Missing code snippet for SessionManagementAgent.",
        }

    asvs_guidance_for_prompt = ASVS_V3_GUIDELINES  # Defined in your existing agent file

    framework_context_str = f"The code is in {language}."
    if framework:
        framework_context_str += f" It appears to use the {framework} framework. Consider {framework}-specific session management mechanisms (e.g., built-in session handlers, cookie configurations)."

    # Provide context about common session related patterns if language is known
    # This can be expanded from AUTH_PATTERNS if specific session patterns are identified
    session_pattern_context = ""
    if (
        language.lower() in AUTH_PATTERNS
    ):  # AUTH_PATTERNS might contain session related keywords
        lang_auth_patterns = AUTH_PATTERNS[language.lower()]
        relevant_session_keywords = []
        for key, patterns in lang_auth_patterns.items():
            for p in patterns:
                if (
                    "session" in p.lower()
                    or "cookie" in p.lower()
                    or "token" in p.lower()
                    or "logout" in p.lower()
                    or "timeout" in p.lower()
                ):
                    relevant_session_keywords.append(p)
        if relevant_session_keywords:
            session_pattern_context = f"Relevant {language} keywords/patterns for session management include: {', '.join(list(set(relevant_session_keywords[:5])))}."

    trigger_context_str = ""
    expected_trigger_area = "V3_SessionManagement"
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
                f"Please verify and conduct a detailed assessment for session management vulnerabilities based on this context."
            )
        elif trigger_area:
            trigger_context_str = f"\nBroader context: Initial analysis highlighted '{trigger_area}' with likelihood '{task_context.get('likelihood_from_context_analysis', 'N/A')}' as relevant for this file. Consider this while focusing on session management."

    prompt = f"""
    Analyze the following {language} code snippet from file '{filename}' for security vulnerabilities related to OWASP ASVS V3 (Session Management).
    {framework_context_str}
    {session_pattern_context}
    {trigger_context_str}
    Focus on how session identifiers (cookies, tokens) are generated, transmitted, stored, and invalidated. Examine session timeout configurations, logout mechanisms, cookie security attributes (HttpOnly, Secure, SameSite), and protections against session fixation, hijacking, or replay.

    Refer to these ASVS V3 Guidelines:
    {asvs_guidance_for_prompt}

    Code Snippet:
    ```{language}
    {code_snippet}
    ```

    Task:
    1. Identify specific vulnerabilities related to session management.
    2. For each vulnerability found, provide:
        - "description": A concise description of the session management weakness.
        - "severity": Estimated severity (High, Medium, Low).
        - "line_start": Approximate starting line number of the vulnerable code.
        - "line_end": Approximate ending line number.
        - "recommendation": A specific recommendation for fixing the vulnerability (e.g., regenerate session ID on login, set secure cookie flags, implement proper timeouts).
        - "asvs_id": The primary ASVS V3 requirement ID it violates (e.g., "V3.1.1", "V3.6.1").
    3. If no session management vulnerabilities are found in this snippet, return an empty array.
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
                    f"SessionManagementAgent successfully assessed '{filename}', found {len(findings_output)} potential issues."
                )
            else:
                error_output = "Failed to parse JSON findings from LLM response for SessionManagementAgent assessment."
                logger.error(
                    f"{error_output} LLM raw response: {llm_result.content[:500]}"
                )
        else:
            error_output = (
                llm_result.error
                or "LLM call failed or returned no content for SessionManagementAgent assessment."
            )
            logger.error(
                f"SessionManagementAgent assessment LLM call failed for '{filename}': {error_output}"
            )

    except Exception as e:
        logger.exception(
            f"Exception during SessionManagementAgent assessment for '{filename}': {e}"
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
    agent_name_for_logging = "SessionManagementAgent_Fix"

    logger.info(
        f"SessionManagementAgent Node: generate_fixes for '{filename}' (Submission: {submission_id})"
    )

    if not findings:
        return {
            "fixed_code_snippet": code_snippet,
            "explanation": "No session management vulnerabilities were identified to fix.",
            "error": None,
        }

    issues_json = json.dumps(findings, indent=2)
    prompt = f"""
    The following {language} code snippet from file '{filename}' has session management vulnerabilities.
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
        Focus on secure session ID generation (using cryptographically secure random numbers), proper invalidation of sessions on logout and timeout, setting secure cookie attributes (HttpOnly, Secure, SameSite=Lax or Strict), regenerating session IDs upon any change in privilege level or authentication state, and adding CSRF protection if relevant to session tokens.
    3.  After the fixed code, provide a brief, clear "explanation" of key changes and why they improve session management security.
    4.  Return ONLY a single valid JSON object with two keys: "fixed_code" (string) and "explanation" (string).
    """

    llm = get_llm_client()
    llm_result: Optional[LLMResult] = None
    fixed_code_output = code_snippet
    explanation_output = (
        "Fix generation for session management issues failed or was not applicable."
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
                            f"Failed to parse extracted JSON for session management fix: {e_inner}"
                        )

            if (
                parsed_fix_object
                and "fixed_code" in parsed_fix_object
                and "explanation" in parsed_fix_object
            ):
                fixed_code_output = parsed_fix_object["fixed_code"]
                explanation_output = parsed_fix_object["explanation"]
                logger.info(
                    f"SessionManagementAgent successfully generated fix for '{filename}'."
                )
            else:
                error_output = "Failed to parse 'fixed_code' and 'explanation' from LLM response for SessionManagementAgent fix."
                logger.error(
                    f"{error_output} LLM raw response: {llm_result.content[:500]}"
                )
                explanation_output = error_output
        else:
            error_output = (
                llm_result.error
                or "LLM call failed or returned no content for SessionManagementAgent fix."
            )
            logger.error(
                f"SessionManagementAgent fix LLM call failed for '{filename}': {error_output}"
            )
            explanation_output = error_output

    except Exception as e:
        logger.exception(
            f"Exception during SessionManagementAgent fix generation for '{filename}': {e}"
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
        f"SessionManagementAgent Node: map_to_standards for '{state['filename']}' (Submission: {state['submission_id']})"
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
                    f"Finding in SessionManagementAgent for '{state['filename']}' is missing 'asvs_id': {finding.get('description')}"
                )

    cwe_mappings = _identify_cwe_mappings(findings)
    logger.info(
        f"Mapped {len(cwe_mappings)} findings to CWEs for SessionManagementAgent on '{state['filename']}'."
    )

    return {
        "asvs_mapping": asvs_mappings,
        "cwe_mapping": cwe_mappings,
        "error": state.get("error"),
    }


# --- Graph Construction ---
def build_session_management_agent_graph() -> Any:
    graph = StateGraph(SecurityAgentState)
    graph.add_node("assess_vulnerabilities", assess_vulnerabilities_node)
    graph.add_node("generate_fixes", generate_fixes_node)
    graph.add_node("map_to_standards", map_to_standards_node)

    graph.set_entry_point("assess_vulnerabilities")
    graph.add_edge("assess_vulnerabilities", "generate_fixes")
    graph.add_edge("generate_fixes", "map_to_standards")
    graph.add_edge("map_to_standards", END)

    compiled_graph = graph.compile()
    logger.info("SessionManagementAgent graph compiled successfully.")
    return compiled_graph
