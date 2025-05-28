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

# --- Constants for ASVS V4 Access Control (from collated_code.txt) ---
ASVS_V4_GUIDELINES = """
V4.1 General Access Control Design:
    - Apply "deny by default" principle for access controls
    - Enforce access controls consistently across the application
    - Ensure access controls remain effective during errors/exceptions
    - Implement principle of least privilege for all accounts

V4.2 Operation Level Access Control:
    - Verify sensitive operations enforce re-authentication
    - Verify sensitive resources/functions require specific permissions
    - Verify sensitive data access requires additional validation
    - Verify file operations include proper access controls

V4.3 Other Access Control Considerations:
    - Enforce anti-CSRF measures on all state-changing operations
    - Prevent parameter tampering to bypass access controls
    - Verify direct object reference protections
    - Implement proper segregation of roles and permissions
    - Prevent privilege escalation (vertical/horizontal)
    - Protect against timing attacks in access control decisions
    - Restrict access to authorized IPs/domains if applicable

V4.4 Access Control Implementation:
    - Centralize access control mechanisms
    - Protect access control metadata from tampering
    - Log all access control failures
    - Use rate limiting to prevent brute force attacks on access controls
"""

ACCESS_CONTROL_CWE_MAP = {
    "missing authorization": "CWE-862",
    "incorrect authorization": "CWE-863",
    "privilege escalation": "CWE-269",
    "insecure direct object reference": "CWE-639",  # IDOR
    "idor": "CWE-639",
    "csrf": "CWE-352",
    "business logic bypass": "CWE-840",  # Can relate to access control
    "broken access control": "CWE-284",
    "improper access control": "CWE-284",
    "horizontal privilege escalation": "CWE-639",  # Often a type of IDOR
    "vertical privilege escalation": "CWE-269",
    "user role": "CWE-286",  # Incorrect User Management
    "role-based": "CWE-285",  # Improper Authorization (more general than 932)
    "permission": "CWE-732",  # Incorrect Permission Assignment for Critical Resource
    "least privilege": "CWE-272",  # Least Privilege Violation
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
                    "LLM returned a single JSON object for findings (AccessControlAgent), expected array. Wrapping it."
                )
                return [loaded_json]
    except json.JSONDecodeError as e:
        logger.error(
            f"JSONDecodeError in _extract_json_from_llm_response (AccessControlAgent): {e}. Response: {response_text[:500]}"
        )
    return None


def _identify_cwe_mappings(findings: List[Dict[str, Any]]) -> List[Dict[str, str]]:
    cwe_mappings = []
    for finding in findings:
        description = finding.get("description", "").lower()
        recommendation = finding.get("recommendation", "").lower()
        text_to_check = description + " " + recommendation
        mapped_cwe = False
        for keyword, cwe_id in ACCESS_CONTROL_CWE_MAP.items():
            if keyword in text_to_check:
                cwe_mappings.append(
                    {"description": finding.get("description", ""), "cwe_id": cwe_id}
                )
                mapped_cwe = True
                break
        if not mapped_cwe:
            logger.debug(
                f"No direct CWE keyword match for access control finding: {description}"
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
    agent_name_for_logging = "AccessControlAgent_Assess"

    logger.info(
        f"AccessControlAgent Node: assess_vulnerabilities for '{filename}' (Submission: {submission_id})"
    )

    if not code_snippet:
        return {"findings": [], "error": "Missing code snippet for AccessControlAgent."}

    asvs_guidance_for_prompt = ASVS_V4_GUIDELINES  # Defined in your existing agent file

    framework_context_str = f"The code is in {language}."
    if framework:
        framework_context_str += f" It appears to use the {framework} framework. Consider {framework}-specific access control mechanisms (e.g., decorators like @permission_required, middleware for authorization, annotations for roles/permissions)."

    # Language-specific access control patterns (can be expanded)
    access_control_keywords = {
        "python": [
            "role",
            "permission",
            "has_permission",
            "is_admin",
            "is_staff",
            "decorator",
            "access_control_list",
            "acl",
            "getattr",
        ],
        "java": [
            "@RolesAllowed",
            "@Secured",
            "isUserInRole",
            "SecurityContext",
            "AccessDecisionManager",
            "ACL",
        ],
        "csharp": ["AuthorizeAttribute", "User.IsInRole", "IAuthorizationService"],
        "php": [
            "can(",
            "Gate::allows",
            "isGranted(",
            "$user->hasRole(",
        ],  # Common in frameworks like Laravel/Symfony
        "javascript": [
            "roles.includes(",
            "permissions.has(",
            "user.isAdmin",
            "checkAuth",
        ],
    }
    keyword_context_str = ""
    lang_keywords = access_control_keywords.get(language.lower(), [])
    if lang_keywords:
        detected_keywords = [
            kw
            for kw in lang_keywords
            if re.search(r"\b" + re.escape(kw) + r"\b", code_snippet, re.IGNORECASE)
        ]
        if detected_keywords:
            keyword_context_str = f"The code may use access control related keywords/patterns such as: {', '.join(list(set(detected_keywords[:5])))}."

    trigger_context_str = ""
    expected_trigger_area = "V4_AccessControl"
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
                f"Please verify and conduct a detailed assessment for access control vulnerabilities based on this context."
            )
        elif trigger_area:
            trigger_context_str = f"\nBroader context: Initial analysis highlighted '{trigger_area}' with likelihood '{task_context.get('likelihood_from_context_analysis', 'N/A')}' as relevant for this file. Consider this while focusing on access control."

    prompt = f"""
    Analyze the following {language} code snippet from file '{filename}' for security vulnerabilities related to OWASP ASVS V4 (Access Control).
    {framework_context_str}
    {keyword_context_str}
    {trigger_context_str}
    Focus on how the code enforces permissions, manages roles, protects against unauthorized access to functions or data (including Insecure Direct Object References - IDORs), and prevents privilege escalation (both vertical and horizontal). Examine if "deny by default" and "least privilege" principles are applied. Check for flaws in CSRF protection if state-changing operations are present.

    Refer to these ASVS V4 Guidelines:
    {asvs_guidance_for_prompt}

    Code Snippet:
    ```{language}
    {code_snippet}
    ```

    Task:
    1. Identify specific vulnerabilities related to access control.
    2. For each vulnerability found, provide:
        - "description": A concise description of the access control weakness (e.g., "Missing authorization check for admin function", "IDOR allowing access to other user's data via parameter 'userId'").
        - "severity": Estimated severity (High, Medium, Low).
        - "line_start": Approximate starting line number of the vulnerable code.
        - "line_end": Approximate ending line number.
        - "recommendation": A specific recommendation for fixing the vulnerability (e.g., "Implement a role check using @admin_required decorator", "Validate that 'userId' parameter matches the authenticated user's ID or that the user has explicit permission to access the target resource.").
        - "asvs_id": The primary ASVS V4 requirement ID it violates (e.g., "V4.1.1", "V4.3.2").
    3. If no access control vulnerabilities are found in this snippet, return an empty array.
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
                    f"AccessControlAgent successfully assessed '{filename}', found {len(findings_output)} potential issues."
                )
            else:
                error_output = "Failed to parse JSON findings from LLM response for AccessControlAgent assessment."
                logger.error(
                    f"{error_output} LLM raw response: {llm_result.content[:500]}"
                )
        else:
            error_output = (
                llm_result.error
                or "LLM call failed or returned no content for AccessControlAgent assessment."
            )
            logger.error(
                f"AccessControlAgent assessment LLM call failed for '{filename}': {error_output}"
            )

    except Exception as e:
        logger.exception(
            f"Exception during AccessControlAgent assessment for '{filename}': {e}"
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
    agent_name_for_logging = "AccessControlAgent_Fix"

    logger.info(
        f"AccessControlAgent Node: generate_fixes for '{filename}' (Submission: {submission_id})"
    )

    if not findings:
        return {
            "fixed_code_snippet": code_snippet,
            "explanation": "No access control vulnerabilities were identified to fix.",
            "error": None,
        }

    issues_json = json.dumps(findings, indent=2)
    prompt = f"""
    The following {language} code snippet from file '{filename}' has access control vulnerabilities.
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
        Focus on implementing proper authorization checks (e.g., role checks, permission checks before accessing resources or performing actions), mitigating IDORs by verifying object ownership or using indirect references, ensuring "deny by default" where applicable, and applying the principle of least privilege. If CSRF issues are noted, ensure appropriate token validation is added for state-changing requests.
    3.  After the fixed code, provide a brief, clear "explanation" of key changes and why they improve access control.
    4.  Return ONLY a single valid JSON object with two keys: "fixed_code" (string) and "explanation" (string).
    """

    llm = get_llm_client()
    llm_result: Optional[LLMResult] = None
    fixed_code_output = code_snippet
    explanation_output = (
        "Fix generation for access control issues failed or was not applicable."
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
                            f"Failed to parse extracted JSON for access control fix: {e_inner}"
                        )

            if (
                parsed_fix_object
                and "fixed_code" in parsed_fix_object
                and "explanation" in parsed_fix_object
            ):
                fixed_code_output = parsed_fix_object["fixed_code"]
                explanation_output = parsed_fix_object["explanation"]
                logger.info(
                    f"AccessControlAgent successfully generated fix for '{filename}'."
                )
            else:
                error_output = "Failed to parse 'fixed_code' and 'explanation' from LLM response for AccessControlAgent fix."
                logger.error(
                    f"{error_output} LLM raw response: {llm_result.content[:500]}"
                )
                explanation_output = error_output
        else:
            error_output = (
                llm_result.error
                or "LLM call failed or returned no content for AccessControlAgent fix."
            )
            logger.error(
                f"AccessControlAgent fix LLM call failed for '{filename}': {error_output}"
            )
            explanation_output = error_output

    except Exception as e:
        logger.exception(
            f"Exception during AccessControlAgent fix generation for '{filename}': {e}"
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
        f"AccessControlAgent Node: map_to_standards for '{state['filename']}' (Submission: {state['submission_id']})"
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
                    f"Finding in AccessControlAgent for '{state['filename']}' is missing 'asvs_id': {finding.get('description')}"
                )

    cwe_mappings = _identify_cwe_mappings(findings)
    logger.info(
        f"Mapped {len(cwe_mappings)} findings to CWEs for AccessControlAgent on '{state['filename']}'."
    )

    return {
        "asvs_mapping": asvs_mappings,
        "cwe_mapping": cwe_mappings,
        "error": state.get("error"),
    }


# --- Graph Construction ---
def build_access_control_agent_graph() -> (
    StateGraph
):  # Function name was incorrect in collated_code for this agent
    graph = StateGraph(SecurityAgentState)
    graph.add_node("assess_vulnerabilities", assess_vulnerabilities_node)
    graph.add_node("generate_fixes", generate_fixes_node)
    graph.add_node("map_to_standards", map_to_standards_node)

    graph.set_entry_point("assess_vulnerabilities")
    graph.add_edge("assess_vulnerabilities", "generate_fixes")
    graph.add_edge("generate_fixes", "map_to_standards")
    graph.add_edge("map_to_standards", END)

    compiled_graph = graph.compile()
    logger.info("AccessControlAgent graph compiled successfully.")
    return compiled_graph
