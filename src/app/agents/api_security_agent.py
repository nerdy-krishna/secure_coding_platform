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
    task_context: Optional[Dict[str, Any]]  # Context from CoordinatorAgent
    findings: Optional[List[Dict[str, Any]]]
    fixed_code_snippet: Optional[str]
    explanation: Optional[str]
    error: Optional[str]
    asvs_mapping: Optional[List[Dict[str, str]]]
    cwe_mapping: Optional[List[Dict[str, str]]]


logger = logging.getLogger(__name__)

# --- Constants for ASVS V13 API Security (from collated_code.txt) ---
ASVS_V13_GUIDELINES = """
V13.1 Generic Web Service Security:
    - Use same security controls for all API types (REST, SOAP, GraphQL, gRPC, etc.)
    - Verify all API endpoints enforce authentication
    - Implement defense in depth for API security
    - Verify all parameters are validated (type, length, format, bounds)
    - Validate content types in requests/responses
    - Implement proper error handling without leaking information

V13.2 RESTful Web Service Security:
    - Use proper HTTP methods (GET, POST, PUT, DELETE)
    - Validate URL structure and parameters
    - Implement stateless authentication
    - Avoid exposing internal object references (IDs)
    - Validate content negotiation
    - Use proper HTTP status codes and error responses

V13.3 SOAP Web Service Security:
    - Use WS-Security for authentication and integrity
    - Validate XML structure and content
    - Prevent XXE and XML injection attacks
    - Implement proper error handling and logging
    - Ensure proper access controls

V13.4 GraphQL and other API Security:
    - Implement complexity analysis for GraphQL queries
    - Prevent resource exhaustion via nested queries
    - Use proper rate limiting and pagination
    - Validate field-level permissions
    - Ensure proper authentication for all operations
"""

API_SECURITY_CWE_MAP = {
    "missing authentication": "CWE-306",
    "improper input validation": "CWE-20",  # Broader than just API but very relevant
    "excessive data exposure": "CWE-213",  # Was CWE-200, 213 is more specific to incompatible policies or overexposure
    "broken object level authorization": "CWE-285",  # (BOLA) or CWE-639 for IDOR aspects
    "bola": "CWE-285",
    "mass assignment": "CWE-915",
    "security misconfiguration": "CWE-16",  # Generic, can apply to API configs
    "injection": "CWE-74",  # Generic, but applies to SQLi, NoSQLi, Commandi in APIs
    "improper assets management": "CWE-1059",  # (e.g. deprecated API versions, unpatched systems)
    "insufficient logging & monitoring": "CWE-778",  # (was just insufficient logging)
    "rate limiting missing": "CWE-770",
    "lack of resources & rate limiting": "CWE-770",  # (was lack of resources)
    "missing cors": "CWE-942",  # Permissive Cross-domain Policy with Untrusted Domains
    "insecure deserialization": "CWE-502",  # Common in APIs
    "broken function level authorization": "CWE-862",  # Missing Authorization (more direct than 285)
    "bfla": "CWE-862",
    "inadequate error handling": "CWE-209",  # Information Exposure Through an Error Message
    "graphql depth limit": "CWE-770",  # Can lead to DoS
    "unvalidated redirect": "CWE-601",  # If API causes redirects
}  # Adapted slightly

API_FRAMEWORKS = {  # from collated_code.txt
    "python": {
        "flask": [
            "@app.route",
            "request",
            "jsonify",
            "Blueprint",
            "flask_restful",
            "Resource",
        ],
        "django": [
            "@api_view",
            "APIView",
            "viewsets",
            "serializers",
            "DRF",
            "rest_framework.decorators.api_view",
        ],
        "fastapi": [
            "@app.get",
            "@app.post",
            "APIRouter",
            "Path",
            "Query",
            "Body",
            "Depends",
            "HTTPException",
        ],
        "generic": ["http.server", "wsgiref", "werkzeug", "aiohttp.web"],
    },
    "javascript": {
        "express": [
            "app.get",
            "app.post",
            "router.get",
            "req.body",
            "res.json",
            "express.Router",
            "middleware",
        ],
        "nestjs": [
            "@Controller",
            "@Get",
            "@Post",
            "HttpService",
            "@nestjs/graphql",
            "GraphQLModule",
        ],
        "koa": ["ctx.body", "koa-router", "router.get"],
        "generic": ["http.createServer", "node-fetch", "axios.post"],
    },
    "java": {
        "spring": [
            "@RestController",
            "@RequestMapping",
            "@GetMapping",
            "@PostMapping",
            "ResponseEntity",
            "org.springframework.web.bind.annotation.*",
        ],
        "jaxrs": [
            "@Path",
            "@GET",
            "@POST",
            "@Produces",
            "@Consumes",
            "javax.ws.rs.*",
            "jakarta.ws.rs.*",
        ],
        "generic": ["Servlet", "HttpServlet", "doGet", "doPost", "Spark.get"],
    },
    "csharp": {
        "aspnetcore": [
            "[HttpGet]",
            "[HttpPost]",
            "ControllerBase",
            "IActionResult",
            "Microsoft.AspNetCore.Mvc.*",
            "MapGet",
        ],
        "generic": ["HttpListener", "HttpClient.PostAsync"],
    },
    "php": {
        "laravel": [
            "Route::apiResource",
            "Route::get",
            "Controller",
            "request->input()",
            "response()->json()",
        ],
        "symfony": [
            "#[Route('/api')]",
            "AbstractController",
            "JsonResponse",
            "Request::createFromGlobals",
        ],
        "generic": [
            "$_GET",
            "$_POST",
            "file_get_contents('php://input')",
            "header('Content-Type: application/json')",
        ],
    },
    "ruby": {
        "rails": [
            "resources :, api: true",
            "namespace :api",
            "ApplicationController::API",
            "render json:",
        ],
        "sinatra": ["get '/api'", "post '/api'", "content_type :json"],
        "grape": ["Grape::API", "resource", "get"],
    },
    "go": {
        "gin": ["gin.Engine", "router.GET", "router.POST", "c.JSON", "c.BindJSON"],
        "echo": ["e.GET", "e.POST", "c.JSON", "c.Bind"],
        "generic": [
            "net/http.HandleFunc",
            "http.ListenAndServe",
            "json.NewDecoder(r.Body)",
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
                    "LLM returned a single JSON object for findings (APISecurityAgent), expected array. Wrapping it."
                )
                return [loaded_json]
    except json.JSONDecodeError as e:
        logger.error(
            f"JSONDecodeError in _extract_json_from_llm_response (APISecurityAgent): {e}. Response: {response_text[:500]}"
        )
    return None


def _identify_cwe_mappings(findings: List[Dict[str, Any]]) -> List[Dict[str, str]]:
    cwe_mappings = []
    for finding in findings:
        description = finding.get("description", "").lower()
        recommendation = finding.get("recommendation", "").lower()
        text_to_check = description + " " + recommendation
        mapped_cwe = False
        for keyword, cwe_id in API_SECURITY_CWE_MAP.items():
            if keyword in text_to_check:
                cwe_mappings.append(
                    {"description": finding.get("description", ""), "cwe_id": cwe_id}
                )
                mapped_cwe = True
                break
        if not mapped_cwe:
            logger.debug(
                f"No direct CWE keyword match for API security finding: {description}"
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
    agent_name_for_logging = "APISecurityAgent_Assess"

    logger.info(
        f"APISecurityAgent Node: assess_vulnerabilities for '{filename}' (Submission: {submission_id})"
    )

    if not code_snippet:
        return {"findings": [], "error": "Missing code snippet for APISecurityAgent."}

    asvs_guidance_for_prompt = ASVS_V13_GUIDELINES

    api_patterns_lang = API_FRAMEWORKS.get(language.lower(), {})
    framework_api_patterns = (
        api_patterns_lang.get(framework.lower(), []) if framework else []
    )
    generic_api_patterns = api_patterns_lang.get("generic", [])
    relevant_api_patterns = framework_api_patterns + generic_api_patterns

    pattern_context_str = ""
    if relevant_api_patterns:
        # Handle potential wildcards in patterns if necessary, e.g. replace '*' with '.*' for regex
        detected_api_patterns = [
            p
            for p in relevant_api_patterns
            if re.search(
                r"\b" + re.escape(p).replace("\\*", ".*") + r"\b",
                code_snippet,
                re.IGNORECASE,
            )
        ]
        if detected_api_patterns:
            pattern_context_str = f"The code appears to implement API endpoints, possibly using patterns like: {', '.join(list(set(detected_api_patterns[:5])))}."

    framework_context_str = f"The code is in {language}."
    if framework:
        framework_context_str += f" It seems to be using the {framework} framework."

    api_type_context_from_task = task_context.get(
        "api_type", "generic RESTful or web API"
    )
    # Use api_type from task_context if CoordinatorAgent provides it.
    # The original version of this node in collated_code.txt had an _detect_api_framework helper.
    # For now, we simplify and rely on context passed or general analysis.
    # If more sophisticated API type detection is needed here, that helper could be reinstated or enhanced.

    trigger_context_str = ""
    expected_trigger_area = "V13_APISecurity"
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
                f"Please verify and conduct a detailed assessment for API security vulnerabilities based on this context."
            )
        elif trigger_area:  # Context provided but not directly for this agent
            trigger_context_str = f"\nBroader context: Initial analysis highlighted '{trigger_area}' with likelihood '{task_context.get('likelihood_from_context_analysis', 'N/A')}' as relevant for this file. Consider this while focusing on API security."
        # Add specific API endpoint info if available in task_context
        if task_context.get("api_endpoints"):
            trigger_context_str += f"\nRelevant API endpoints identified for deeper review: {task_context.get('api_endpoints')}"

    prompt = f"""
    Analyze the following {language} code snippet from file '{filename}' for security vulnerabilities related to OWASP ASVS V13 (API and Web Service Security).
    The API type is likely: {api_type_context_from_task}.
    {framework_context_str}
    {pattern_context_str}
    {trigger_context_str}
    Focus on identifying issues such as missing or broken authentication/authorization at API endpoints, improper input validation for API parameters (query, path, body), excessive data exposure in responses, mass assignment vulnerabilities, security misconfigurations specific to APIs (e.g., CORS, rate limiting), injection flaws in API context, and insecure deserialization. For GraphQL, consider query complexity and depth.

    Refer to these ASVS V13 Guidelines:
    {asvs_guidance_for_prompt}

    Code Snippet:
    ```{language}
    {code_snippet}
    ```

    Task:
    1. Identify specific vulnerabilities related to API security.
    2. For each vulnerability found, provide:
        - "description": A concise description of the API security weakness.
        - "severity": Estimated severity (High, Medium, Low).
        - "line_start": Approximate starting line number of the vulnerable code.
        - "line_end": Approximate ending line number.
        - "recommendation": A specific recommendation for fixing the vulnerability (e.g., implement JWT auth, validate all input parameters, apply field masking, configure rate limits).
        - "asvs_id": The primary ASVS V13 requirement ID it violates (e.g., "V13.1.2", "V13.2.4").
    3. If no API security vulnerabilities are found in this snippet, return an empty array.
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
                    f"APISecurityAgent successfully assessed '{filename}', found {len(findings_output)} potential issues."
                )
            else:
                error_output = "Failed to parse JSON findings from LLM response for APISecurityAgent assessment."
                logger.error(
                    f"{error_output} LLM raw response: {llm_result.content[:500]}"
                )
        else:
            error_output = (
                llm_result.error
                or "LLM call failed or returned no content for APISecurityAgent assessment."
            )
            logger.error(
                f"APISecurityAgent assessment LLM call failed for '{filename}': {error_output}"
            )

    except Exception as e:
        logger.exception(
            f"Exception during APISecurityAgent assessment for '{filename}': {e}"
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
    agent_name_for_logging = "APISecurityAgent_Fix"

    logger.info(
        f"APISecurityAgent Node: generate_fixes for '{filename}' (Submission: {submission_id})"
    )

    if not findings:
        return {
            "fixed_code_snippet": code_snippet,
            "explanation": "No API security vulnerabilities were identified to fix.",
            "error": None,
        }

    issues_json = json.dumps(findings, indent=2)
    prompt = f"""
    The following {language} code snippet from file '{filename}' has API security vulnerabilities.
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
        Focus on implementing robust authentication (e.g., token-based), fine-grained authorization (checking permissions for specific actions/resources), strict input validation for all API parameters (headers, query params, body), output encoding/data sanitization for responses, and secure configurations (e.g., rate limiting, CORS).
    3.  After the fixed code, provide a brief, clear "explanation" of key changes and why they improve API security.
    4.  Return ONLY a single valid JSON object with two keys: "fixed_code" (string) and "explanation" (string).
    """

    llm = get_llm_client()
    llm_result: Optional[LLMResult] = None
    fixed_code_output = code_snippet
    explanation_output = (
        "Fix generation for API security issues failed or was not applicable."
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
                            f"Failed to parse extracted JSON for API security fix: {e_inner}"
                        )

            if (
                parsed_fix_object
                and "fixed_code" in parsed_fix_object
                and "explanation" in parsed_fix_object
            ):
                fixed_code_output = parsed_fix_object["fixed_code"]
                explanation_output = parsed_fix_object["explanation"]
                logger.info(
                    f"APISecurityAgent successfully generated fix for '{filename}'."
                )
            else:
                error_output = "Failed to parse 'fixed_code' and 'explanation' from LLM response for APISecurityAgent fix."
                logger.error(
                    f"{error_output} LLM raw response: {llm_result.content[:500]}"
                )
                explanation_output = error_output
        else:
            error_output = (
                llm_result.error
                or "LLM call failed or returned no content for APISecurityAgent fix."
            )
            logger.error(
                f"APISecurityAgent fix LLM call failed for '{filename}': {error_output}"
            )
            explanation_output = error_output

    except Exception as e:
        logger.exception(
            f"Exception during APISecurityAgent fix generation for '{filename}': {e}"
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
        f"APISecurityAgent Node: map_to_standards for '{state['filename']}' (Submission: {state['submission_id']})"
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
                    f"Finding in APISecurityAgent for '{state['filename']}' is missing 'asvs_id': {finding.get('description')}"
                )

    cwe_mappings = _identify_cwe_mappings(findings)
    logger.info(
        f"Mapped {len(cwe_mappings)} findings to CWEs for APISecurityAgent on '{state['filename']}'."
    )

    return {
        "asvs_mapping": asvs_mappings,
        "cwe_mapping": cwe_mappings,
        "error": state.get("error"),
    }


# --- Graph Construction ---
def build_api_security_agent_graph() -> Any:
    graph = StateGraph(SecurityAgentState)
    graph.add_node("assess_vulnerabilities", assess_vulnerabilities_node)
    graph.add_node("generate_fixes", generate_fixes_node)
    graph.add_node("map_to_standards", map_to_standards_node)

    graph.set_entry_point("assess_vulnerabilities")
    graph.add_edge("assess_vulnerabilities", "generate_fixes")
    graph.add_edge("generate_fixes", "map_to_standards")
    graph.add_edge("map_to_standards", END)

    compiled_graph = graph.compile()
    logger.info("APISecurityAgent graph compiled successfully.")
    return compiled_graph
