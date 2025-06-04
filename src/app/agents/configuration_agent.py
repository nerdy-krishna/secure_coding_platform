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

# --- Constants for ASVS V14 Configuration (from collated_code.txt) ---
ASVS_V14_GUIDELINES = """
V14.1 Build and Deploy:
    - Remove debugging capabilities and developer documentation
    - Remove development, test, or configuration files
    - Verify the HTTP headers or security directives are properly configured
    - Ensure dependencies are kept up to date
    - Ensure a proper CI/CD pipeline with security checks
    - Configure secure HTTP headers (CSP, X-Frame-Options, etc.)

V14.2 Dependency Management:
    - Verify all components are up-to-date
    - Use only latest versions of dependencies
    - Remove unnecessary dependencies and features
    - Verify safe source build and deployment of components
    - Ensure components come from trusted sources
    - Implement proper dependency vulnerability scanning

V14.3 Unintended Security Disclosure:
    - Verify web or application server remove debug information
    - Ensure stack traces are not displayed to users
    - Remove unnecessary configuration files
    - Exclude sensitive data from debug output
    - Configure appropriate security headers

V14.4 HTTP Security Headers:
    - Configure Content Security Policy (CSP)
    - Enable X-Content-Type-Options: nosniff
    - Configure X-Frame-Options to prevent clickjacking
    - Set Strict-Transport-Security (HSTS) for HTTPS
    - Implement proper cache control headers
    - Use secure cookie attributes (Secure, HttpOnly, SameSite)
"""

CONFIG_CWE_MAP = {
    "security misconfiguration": "CWE-16",  # General Security Misconfiguration
    "missing security header": "CWE-693",  # Protection Mechanism Failure (e.g., missing X-Frame-Options)
    "csp missing": "CWE-693",  # CSP is a protection mechanism
    "outdated component": "CWE-1104",  # Use of Unmaintained Third Party Components
    "outdated dependency": "CWE-1104",
    "verbose error message": "CWE-209",  # Information Exposure Through an Error Message
    "debug mode enabled": "CWE-489",  # Active Debug Code
    "default credentials": "CWE-798",  # Use of Hard-coded Credentials (if related to default configs)
    "information disclosure": "CWE-200",  # Exposure of Sensitive Information to an Unauthorized Actor
    "insecure default": "CWE-1188",  # Insecure Default Initialization of Resource
    "unnecessary features enabled": "CWE-1048",  # Unnecessary Privileges or Functionality
    "improper permissions on config files": "CWE-732",  # Incorrect Permission Assignment for Critical Resource
    "hardcoded secrets in config": "CWE-798",
}  # Adapted slightly

CONFIG_PATTERNS = {  # from collated_code.txt
    "python": {
        "flask": [
            "app.config",
            "Flask(__name__)",
            "app.run(debug=True)",
            "CORS",
            "werkzeug.debug",
        ],
        "django": [
            "settings.py",
            "DEBUG = True",
            "ALLOWED_HOSTS",
            "MIDDLEWARE",
            "INSTALLED_APPS",
            "SECURE_",
        ],
        "fastapi": [
            "app = FastAPI(",
            "CORSMiddleware",
            "allow_origins=['*']",
            "debug=True",
        ],
        "generic": [
            "config.ini",
            "settings.json",
            "os.environ.get",
            ".env",
            "DEBUG",
            "development_mode",
        ],
    },
    "javascript": {
        "express": [
            "app.use(cors())",
            "helmet()",
            "morgan('dev')",
            "process.env.NODE_ENV !== 'production'",
        ],
        "nodejs": [
            "package.json",
            "dependencies",
            "devDependencies",
            "process.env.DEBUG",
            "config.js",
        ],
        "react": [
            ".env.development",
            "webpack.config.js",
            "babel.config.js",
            "public/index.html",
        ],  # Added public/index.html for meta tags
        "generic": ["config.json", ".env", "environment.js", "debug: true"],
    },
    "java": {
        "spring": [
            "application.properties",
            "application.yml",
            "SecurityConfig",
            "@Profile('dev')",
            "logging.level.root=DEBUG",
        ],
        "generic": [
            "web.xml",
            "server.xml",
            "config.properties",
            "log4j.properties",
            "System.getProperty('debug')",
        ],
    },
    "generic": [  # General keywords applicable across languages/frameworks for config files/code
        "config",
        "settings",
        "environment",
        "setup",
        "initialization",
        "security.headers",
        "debug=true",
        "verbose_errors=true",
        "trace_enabled=true",
        "default_password",
        "admin_token",
        "secret_key = ['\"]changeme['\"]",
    ],
}

SECURITY_HEADERS = {  # from collated_code.txt
    "generic": [
        "Content-Security-Policy",
        "X-Content-Type-Options",
        "X-Frame-Options",
        "Strict-Transport-Security",
        "X-XSS-Protection",
        "Referrer-Policy",
        "Permissions-Policy",
        "Cache-Control",
    ],
    "flask": [
        "response.headers['X-Frame-Options'] = 'DENY'"
    ],  # Example how Flask might set it
    "django": [
        "SECURE_BROWSER_XSS_FILTER",
        "SECURE_CONTENT_TYPE_NOSNIFF",
        "SecurityMiddleware",
    ],
    "express": [
        "app.use(helmet())",
        "app.disable('x-powered-by')",
    ],  # Helmet sets many headers
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
                    "LLM returned a single JSON object for findings (ConfigAgent), expected array. Wrapping it."
                )
                return [loaded_json]
    except json.JSONDecodeError as e:
        logger.error(
            f"JSONDecodeError in _extract_json_from_llm_response (ConfigurationAgent): {e}. Response: {response_text[:500]}"
        )
    return None


def _identify_cwe_mappings(findings: List[Dict[str, Any]]) -> List[Dict[str, str]]:
    cwe_mappings = []
    for finding in findings:
        description = finding.get("description", "").lower()
        recommendation = finding.get("recommendation", "").lower()
        text_to_check = description + " " + recommendation
        mapped_cwe = False
        for keyword, cwe_id in CONFIG_CWE_MAP.items():
            if keyword in text_to_check:
                cwe_mappings.append(
                    {"description": finding.get("description", ""), "cwe_id": cwe_id}
                )
                mapped_cwe = True
                break
        if not mapped_cwe:
            logger.debug(
                f"No direct CWE keyword match for configuration finding: {description}"
            )
    return cwe_mappings


# --- Node Functions ---


async def assess_vulnerabilities_node(state: SecurityAgentState) -> Dict[str, Any]:
    submission_id = state["submission_id"]
    filename = state["filename"]
    code_snippet = state["code_snippet"]  # This could be code or a config file content
    language = state["language"]  # Could be 'config' or a programming language
    framework = state.get("framework")
    task_context = state.get("task_context", {})  # Kept
    agent_name_for_logging = "ConfigurationAgent_Assess"

    logger.info(
        f"ConfigurationAgent Node: assess_vulnerabilities for '{filename}' (Submission: {submission_id})"
    )

    if not code_snippet:
        return {
            "findings": [],
            "error": "Missing code/configuration snippet for ConfigurationAgent.",
        }

    asvs_guidance_for_prompt = ASVS_V14_GUIDELINES

    config_patterns_lang_specific = CONFIG_PATTERNS.get(language.lower(), {})
    config_patterns_framework = (
        config_patterns_lang_specific.get(framework.lower(), []) if framework else []
    )
    config_patterns_generic_lang = config_patterns_lang_specific.get("generic", [])
    config_patterns_truly_generic = CONFIG_PATTERNS.get(
        "generic", []
    )  # General config keywords

    all_relevant_patterns = list(
        set(
            config_patterns_framework
            + config_patterns_generic_lang
            + config_patterns_truly_generic
        )
    )  # Use set to avoid duplicates
    pattern_context_str = ""
    if all_relevant_patterns:
        # Handle potential wildcards in patterns if necessary, e.g. replace '*' with '.*' for regex
        detected_patterns = [
            p
            for p in all_relevant_patterns
            if re.search(
                r"\b" + re.escape(p).replace("\\*", ".*") + r"\b",
                code_snippet,
                re.IGNORECASE,
            )
        ]
        if detected_patterns:
            pattern_context_str = f"The content appears to be related to configuration, possibly involving patterns like: {', '.join(list(set(detected_patterns[:7])))} (and potentially others)."

    framework_context_str = f"The content is from a file named '{filename}', potentially related to language/type '{language}'."
    if framework:
        framework_context_str += f" The project might use the {framework} framework."

    target_env_context = task_context.get(
        "environment", "a production or similarly sensitive environment"
    )
    if not target_env_context:  # Ensure a default
        target_env_context = "a production or similarly sensitive environment"

    trigger_context_str = ""
    expected_trigger_area = "V14_Configuration"
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
                f"Please verify and conduct a detailed assessment for configuration vulnerabilities based on this context, assuming it is for '{target_env_context}'."
            )
        elif trigger_area:
            trigger_context_str = f"\nBroader context: Initial analysis highlighted '{trigger_area}' with likelihood '{task_context.get('likelihood_from_context_analysis', 'N/A')}' as relevant for this file. Consider this while focusing on its configuration, assuming it's for '{target_env_context}'."
        else:  # If no specific trigger_area, still mention target env
            trigger_context_str = (
                f"\nAssume the configuration is for '{target_env_context}'."
            )

    prompt = f"""
    Analyze the following content from file '{filename}' for security misconfigurations and vulnerabilities related to OWASP ASVS V14 (Configuration).
    {framework_context_str}
    {pattern_context_str}
    {trigger_context_str}

    Focus on identifying issues such as enabled debugging features in production, insecure default settings, missing or weak security headers (CSP, HSTS, X-Frame-Options, X-Content-Type-Options, etc.), outdated or unnecessary dependencies (if discernible from configuration), exposure of sensitive information within the configuration, and improper build/deployment practices if evident from the content.

    Refer to these ASVS V14 Guidelines:
    {asvs_guidance_for_prompt}

    Content Snippet (could be code that sets configuration, or a configuration file like JSON, YAML, .properties, XML etc.):
    ```text
    {code_snippet}
    ```

    Task:
    1. Identify specific vulnerabilities related to insecure configuration.
    2. For each vulnerability found, provide:
        - "description": A concise description of the misconfiguration or weakness.
        - "severity": Estimated severity (High, Medium, Low).
        - "line_start": Approximate starting line number (or N/A if not applicable to the finding type, e.g., a missing header).
        - "line_end": Approximate ending line number (or N/A).
        - "recommendation": A specific recommendation for fixing the vulnerability (e.g., set 'DEBUG=False', add specific HTTP header, update dependency, remove hardcoded secret).
        - "asvs_id": The primary ASVS V14 requirement ID it violates (e.g., "V14.1.1", "V14.4.2").
    3. If no configuration vulnerabilities are found in this snippet, return an empty array.
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
                    f"ConfigurationAgent successfully assessed '{filename}', found {len(findings_output)} potential issues."
                )
            else:
                error_output = "Failed to parse JSON findings from LLM response for ConfigurationAgent assessment."
                logger.error(
                    f"{error_output} LLM raw response: {llm_result.content[:500]}"
                )
        else:
            error_output = (
                llm_result.error
                or "LLM call failed or returned no content for ConfigurationAgent assessment."
            )
            logger.error(
                f"ConfigurationAgent assessment LLM call failed for '{filename}': {error_output}"
            )

    except Exception as e:
        logger.exception(
            f"Exception during ConfigurationAgent assessment for '{filename}': {e}"
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
    code_snippet = state["code_snippet"]  # Content of the config file or related code
    language = state["language"]
    findings = state.get("findings") or []
    agent_name_for_logging = "ConfigurationAgent_Fix"

    logger.info(
        f"ConfigurationAgent Node: generate_fixes for '{filename}' (Submission: {submission_id})"
    )

    if not findings:
        return {
            "fixed_code_snippet": code_snippet,
            "explanation": "No configuration vulnerabilities were identified to fix.",
            "error": None,
        }

    issues_json = json.dumps(findings, indent=2)
    prompt = f"""
    The following content from file '{filename}' (language/type: {language}) has security misconfigurations.
    Your task is to provide a fixed version of the content and an explanation of the fixes.

    Original Content Snippet:
    ```text
    {code_snippet}
    ```

    Identified Vulnerabilities:
    {issues_json}

    Instructions:
    1.  Review the original content and vulnerabilities.
    2.  Provide a complete, fixed version of the content snippet addressing ALL listed vulnerabilities.
        Focus on disabling debug modes for production, setting secure HTTP headers (e.g., Content-Security-Policy: default-src 'self'; script-src 'self' 'unsafe-inline'; object-src 'none'; base-uri 'self';, Strict-Transport-Security, X-Frame-Options: DENY, X-Content-Type-Options: nosniff), removing hardcoded secrets (suggesting environment variables or vault usage like '{{{{ 환경변수_이름 }}}}' or 'VAULT:secret/path'), and correcting insecure defaults.
    3.  If the content is a configuration file (e.g., JSON, YAML, properties, XML), provide the fixed configuration file content. If it's code that sets configurations (e.g., Python, Java), provide the fixed code.
    4.  After the fixed content, provide a brief, clear "explanation" of key changes and why they improve security configuration.
    5.  Return ONLY a single valid JSON object with two keys: "fixed_code" (string, the fixed content) and "explanation" (string).
    """

    llm = get_llm_client()
    llm_result: Optional[LLMResult] = None
    fixed_code_output = code_snippet
    explanation_output = (
        "Fix generation for configuration issues failed or was not applicable."
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
                            f"Failed to parse extracted JSON for configuration fix: {e_inner}"
                        )

            if (
                parsed_fix_object
                and "fixed_code" in parsed_fix_object
                and "explanation" in parsed_fix_object
            ):
                fixed_code_output = parsed_fix_object["fixed_code"]
                explanation_output = parsed_fix_object["explanation"]
                logger.info(
                    f"ConfigurationAgent successfully generated fix for '{filename}'."
                )
            else:
                error_output = "Failed to parse 'fixed_code' and 'explanation' from LLM response for ConfigurationAgent fix."
                logger.error(
                    f"{error_output} LLM raw response: {llm_result.content[:500]}"
                )
                explanation_output = error_output
        else:
            error_output = (
                llm_result.error
                or "LLM call failed or returned no content for ConfigurationAgent fix."
            )
            logger.error(
                f"ConfigurationAgent fix LLM call failed for '{filename}': {error_output}"
            )
            explanation_output = error_output

    except Exception as e:
        logger.exception(
            f"Exception during ConfigurationAgent fix generation for '{filename}': {e}"
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
        f"ConfigurationAgent Node: map_to_standards for '{state['filename']}' (Submission: {state['submission_id']})"
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
                    f"Finding in ConfigurationAgent for '{state['filename']}' is missing 'asvs_id': {finding.get('description')}"
                )

    cwe_mappings = _identify_cwe_mappings(findings)
    logger.info(
        f"Mapped {len(cwe_mappings)} findings to CWEs for ConfigurationAgent on '{state['filename']}'."
    )

    return {
        "asvs_mapping": asvs_mappings,
        "cwe_mapping": cwe_mappings,
        "error": state.get("error"),
    }


# --- Graph Construction ---
def build_configuration_agent_graph() -> Any:
    graph = StateGraph(SecurityAgentState)
    graph.add_node("assess_vulnerabilities", assess_vulnerabilities_node)
    graph.add_node("generate_fixes", generate_fixes_node)
    graph.add_node("map_to_standards", map_to_standards_node)

    graph.set_entry_point("assess_vulnerabilities")
    graph.add_edge("assess_vulnerabilities", "generate_fixes")
    graph.add_edge("generate_fixes", "map_to_standards")
    graph.add_edge("map_to_standards", END)

    compiled_graph = graph.compile()
    logger.info("ConfigurationAgent graph compiled successfully.")
    return compiled_graph
