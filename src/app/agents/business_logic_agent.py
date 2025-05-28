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

# --- Constants for ASVS V11 Business Logic (from collated_code.txt) ---
ASVS_V11_GUIDELINES = """
V11.1 Business Logic Security:
    - Verify business logic flows proceed in sequential order and cannot be bypassed
    - Verify business logic limits or prevents mass data extraction
    - Verify protection against denial of service attacks
    - Verify appropriate limits are in place for business functionality
    - Verify critical operations require re-authentication, CAPTCHA, etc.

V11.2 Transaction Integrity:
    - Ensure transaction integrity is maintained, especially for critical operations
    - Verify the application processes high-value transactions with different rates, values, or frequencies than expected
    - Ensure operations cannot be replayed or tampered with
    - Verify race conditions cannot be exploited (especially in multi-step operations)
    - Ensure proper access controls during multi-step transactions

V11.3 Time-Based Logic:
    - Protect against time-of-check time-of-use (TOCTOU) attacks
    - Verify time-sensitive operations only occur within an acceptable time window
    - Ensure proper enforcement of cooldown periods, reset limits, etc.
    - Protect against manipulation of server-side timestamps
    - Ensure time-sensitive operations can't be abused by automated tools
"""

BUSINESS_LOGIC_CWE_MAP = {
    "race condition": "CWE-362",  # Concurrent Execution using Shared Resource with Improper Synchronization
    "toctou": "CWE-367",  # Time-of-check Time-of-use Race Condition
    "business logic flaw": "CWE-840",  # Business Logic Errors
    "improper business logic": "CWE-840",
    "rate limit abuse": "CWE-770",  # Allocation of Resources Without Limits or Throttling
    "mass assignment": "CWE-915",  # Improperly Controlled Modification of Dynamically-Determined Object Attributes
    "insecure business flow": "CWE-840",
    "privilege escalation through logic": "CWE-269",  # Improper Privilege Management (if logic flaw leads to it)
    "insufficient re-authentication": "CWE-294",  # Authentication Bypass by Capture-replay (if critical op lacks re-auth)
    "session replay": "CWE-384",  # Session Fixation (if session handling in logic is flawed)
    "denial of service": "CWE-400",  # Uncontrolled Resource Consumption (if logic leads to DoS)
    "transaction replay": "CWE-294",  # Can be CWE-404 if it's about lack of atomicity.
    "insufficient anti-automation": "CWE-799",  # Improper Control of Interaction Frequency
    "logic bypass": "CWE-840",  # (or CWE-693 if protection mechanism fails)
    "atomicity issue": "CWE-662",  # Improper Synchronization
    "missing lock": "CWE-413",  # Improper Resource Locking
    "parameter tampering": "CWE-840",  # Can be CWE-472 if external parameters control behavior
}  # Adapted slightly

CONCURRENCY_PATTERNS = {  # from collated_code.txt
    "python": [
        "threading",
        "multiprocessing",
        "asyncio",
        "Lock",
        "Semaphore",
        "Queue",
        "atomic",
        "transaction.atomic",
    ],
    "java": [
        "synchronized",
        "volatile",
        "AtomicInteger",
        "java.util.concurrent.locks.Lock",
        "Semaphore",
        "ConcurrentHashMap",
        "@Transactional",
        "ThreadLocal",
    ],
    "javascript": [
        "Promise.all",
        "async/await",
        "WebWorkers",
        "Atomics",
        "Mutex (library)",
        "Redlock (for Redis)",
    ],
    "php": ["pcntl_fork", "pthreads", "ReactPHP", "Amp", "DB::transaction", "flock"],
    "csharp": [
        "lock",
        "Mutex",
        "SemaphoreSlim",
        "Interlocked",
        "async/await",
        "Task",
        "TransactionScope",
        "Monitor.Enter",
    ],
    "ruby": [
        "Mutex",
        "Thread",
        "Celluloid",
        "ConcurrentRuby",
        "ActiveRecord::Base.transaction",
    ],
    "go": [
        "sync.Mutex",
        "sync.RWMutex",
        "sync.WaitGroup",
        "atomic",
        "chan",
        "select",
        "goroutine",
        "context.Context",
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
                    "LLM returned a single JSON object for findings (BusinessLogicAgent), expected array. Wrapping it."
                )
                return [loaded_json]
    except json.JSONDecodeError as e:
        logger.error(
            f"JSONDecodeError in _extract_json_from_llm_response (BusinessLogicAgent): {e}. Response: {response_text[:500]}"
        )
    return None


def _identify_cwe_mappings(findings: List[Dict[str, Any]]) -> List[Dict[str, str]]:
    cwe_mappings = []
    for finding in findings:
        description = finding.get("description", "").lower()
        recommendation = finding.get("recommendation", "").lower()
        text_to_check = description + " " + recommendation
        mapped_cwe = False
        for keyword, cwe_id in BUSINESS_LOGIC_CWE_MAP.items():
            if keyword in text_to_check:
                cwe_mappings.append(
                    {"description": finding.get("description", ""), "cwe_id": cwe_id}
                )
                mapped_cwe = True
                break
        if not mapped_cwe:
            logger.debug(
                f"No direct CWE keyword match for business logic finding: {description}"
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
    agent_name_for_logging = "BusinessLogicAgent_Assess"

    logger.info(
        f"BusinessLogicAgent Node: assess_vulnerabilities for '{filename}' (Submission: {submission_id})"
    )

    if not code_snippet:
        return {"findings": [], "error": "Missing code snippet for BusinessLogicAgent."}

    asvs_guidance_for_prompt = (
        ASVS_V11_GUIDELINES  # Defined in your existing agent file
    )

    concurrency_patterns_lang = CONCURRENCY_PATTERNS.get(language.lower(), [])
    detected_concurrency_patterns = [
        p
        for p in concurrency_patterns_lang
        if re.search(r"\b" + re.escape(p) + r"\b", code_snippet, re.IGNORECASE)
    ]
    concurrency_context_str = ""
    if detected_concurrency_patterns:
        concurrency_context_str = f"The code may use concurrency or transaction patterns like: {', '.join(list(set(detected_concurrency_patterns[:5])))}. Examine for race conditions, atomicity issues, and transaction integrity."

    framework_context_str = f"The code is in {language}."
    if framework:
        framework_context_str += f" It might be using the {framework} framework; consider its transaction management or stateful processing features."

    # Use business_context from task_context if provided by CoordinatorAgent
    business_process_description = task_context.get(
        "business_context",
        "The specific business process this code supports is not fully known. Analyze based on common application logic flows such as user workflows, financial transactions, or data processing steps.",
    )
    if (
        not business_process_description or business_process_description == "N/A"
    ):  # Ensure a good default
        business_process_description = "Analyze based on common application business logic like ordering, payments, user workflows, data state transitions, etc."

    trigger_context_str = ""
    expected_trigger_area = "V11_BusinessLogic"
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
                f"Please verify and conduct a detailed assessment for business logic vulnerabilities considering: {business_process_description}."
            )
        elif trigger_area:
            trigger_context_str = f"\nBroader context: Initial analysis highlighted '{trigger_area}' with likelihood '{task_context.get('likelihood_from_context_analysis', 'N/A')}' as relevant for this file. Consider this while focusing on its business logic impact, given: {business_process_description}."
        else:  # If no specific trigger_area, still use the business process description
            trigger_context_str = f"\nConsider the business logic context: {business_process_description}."

    prompt = f"""
    Analyze the following {language} code snippet from file '{filename}' for security vulnerabilities related to OWASP ASVS V11 (Business Logic).
    {framework_context_str}
    {concurrency_context_str}
    {trigger_context_str}

    Focus on identifying flaws that could be exploited to bypass intended process flows (e.g., skipping payment steps), cause denial of service through resource exhaustion via business functions, manipulate transaction integrity (e.g., replay attacks, race conditions leading to incorrect outcomes like double spending or inventory issues), or abuse time-sensitive operations (e.g., bypassing cooldowns).

    Refer to these ASVS V11 Guidelines:
    {asvs_guidance_for_prompt}

    Code Snippet:
    ```{language}
    {code_snippet}
    ```

    Task:
    1. Identify specific vulnerabilities related to business logic abuse or flaws.
    2. For each vulnerability found, provide:
        - "description": A concise description of the business logic weakness (e.g., "User can complete order without payment if 'payment_verified' flag is manipulated.", "Race condition in voucher application allows multiple uses.").
        - "severity": Estimated severity (Often High or Critical for business logic flaws affecting core functionality or financial transactions).
        - "line_start": Approximate starting line number of the vulnerable code.
        - "line_end": Approximate ending line number.
        - "recommendation": A specific recommendation for fixing the vulnerability (e.g., "Ensure server-side validation of payment status before order completion.", "Implement atomic operations or pessimistic locking for voucher redemption.").
        - "asvs_id": The primary ASVS V11 requirement ID it violates (e.g., "V11.1.1", "V11.2.3").
    3. If no business logic vulnerabilities are found in this snippet, return an empty array.
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
                    f"BusinessLogicAgent successfully assessed '{filename}', found {len(findings_output)} potential issues."
                )
            else:
                error_output = "Failed to parse JSON findings from LLM response for BusinessLogicAgent assessment."
                logger.error(
                    f"{error_output} LLM raw response: {llm_result.content[:500]}"
                )
        else:
            error_output = (
                llm_result.error
                or "LLM call failed or returned no content for BusinessLogicAgent assessment."
            )
            logger.error(
                f"BusinessLogicAgent assessment LLM call failed for '{filename}': {error_output}"
            )

    except Exception as e:
        logger.exception(
            f"Exception during BusinessLogicAgent assessment for '{filename}': {e}"
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
    task_context = state.get(
        "task_context", {}
    )  # For additional context if needed for fixes
    agent_name_for_logging = "BusinessLogicAgent_Fix"

    logger.info(
        f"BusinessLogicAgent Node: generate_fixes for '{filename}' (Submission: {submission_id})"
    )

    if not findings:
        return {
            "fixed_code_snippet": code_snippet,
            "explanation": "No business logic vulnerabilities were identified to fix.",
            "error": None,
        }

    issues_json = json.dumps(findings, indent=2)
    business_process_description = task_context.get(
        "business_context",
        "Apply general best practices for secure business logic, ensuring transactional integrity and proper state management.",
    )
    if not business_process_description or business_process_description == "N/A":
        business_process_description = "Apply general best practices for secure business logic like ensuring atomicity, proper state transitions, input validation relevant to the flow, and re-authentication for critical operations."

    prompt = f"""
    The following {language} code snippet from file '{filename}' has business logic vulnerabilities.
    Business Context: {business_process_description}
    Your task is to provide a fixed version of the code and an explanation of the fixes.

    Original Code Snippet:
    ```{language}
    {code_snippet}
    ```

    Identified Vulnerabilities:
    {issues_json}

    Instructions:
    1.  Review the original code and vulnerabilities, considering the provided business context.
    2.  Provide a complete, fixed version of the code snippet addressing ALL listed vulnerabilities.
        Focus on ensuring proper state management and transitions, implementing controls against race conditions (e.g., using locks, database transactions, atomic operations if applicable to the snippet), adding necessary rate limiting or re-authentication steps for critical operations if implied by findings, and generally making the logic flow more robust against manipulation and bypass.
    3.  After the fixed code, provide a brief, clear "explanation" of key changes and why they improve business logic security in the given context. Explain how race conditions or transaction integrity issues were addressed.
    4.  Return ONLY a single valid JSON object with two keys: "fixed_code" (string) and "explanation" (string).
    """

    llm = get_llm_client()
    llm_result: Optional[LLMResult] = None
    fixed_code_output = code_snippet
    explanation_output = (
        "Fix generation for business logic issues failed or was not applicable."
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
                            f"Failed to parse extracted JSON for business logic fix: {e_inner}"
                        )

            if (
                parsed_fix_object
                and "fixed_code" in parsed_fix_object
                and "explanation" in parsed_fix_object
            ):
                fixed_code_output = parsed_fix_object["fixed_code"]
                explanation_output = parsed_fix_object["explanation"]
                logger.info(
                    f"BusinessLogicAgent successfully generated fix for '{filename}'."
                )
            else:
                error_output = "Failed to parse 'fixed_code' and 'explanation' from LLM response for BusinessLogicAgent fix."
                logger.error(
                    f"{error_output} LLM raw response: {llm_result.content[:500]}"
                )
                explanation_output = error_output
        else:
            error_output = (
                llm_result.error
                or "LLM call failed or returned no content for BusinessLogicAgent fix."
            )
            logger.error(
                f"BusinessLogicAgent fix LLM call failed for '{filename}': {error_output}"
            )
            explanation_output = error_output

    except Exception as e:
        logger.exception(
            f"Exception during BusinessLogicAgent fix generation for '{filename}': {e}"
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
                "business_context": business_process_description,
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
        f"BusinessLogicAgent Node: map_to_standards for '{state['filename']}' (Submission: {state['submission_id']})"
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
                    f"Finding in BusinessLogicAgent for '{state['filename']}' is missing 'asvs_id': {finding.get('description')}"
                )

    cwe_mappings = _identify_cwe_mappings(findings)
    logger.info(
        f"Mapped {len(cwe_mappings)} findings to CWEs for BusinessLogicAgent on '{state['filename']}'."
    )

    return {
        "asvs_mapping": asvs_mappings,
        "cwe_mapping": cwe_mappings,
        "error": state.get("error"),
    }


# --- Graph Construction ---
def build_business_logic_agent_graph() -> Any:
    graph = StateGraph(SecurityAgentState)
    graph.add_node("assess_vulnerabilities", assess_vulnerabilities_node)
    graph.add_node("generate_fixes", generate_fixes_node)
    graph.add_node("map_to_standards", map_to_standards_node)

    graph.set_entry_point("assess_vulnerabilities")
    graph.add_edge("assess_vulnerabilities", "generate_fixes")
    graph.add_edge("generate_fixes", "map_to_standards")
    graph.add_edge("map_to_standards", END)

    compiled_graph = graph.compile()
    logger.info("BusinessLogicAgent graph compiled successfully.")
    return compiled_graph
