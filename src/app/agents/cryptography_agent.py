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

# --- Constants for ASVS V6 Cryptography (from collated_code.txt) ---
ASVS_V6_GUIDELINES = """
V6.1 Data Classification:
    - Classify data in storage and during transmission
    - Protect sensitive data with encryption
    - Use encryption compliant with regulatory requirements

V6.2 Algorithms:
    - Use modern, strong cryptographic algorithms
    - Use approved block cipher modes with appropriate padding
    - Use strong random number generators for cryptographic functions
    - Avoid deprecated/weak cryptographic functions and padding schemes
    - Ensure algorithms are configurable to allow future changes

V6.3 Random Values:
    - Use cryptographically secure random number generators (CSRNG)
    - Protect against session prediction/brute force attacks
    - Use seed values that cannot be guessed

V6.4 Secret Management:
    - Store secrets using secure constructs
    - Protect key stores/HSMs from unauthorized access
    - Avoid hard-coded or embedded secrets
    - Ensure keys can be replaced

V6.5 Key Handling and Management:
    - Use separate keys/certificates for different purposes
    - Use sufficient key strength for algorithms
    - Securely store private keys
    - Implement robust key rotation mechanisms
    - Avoid using weak static keys
    - Implement secure key distribution and revocation
"""

CRYPTO_CWE_MAP = {
    "weak algorithm": "CWE-327",  # Use of a Broken or Risky Cryptographic Algorithm
    "insecure random": "CWE-338",  # Use of Cryptographically Weak Pseudo-Random Number Generator
    "hardcoded secret": "CWE-798",  # Use of Hard-coded Credentials
    "hard-coded key": "CWE-798",  # Use of Hard-coded Credentials (variant)
    "weak encryption": "CWE-326",  # Inadequate Encryption Strength
    "cleartext storage": "CWE-312",  # Cleartext Storage of Sensitive Information
    "cleartext transmission": "CWE-319",  # Cleartext Transmission of Sensitive Information
    "insufficient entropy": "CWE-331",
    "cryptographic key management": "CWE-320",  # Key Management Errors
    "improper certificate validation": "CWE-295",
    "padding oracle": "CWE-208",  # Observable Timing Discrepancy (often leads to padding oracles) / CWE-310 Cryptographic Issues
    "ecb mode": "CWE-327",  # ECB is a weak mode
    "md5": "CWE-327",  # (also CWE-328 Reversible One-Way Hash)
    "sha1": "CWE-327",
    "des": "CWE-327",
    "static iv": "CWE-329",  # Not Using a Random IV with CBC Mode
    "missing salt": "CWE-759",  # Use of a One-Way Hash without a Salt
    "small key size": "CWE-326",
}  # Adapted slightly

CRYPTO_LIBRARIES = {  # from collated_code.txt
    "python": [
        "cryptography",
        "pycrypto",
        "pycryptodome",
        "pyOpenSSL",
        "hashlib",
        "secrets",
    ],
    "java": [
        "java.security",
        "javax.crypto",
        "java.util.SecureRandom",
        "org.bouncycastle",
    ],
    "javascript": ["crypto", "crypto-js", "node-forge", "sjcl", "webcrypto", "jose"],
    "php": ["openssl_*", "mcrypt_*", "hash_*", "crypt", "random_bytes", "sodium_*"],
    "csharp": [
        "System.Security.Cryptography",
        "BouncyCastle",
        "Org.BouncyCastle",
    ],  # Added Org.BouncyCastle
    "ruby": ["OpenSSL", "Digest", "securerandom"],
    "go": ["crypto/*", "golang.org/x/crypto", "math/rand vs crypto/rand"],
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
                    "LLM returned a single JSON object for findings (CryptoAgent), expected array. Wrapping it."
                )
                return [loaded_json]
    except json.JSONDecodeError as e:
        logger.error(
            f"JSONDecodeError in _extract_json_from_llm_response (CryptographyAgent): {e}. Response: {response_text[:500]}"
        )
    return None


def _identify_cwe_mappings(findings: List[Dict[str, Any]]) -> List[Dict[str, str]]:
    cwe_mappings = []
    for finding in findings:
        description = finding.get("description", "").lower()
        recommendation = finding.get("recommendation", "").lower()
        text_to_check = description + " " + recommendation
        mapped_cwe = False
        for keyword, cwe_id in CRYPTO_CWE_MAP.items():
            if keyword in text_to_check:
                cwe_mappings.append(
                    {"description": finding.get("description", ""), "cwe_id": cwe_id}
                )
                mapped_cwe = True
                break
        if not mapped_cwe:
            logger.debug(
                f"No direct CWE keyword match for crypto finding: {description}"
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
    agent_name_for_logging = "CryptographyAgent_Assess"

    logger.info(
        f"CryptographyAgent Node: assess_vulnerabilities for '{filename}' (Submission: {submission_id})"
    )

    if not code_snippet:
        return {"findings": [], "error": "Missing code snippet for CryptographyAgent."}

    asvs_guidance_for_prompt = ASVS_V6_GUIDELINES  # Defined in your existing agent file

    libs_for_lang = CRYPTO_LIBRARIES.get(language.lower(), [])
    lib_context_str = (
        f"Pay attention to usage of common {language} crypto libraries like: {', '.join(libs_for_lang)} (e.g., for key generation, encryption, hashing)."
        if libs_for_lang
        else ""
    )

    framework_context_str = f"The code is in {language}."
    if framework:
        framework_context_str += f" It might be using the {framework} framework; consider its specific crypto utilities or recommendations if any."

    trigger_context_str = ""
    expected_trigger_area = "V6_Cryptography"
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
                f"Please verify and conduct a detailed assessment for cryptographic vulnerabilities based on this context."
            )
        elif trigger_area:
            trigger_context_str = f"\nBroader context: Initial analysis highlighted '{trigger_area}' with likelihood '{task_context.get('likelihood_from_context_analysis', 'N/A')}' as relevant for this file. Consider this while focusing on cryptography."

    prompt = f"""
    Analyze the following {language} code snippet from file '{filename}' for security vulnerabilities related to OWASP ASVS V6 (Cryptography).
    {framework_context_str}
    {lib_context_str}
    {trigger_context_str}
    Focus on identifying weak or deprecated algorithms (e.g., MD5, SHA1, DES, ECB mode), insecure random number generation, hardcoded secrets/keys, improper key management (storage, rotation, strength), insecure generation or handling of Initialization Vectors (IVs), missing or weak salts for hashing, and insecure storage/transmission of cryptographic material.

    Refer to these ASVS V6 Guidelines:
    {asvs_guidance_for_prompt}

    Code Snippet:
    ```{language}
    {code_snippet}
    ```

    Task:
    1. Identify specific vulnerabilities related to cryptography.
    2. For each vulnerability found, provide:
        - "description": A concise description of the cryptographic weakness (e.g., "Use of ECB mode for encryption", "Hardcoded cryptographic key").
        - "severity": Estimated severity (High, Medium, Low - often High or Medium for crypto issues).
        - "line_start": Approximate starting line number of the vulnerable code.
        - "line_end": Approximate ending line number.
        - "recommendation": A specific recommendation for fixing the vulnerability (e.g., "Use AES-GCM instead of ECB mode.", "Store cryptographic keys in a secure vault or use environment variables.").
        - "asvs_id": The primary ASVS V6 requirement ID it violates (e.g., "V6.2.1", "V6.4.3").
    3. If no cryptographic vulnerabilities are found in this snippet, return an empty array.
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
                    f"CryptographyAgent successfully assessed '{filename}', found {len(findings_output)} potential issues."
                )
            else:
                error_output = "Failed to parse JSON findings from LLM response for CryptographyAgent assessment."
                logger.error(
                    f"{error_output} LLM raw response: {llm_result.content[:500]}"
                )
        else:
            error_output = (
                llm_result.error
                or "LLM call failed or returned no content for CryptographyAgent assessment."
            )
            logger.error(
                f"CryptographyAgent assessment LLM call failed for '{filename}': {error_output}"
            )

    except Exception as e:
        logger.exception(
            f"Exception during CryptographyAgent assessment for '{filename}': {e}"
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
    agent_name_for_logging = "CryptographyAgent_Fix"

    logger.info(
        f"CryptographyAgent Node: generate_fixes for '{filename}' (Submission: {submission_id})"
    )

    if not findings:
        return {
            "fixed_code_snippet": code_snippet,
            "explanation": "No cryptographic vulnerabilities were identified to fix.",
            "error": None,
        }

    issues_json = json.dumps(findings, indent=2)
    prompt = f"""
    The following {language} code snippet from file '{filename}' has cryptographic vulnerabilities.
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
        Focus on replacing weak algorithms with strong, modern alternatives (e.g., AES-256-GCM for encryption, SHA-256/SHA-512 for hashing, Argon2id/scrypt/bcrypt for password hashing), using cryptographically secure pseudo-random number generators (CSRNGs) for keys/IVs/salts, removing hardcoded secrets (suggesting placeholders like '{{{{ 환경변수_SECRET_KEY }}}}' or 'get_secret_from_vault()'), and implementing proper key/IV/salt handling.
    3.  After the fixed code, provide a brief, clear "explanation" of key changes and why they improve cryptographic security, mentioning specific algorithms or techniques used.
    4.  Return ONLY a single valid JSON object with two keys: "fixed_code" (string) and "explanation" (string).
    """

    llm = get_llm_client()
    llm_result: Optional[LLMResult] = None
    fixed_code_output = code_snippet
    explanation_output = (
        "Fix generation for cryptographic issues failed or was not applicable."
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
                            f"Failed to parse extracted JSON for cryptography fix: {e_inner}"
                        )

            if (
                parsed_fix_object
                and "fixed_code" in parsed_fix_object
                and "explanation" in parsed_fix_object
            ):
                fixed_code_output = parsed_fix_object["fixed_code"]
                explanation_output = parsed_fix_object["explanation"]
                logger.info(
                    f"CryptographyAgent successfully generated fix for '{filename}'."
                )
            else:
                error_output = "Failed to parse 'fixed_code' and 'explanation' from LLM response for CryptographyAgent fix."
                logger.error(
                    f"{error_output} LLM raw response: {llm_result.content[:500]}"
                )
                explanation_output = error_output
        else:
            error_output = (
                llm_result.error
                or "LLM call failed or returned no content for CryptographyAgent fix."
            )
            logger.error(
                f"CryptographyAgent fix LLM call failed for '{filename}': {error_output}"
            )
            explanation_output = error_output

    except Exception as e:
        logger.exception(
            f"Exception during CryptographyAgent fix generation for '{filename}': {e}"
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
        f"CryptographyAgent Node: map_to_standards for '{state['filename']}' (Submission: {state['submission_id']})"
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
                    f"Finding in CryptographyAgent for '{state['filename']}' is missing 'asvs_id': {finding.get('description')}"
                )

    cwe_mappings = _identify_cwe_mappings(findings)
    logger.info(
        f"Mapped {len(cwe_mappings)} findings to CWEs for CryptographyAgent on '{state['filename']}'."
    )

    return {
        "asvs_mapping": asvs_mappings,
        "cwe_mapping": cwe_mappings,
        "error": state.get("error"),
    }


# --- Graph Construction ---
def build_cryptography_agent_graph() -> Any:
    graph = StateGraph(SecurityAgentState)
    graph.add_node("assess_vulnerabilities", assess_vulnerabilities_node)
    graph.add_node("generate_fixes", generate_fixes_node)
    graph.add_node("map_to_standards", map_to_standards_node)

    graph.set_entry_point("assess_vulnerabilities")
    graph.add_edge("assess_vulnerabilities", "generate_fixes")
    graph.add_edge("generate_fixes", "map_to_standards")
    graph.add_edge("map_to_standards", END)

    compiled_graph = graph.compile()
    logger.info("CryptographyAgent graph compiled successfully.")
    return compiled_graph
