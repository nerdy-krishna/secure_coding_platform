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

# --- Constants for ASVS V12 File Handling (from collated_code.txt) ---
ASVS_V12_GUIDELINES = """
V12.1 File Upload Controls:
    - Verify file size limits are enforced
    - Verify file type validation prevents dangerous file types
    - Ensure anti-virus scans are performed for uploaded content
    - Verify user-supplied filename is validated and sanitized
    - Use secure temporary file handling mechanisms
    - Verify uploaded files are stored outside the web root

V12.2 File Integrity Controls:
    - Validate/sanitize filenames to prevent path traversal
    - Verify untrusted file metadata is not used directly
    - Use secure, unique filenames to prevent overwriting
    - Verify file integrity with signatures/checksums
    - Ensure files come from trusted sources

V12.3 File Execution Controls:
    - Prevent untrusted file execution
    - Use secure methods to execute files
    - Verify sandboxing for uploaded files
    - Prevent loading of untrusted code or libraries

V12.4 File Download and Resource Controls:
    - Sanitize untrusted content before processing
    - Set proper security headers for downloads
    - Prevent sensitive information exposure through files
    - Verify untrusted file parsing doesn't lead to resource exhaustion
    - Ensure resource references are properly validated
"""

FILE_HANDLING_CWE_MAP = {
    "path traversal": "CWE-22",  # Improper Limitation of a Pathname to a Restricted Directory
    "directory traversal": "CWE-22",
    "file upload vulnerability": "CWE-434",  # Unrestricted Upload of File with Dangerous Type
    "unrestricted file upload": "CWE-434",
    "untrusted file": "CWE-73",  # External Control of File Name or Path
    "xml injection": "CWE-91",  # (often via file parsing)
    "xxe": "CWE-611",  # Improper Restriction of XML External Entity Reference (often via file parsing)
    "file inclusion": "CWE-98",  # Improper Control of Filename for Include/Require Statement
    "lfi": "CWE-98",  # Local File Inclusion
    "rfi": "CWE-98",  # Remote File Inclusion (less common in modern contexts but still possible)
    "zip bomb": "CWE-409",  # Improper Handling of Highly Compressed Data (decompression bomb)
    "zip slip": "CWE-22",  # Specific path traversal via archives
    "resource exhaustion": "CWE-400",  # Uncontrolled Resource Consumption (e.g., parsing large files)
    "symlink attack": "CWE-59",  # Improper Link Resolution Before File Access
    "file permission issue": "CWE-732",  # Incorrect Permission Assignment for Critical Resource
    "unsafe deserialization from file": "CWE-502",  # Deserialization of Untrusted Data
    "TOCTOU file access": "CWE-367",  # Time-of-check Time-of-use (TOCTOU) Race Condition
}  # Adapted slightly

FILE_HANDLING_FUNCTIONS = {  # from collated_code.txt
    "python": [
        "open",
        "os.path",
        "pathlib",
        "glob",
        "shutil",
        "tempfile",
        "fileinput",
        "pickle.load",
        "zipfile",
        "tarfile",
        "xml.etree.ElementTree.parse",
    ],
    "java": [
        "java.io.File",
        "java.nio.file.Files",
        "java.nio.file.Path",
        "FileInputStream",
        "FileOutputStream",
        "MultipartFile",
        "ZipInputStream",
        "javax.xml.parsers",
    ],
    "javascript": [
        "fs.readFile",
        "fs.writeFile",
        "path.join",
        "multer",
        "formidable",
        "FileReader",
        "require()",
    ],  # Added require() for module loading aspects
    "php": [
        "fopen",
        "file_get_contents",
        "move_uploaded_file",
        "$_FILES",
        "include",
        "require",
        "ZipArchive",
        "simplexml_load_file",
    ],
    "csharp": [
        "System.IO.File",
        "System.IO.FileStream",
        "System.IO.Path",
        "System.IO.Directory",
        "IFormFile",
        "System.IO.Compression.ZipFile",
        "System.Xml.XmlReader",
    ],
    "ruby": [
        "File.open",
        "File.read",
        "FileUtils",
        "Dir",
        "Pathname",
        "IO.read",
        "Zip::File",
        "REXML::Document.new",
        "Nokogiri::XML",
    ],
    "go": [
        "os.Open",
        "os.Create",
        "io/ioutil.ReadFile",
        "path/filepath.Join",
        "mime/multipart.FileHeader",
        "archive/zip.OpenReader",
        "encoding/xml.Unmarshal",
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
                    "LLM returned a single JSON object for findings (FileHandlingAgent), expected array. Wrapping it."
                )
                return [loaded_json]
    except json.JSONDecodeError as e:
        logger.error(
            f"JSONDecodeError in _extract_json_from_llm_response (FileHandlingAgent): {e}. Response: {response_text[:500]}"
        )
    return None


def _identify_cwe_mappings(findings: List[Dict[str, Any]]) -> List[Dict[str, str]]:
    cwe_mappings = []
    for finding in findings:
        description = finding.get("description", "").lower()
        recommendation = finding.get("recommendation", "").lower()
        text_to_check = description + " " + recommendation
        mapped_cwe = False
        for keyword, cwe_id in FILE_HANDLING_CWE_MAP.items():
            if keyword in text_to_check:
                cwe_mappings.append(
                    {"description": finding.get("description", ""), "cwe_id": cwe_id}
                )
                mapped_cwe = True
                break
        if not mapped_cwe:
            logger.debug(
                f"No direct CWE keyword match for file handling finding: {description}"
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
    agent_name_for_logging = "FileHandlingAgent_Assess"

    logger.info(
        f"FileHandlingAgent Node: assess_vulnerabilities for '{filename}' (Submission: {submission_id})"
    )

    if not code_snippet:
        return {"findings": [], "error": "Missing code snippet for FileHandlingAgent."}

    asvs_guidance_for_prompt = ASVS_V12_GUIDELINES

    file_ops_patterns = FILE_HANDLING_FUNCTIONS.get(language.lower(), [])
    file_ops_context = ""
    if file_ops_patterns:
        detected_file_ops = [
            p
            for p in file_ops_patterns
            if re.search(r"\b" + re.escape(p) + r"\b", code_snippet, re.IGNORECASE)
        ]
        if detected_file_ops:
            file_ops_context = f"The code appears to use file handling functions like: {', '.join(list(set(detected_file_ops[:5])))}. Examine their usage carefully for path traversal, insecure uploads, XXE, etc."

    framework_context_str = f"The code is in {language}."
    if framework:
        framework_context_str += f" It might be using the {framework} framework (e.g., for file uploads or resource access)."

    trigger_context_str = ""
    expected_trigger_area = "V12_FileHandling"
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
                f"Please verify and conduct a detailed assessment for file handling vulnerabilities based on this context."
            )
        elif trigger_area:
            trigger_context_str = f"\nBroader context: Initial analysis highlighted '{trigger_area}' with likelihood '{task_context.get('likelihood_from_context_analysis', 'N/A')}' as relevant for this file. Consider this while focusing on file handling security."

    prompt = f"""
    Analyze the following {language} code snippet from file '{filename}' for security vulnerabilities related to OWASP ASVS V12 (Files and Resources).
    {framework_context_str}
    {file_ops_context}
    {trigger_context_str}
    Focus on identifying issues such as path traversal, unrestricted file uploads (type, size, content), XML External Entity (XXE) injection from file parsing, insecure handling of archives (zip bombs, zip slip), missing file integrity checks, and potential for arbitrary file execution or inclusion.

    Refer to these ASVS V12 Guidelines:
    {asvs_guidance_for_prompt}

    Code Snippet:
    ```{language}
    {code_snippet}
    ```

    Task:
    1. Identify specific vulnerabilities related to file and resource handling.
    2. For each vulnerability found, provide:
        - "description": A concise description of the weakness.
        - "severity": Estimated severity (High, Medium, Low).
        - "line_start": Approximate starting line number of the vulnerable code.
        - "line_end": Approximate ending line number.
        - "recommendation": A specific recommendation for fixing the vulnerability (e.g., validate filenames, sanitize paths, check file types/sizes, use safe XML parsers).
        - "asvs_id": The primary ASVS V12 requirement ID it violates (e.g., "V12.1.2", "V12.2.1").
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
                    f"FileHandlingAgent successfully assessed '{filename}', found {len(findings_output)} potential issues."
                )
            else:
                error_output = "Failed to parse JSON findings from LLM response for FileHandlingAgent assessment."
                logger.error(
                    f"{error_output} LLM raw response: {llm_result.content[:500]}"
                )
        else:
            error_output = (
                llm_result.error
                or "LLM call failed or returned no content for FileHandlingAgent assessment."
            )
            logger.error(
                f"FileHandlingAgent assessment LLM call failed for '{filename}': {error_output}"
            )

    except Exception as e:
        logger.exception(
            f"Exception during FileHandlingAgent assessment for '{filename}': {e}"
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
    agent_name_for_logging = "FileHandlingAgent_Fix"

    logger.info(
        f"FileHandlingAgent Node: generate_fixes for '{filename}' (Submission: {submission_id})"
    )

    if not findings:
        return {
            "fixed_code_snippet": code_snippet,
            "explanation": "No file handling vulnerabilities were identified to fix.",
            "error": None,
        }

    issues_json = json.dumps(findings, indent=2)
    prompt = f"""
    The following {language} code snippet from file '{filename}' has file and resource handling vulnerabilities.
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
        Focus on implementing strong input validation for filenames and paths (e.g., against path traversal using `os.path.abspath` and checking against a base directory), validating file types and sizes for uploads, using safe XML parsing configurations to prevent XXE, and ensuring temporary files are handled securely.
    3.  After the fixed code, provide a brief, clear "explanation" of key changes and why they improve file handling security.
    4.  Return ONLY a single valid JSON object with two keys: "fixed_code" (string) and "explanation" (string).
    """

    llm = get_llm_client()
    llm_result: Optional[LLMResult] = None
    fixed_code_output = code_snippet
    explanation_output = (
        "Fix generation for file handling issues failed or was not applicable."
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
                            f"Failed to parse extracted JSON for file handling fix: {e_inner}"
                        )

            if (
                parsed_fix_object
                and "fixed_code" in parsed_fix_object
                and "explanation" in parsed_fix_object
            ):
                fixed_code_output = parsed_fix_object["fixed_code"]
                explanation_output = parsed_fix_object["explanation"]
                logger.info(
                    f"FileHandlingAgent successfully generated fix for '{filename}'."
                )
            else:
                error_output = "Failed to parse 'fixed_code' and 'explanation' from LLM response for FileHandlingAgent fix."
                logger.error(
                    f"{error_output} LLM raw response: {llm_result.content[:500]}"
                )
                explanation_output = error_output
        else:
            error_output = (
                llm_result.error
                or "LLM call failed or returned no content for FileHandlingAgent fix."
            )
            logger.error(
                f"FileHandlingAgent fix LLM call failed for '{filename}': {error_output}"
            )
            explanation_output = error_output

    except Exception as e:
        logger.exception(
            f"Exception during FileHandlingAgent fix generation for '{filename}': {e}"
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
        f"FileHandlingAgent Node: map_to_standards for '{state['filename']}' (Submission: {state['submission_id']})"
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
                    f"Finding in FileHandlingAgent for '{state['filename']}' is missing 'asvs_id': {finding.get('description')}"
                )

    cwe_mappings = _identify_cwe_mappings(findings)
    logger.info(
        f"Mapped {len(cwe_mappings)} findings to CWEs for FileHandlingAgent on '{state['filename']}'."
    )

    return {
        "asvs_mapping": asvs_mappings,
        "cwe_mapping": cwe_mappings,
        "error": state.get("error"),
    }


# --- Graph Construction ---
def build_file_handling_agent_graph() -> Any:
    graph = StateGraph(SecurityAgentState)
    graph.add_node("assess_vulnerabilities", assess_vulnerabilities_node)
    graph.add_node("generate_fixes", generate_fixes_node)
    graph.add_node("map_to_standards", map_to_standards_node)

    graph.set_entry_point("assess_vulnerabilities")
    graph.add_edge("assess_vulnerabilities", "generate_fixes")
    graph.add_edge("generate_fixes", "map_to_standards")
    graph.add_edge("map_to_standards", END)

    compiled_graph = graph.compile()
    logger.info("FileHandlingAgent graph compiled successfully.")
    return compiled_graph
