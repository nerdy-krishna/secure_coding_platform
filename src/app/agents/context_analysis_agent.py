import logging
import json
import re
from typing import TypedDict, List, Optional, Dict, Any

from langgraph.graph import StateGraph, END
from ..llm.llm_client import get_llm_client
from ..llm.providers import LLMResult
from ..db.crud import save_llm_interaction  # For logging LLM calls
from ..utils.cost_estimation import estimate_openai_cost  # For estimating cost

logger = logging.getLogger(__name__)

# Placeholder for ASVS categories - in a real scenario, this might be more dynamic
# or part of the RAG retrieval.
ASVS_CATEGORIES = [
    "V1_Architecture",
    "V2_Authentication",
    "V3_SessionManagement",
    "V4_AccessControl",
    "V5_Validation",
    "V6_Cryptography",
    "V7_ErrorHandling",
    "V8_DataProtection",
    "V9_Communication",
    "V10_MaliciousCode",
    "V11_BusinessLogic",
    "V12_FileHandling",
    "V13_APISecurity",
    "V14_Configuration",
]


# --- State Definition for ContextAnalysisAgent ---
class ContextAnalysisAgentState(TypedDict):
    submission_id: int
    filename: str
    code_snippet: str
    language: str
    # For Sprint 2, we assume "asvs_v5.0" is implicitly selected or passed.
    # selected_frameworks: List[str] # e.g., ["asvs_v5.0"]

    # Output of this agent for a single file
    analysis_summary: Optional[str]
    identified_components: Optional[List[str]]
    # RAG-informed likelihood mapping for ASVS
    # Structure: {"V1_Architecture": {"likelihood": "High", "evidence": "...", "relevant_asvs_controls": ["1.1.1"]}}
    asvs_analysis: Optional[Dict[str, Any]]
    error_message: Optional[str]


# --- Helper Functions ---
def _extract_json_from_llm_response(response_text: str) -> Optional[Dict[str, Any]]:
    """
    Extracts a JSON object from the LLM response.
    Handles cases where JSON might be embedded in markdown or have surrounding text.
    """
    if not response_text:
        return None

    # Try direct parsing first
    try:
        return json.loads(response_text)
    except json.JSONDecodeError:
        pass  # Continue to other methods

    # Handle markdown code blocks (```json ... ``` or ``` ... ```)
    match = re.search(
        r"```(?:json)?\s*(\{.*?\})\s*```", response_text, re.DOTALL | re.IGNORECASE
    )
    if match:
        try:
            return json.loads(match.group(1))
        except json.JSONDecodeError as e:
            logger.warning(f"Failed to parse JSON from markdown block: {e}")
            pass  # Continue

    # Fallback: find the first '{' and last '}'
    try:
        json_start = response_text.find("{")
        json_end = response_text.rfind("}") + 1
        if 0 <= json_start < json_end:
            potential_json_str = response_text[json_start:json_end]
            return json.loads(potential_json_str)
    except json.JSONDecodeError as e:
        logger.warning(f"Failed to parse JSON using fallback search: {e}")

    logger.error("Could not extract valid JSON from LLM response.")
    return None


def _validate_asvs_analysis_structure(
    analysis_data: Dict[str, Any], filename: str
) -> bool:
    """
    Validates the structure of the ASVS analysis data from the LLM.
    Ensures all ASVS categories are present with likelihood.
    """
    if not isinstance(analysis_data, dict):
        return False
    if analysis_data.get("filename") != filename:
        logger.warning(
            f"Filename mismatch in LLM response. Expected {filename}, got {analysis_data.get('filename')}"
        )
        analysis_data["filename"] = filename  # Correct it

    if "summary" not in analysis_data or not isinstance(analysis_data["summary"], str):
        analysis_data["summary"] = "Summary not provided or invalid."
    if "components" not in analysis_data or not isinstance(
        analysis_data["components"], list
    ):
        analysis_data["components"] = []

    security_areas = analysis_data.get("security_areas")
    if not isinstance(security_areas, dict):
        analysis_data["security_areas"] = {}  # Initialize if missing or wrong type
        security_areas = analysis_data["security_areas"]

    for category in ASVS_CATEGORIES:
        if category not in security_areas:
            security_areas[category] = {
                "likelihood": "None",
                "evidence": "",
                "key_elements": [],
                "relevant_asvs_controls": [],
            }
        else:
            area_detail = security_areas[category]
            if not isinstance(area_detail, dict):  # Ensure it's a dict
                security_areas[category] = {
                    "likelihood": "None",
                    "evidence": "",
                    "key_elements": [],
                    "relevant_asvs_controls": [],
                }
                area_detail = security_areas[category]

            # Normalize likelihood
            likelihood_val = (
                str(area_detail.get("likelihood", "None")).strip().capitalize()
            )
            if likelihood_val not in ["High", "Medium", "Low", "None"]:
                likelihood_val = "None"
            area_detail["likelihood"] = likelihood_val

            if "evidence" not in area_detail:
                area_detail["evidence"] = ""
            if "key_elements" not in area_detail or not isinstance(
                area_detail["key_elements"], list
            ):
                area_detail["key_elements"] = []
            if "relevant_asvs_controls" not in area_detail or not isinstance(
                area_detail["relevant_asvs_controls"], list
            ):
                area_detail["relevant_asvs_controls"] = []
    return True


# --- Node Functions ---


async def perform_rag_enhanced_analysis_node(
    state: ContextAnalysisAgentState,
) -> Dict[str, Any]:
    """
    Performs RAG-enhanced analysis using an LLM.
    For Sprint 2, RAG is simulated by including placeholder ASVS controls in the prompt.
    """
    submission_id = state["submission_id"]
    filename = state["filename"]
    code_snippet = state["code_snippet"]
    language = state["language"]
    agent_name = "ContextAnalysisAgent_RAGAnalysis"  # More specific for logging

    logger.info(
        f"Node: perform_rag_enhanced_analysis_node for file '{filename}' (Submission ID: {submission_id})"
    )

    simulated_retrieved_asvs_controls = """
    Relevant ASVS Controls (Simulated RAG Output):
    - ASVS V5.1.1: Verify that all input is validated using positive validation (allow-lists).
    - ASVS V5.2.1: Verify that output encoding is contextual and relevant for the output interpreter.
    - ASVS V2.1.1: Verify that passwords are at least 12 characters in length.
    - ASVS V4.1.1: Verify that access control enforces "deny by default".
    (This is a placeholder. A real system would fetch specific, relevant controls based on code content.)
    """

    max_content_length = 10000
    content_to_analyze = code_snippet
    if len(code_snippet) > max_content_length:
        trunc_point = code_snippet[:max_content_length].rfind("\n")
        trunc_point = trunc_point if trunc_point != -1 else max_content_length
        content_to_analyze = (
            code_snippet[:trunc_point] + "\n... [TRUNCATED FOR ANALYSIS]"
        )
        logger.warning(
            f"Code snippet for '{filename}' was truncated for LLM analysis due to length."
        )

    prompt = f"""
    Analyze the following code snippet from the file '{filename}' (language: {language}).
    Your task is to identify its purpose, key components, and map its relevance to OWASP ASVS security categories.
    This analysis should be informed by the conceptually relevant ASVS controls provided below.

    Code Snippet:
    ```{language}
    {content_to_analyze}
    ```

    Conceptually Relevant OWASP ASVS Controls (imagine these were retrieved from a knowledge base based on the code):
    {simulated_retrieved_asvs_controls}

    Instructions:
    1.  Based on the code AND the provided ASVS controls, provide a brief overall summary of the code's purpose.
    2.  List key components (e.g., functions, classes, main logic blocks).
    3.  For EACH of the following ASVS categories, assess its likelihood of being relevant to the provided code snippet: {", ".join(ASVS_CATEGORIES)}.
        Rate likelihood as "High", "Medium", "Low", or "None".
    4.  For categories with likelihood "High", "Medium", or "Low", provide:
        a.  Brief "evidence" from the code that supports this likelihood (e.g., specific function names, patterns, or line number hints).
        b.  A list of "key_elements" from the code related to this category.
        c.  A list of "relevant_asvs_controls" by listing specific ASVS IDs (e.g., "V5.1.1", "V2.3.4") from the conceptual list above that seem most pertinent to the code in relation to this category. If none from the list seem directly relevant despite the category's likelihood, provide an empty list.
    5.  Return ONLY a single, valid JSON object with the following structure:
        {{
          "filename": "{filename}",
          "summary": "Brief purpose description of the code snippet.",
          "components": ["component1_name", "component2_name", ...],
          "security_areas": {{
            "V1_Architecture": {{ "likelihood": "...", "evidence": "...", "key_elements": [...], "relevant_asvs_controls": [...] }},
            "V2_Authentication": {{ "likelihood": "...", "evidence": "...", "key_elements": [...], "relevant_asvs_controls": [...] }},
            // ... include ALL ASVS_CATEGORIES listed above in this section ...
            "V14_Configuration": {{ "likelihood": "...", "evidence": "...", "key_elements": [...], "relevant_asvs_controls": [...] }}
          }}
        }}
    Ensure all ASVS categories are present in the "security_areas" object. If a category is not relevant, set its likelihood to "None" and other fields can be empty or brief.
    The "relevant_asvs_controls" should only contain IDs like "V5.1.1", "V2.1.1" etc.
    """

    llm = get_llm_client()
    llm_result: Optional[LLMResult] = None
    parsed_analysis: Optional[Dict[str, Any]] = None
    # Initialize status and error for logging block
    llm_response_status = "failed"
    llm_response_error: Optional[str] = "Initialization error before LLM call."

    try:
        llm_result = await llm.generate(prompt)

        if llm_result.status == "success" and llm_result.content:
            parsed_analysis = _extract_json_from_llm_response(llm_result.content)
            if parsed_analysis and _validate_asvs_analysis_structure(
                parsed_analysis, filename
            ):
                llm_response_status = "success"
                llm_response_error = None  # Clear previous error if successful
                logger.info(
                    f"Successfully parsed RAG-enhanced analysis for '{filename}'."
                )
            else:
                llm_response_status = "failed"
                llm_response_error = "Failed to parse valid JSON or structure mismatch from LLM response."
                logger.error(
                    f"{llm_response_error} for file '{filename}'. Response: {llm_result.content[:500]}"
                )
        else:
            llm_response_status = "failed"
            llm_response_error = (
                llm_result.error or "LLM call failed or returned no content."
            )
            logger.error(f"LLM analysis failed for '{filename}': {llm_response_error}")

    except Exception as e:
        logger.exception(
            f"Unhandled exception during RAG analysis for '{filename}': {e}"
        )
        llm_response_status = "failed"
        llm_response_error = f"Unhandled exception: {str(e)}"
        if llm_result is None:
            llm_result = LLMResult(status="failed", error=llm_response_error)
        elif (
            llm_result.status != "failed"
        ):  # If llm_result existed but wasn't marked failed
            llm_result.status = "failed"
            llm_result.error = llm_response_error

    # Log the LLM interaction
    cost = None
    # Ensure llm_result is used for logging if it exists from the try block
    loggable_llm_result = (
        llm_result
        if llm_result is not None
        else LLMResult(
            status=llm_response_status, error=llm_response_error, content=None
        )
    )

    cost = estimate_openai_cost(
        model_name=loggable_llm_result.model_name,
        input_tokens=loggable_llm_result.input_tokens,
        output_tokens=loggable_llm_result.output_tokens,
    )

    # Use the determined status and error for logging
    # final_log_status was what the traceback pointed to. It's now llm_response_status
    # final_log_error was llm_response_error if llm_response_status == "failed" else None

    await save_llm_interaction(
        submission_id=submission_id,
        agent_name=agent_name,
        prompt=prompt,
        result=loggable_llm_result,
        estimated_cost=cost,
        status=llm_response_status,  # Use the status determined from processing
        error_message=llm_response_error if llm_response_status == "failed" else None,
    )

    if llm_response_status == "success" and parsed_analysis:
        return {
            "analysis_summary": parsed_analysis.get("summary"),
            "identified_components": parsed_analysis.get("components"),
            "asvs_analysis": parsed_analysis.get("security_areas"),
            "error_message": None,  # Cleared because overall operation for this node was success
        }
    else:
        # If llm_response_status is "failed", llm_response_error will contain the reason.
        return {
            "analysis_summary": None,
            "identified_components": None,
            "asvs_analysis": None,
            "error_message": llm_response_error
            or "RAG analysis failed to produce valid output.",
        }


# --- Graph Construction ---
def build_context_analysis_agent_graph() -> Any:
    """Builds and returns the compiled LangGraph for context analysis."""
    graph = StateGraph(ContextAnalysisAgentState)

    graph.add_node("perform_rag_enhanced_analysis", perform_rag_enhanced_analysis_node)
    graph.set_entry_point("perform_rag_enhanced_analysis")
    graph.add_edge("perform_rag_enhanced_analysis", END)

    compiled_graph = graph.compile()
    logger.info("ContextAnalysisAgent graph compiled successfully.")
    return compiled_graph


# To make it callable, similar to other agents
# context_analysis_agent_workflow = build_context_analysis_agent_graph()
