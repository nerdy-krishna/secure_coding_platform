import logging
import json
import re
from typing import TypedDict, List, Optional, Dict, Any

from langgraph.graph import StateGraph, END
from ..llm.llm_client import get_llm_client
from ..llm.providers import LLMResult
from ..db.crud import save_llm_interaction  # For logging LLM calls
from ..utils.cost_estimation import estimate_openai_cost  # For estimating cost
from src.app.llm.llm_client import get_llm_client
from src.app.db.crud import save_llm_interaction
from src.app.utils.cost_estimation import estimate_cost
from src.app.llm.providers import LLMResult

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


async def perform_rag_enhanced_analysis_node(state: ContextAnalysisAgentState) -> Dict[str, Any]:
    """
    Node for performing context analysis on a single file using RAG-enhanced prompts.
    This version is designed to be called concurrently for multiple files.
    """
    submission_id = state["submission_id"]
    filename = state["filename"]
    language = state["language"]
    file_content = state["file_content"]
    selected_frameworks = state["selected_frameworks"]
    
    logger.info(f"Node: perform_rag_enhanced_analysis_node for file '{filename}' (Submission ID: {submission_id})")

    max_chars = 4000  # Example character limit for the snippet
    code_snippet = (
        file_content[:max_chars]
        if len(file_content) > max_chars
        else file_content
    )
    if len(file_content) > max_chars:
        logger.warning(
            f"Code snippet for '{filename}' was truncated for LLM analysis due to length."
        )

    # Simplified prompt for initial analysis
    prompt_template = """
    Analyze the following code snippet from the file '{filename}' written in {language}.
    Based on the code's content, determine its primary purpose and identify which of the following security domains are most relevant for a detailed security assessment. The security domains are derived from OWASP ASVS:
    - V1: Architecture, Design and Threat Modeling
    - V2: Authentication
    - V3: Session Management
    - V4: Access Control
    - V5: Validation, Sanitization and Encoding
    - V6: Stored Cryptography
    - V7: Error Handling and Logging
    - V8: Data Protection
    - V9: Communications
    - V10: Malicious Code
    - V11: Business Logic
    - V12: Files and Resources
    - V13: API and Web Service
    - V14: Configuration

    Code Snippet:
    ```
    {code_snippet}
    ```

    Respond with a JSON object containing two keys:
    1. "purpose": A brief, one-sentence description of the code's primary purpose.
    2. "relevant_domains": A list of the most relevant domain identifiers (e.g., ["V2", "V4", "V5"]).

    Example Response:
    {{
      "purpose": "This code defines API endpoints for user authentication, including login and registration.",
      "relevant_domains": ["V2", "V4", "V13"]
    }}
    """
    prompt = prompt_template.format(
        filename=filename,
        language=language,
        code_snippet=code_snippet,
    )

    llm_result = None  # Initialize to ensure it's always defined
    try:
        llm = get_llm_client()
        generation_config_override = {"temperature": 0.1} # Lower temp for more deterministic analysis
        
        llm_result = await llm.generate(
            prompt=prompt, generation_config_override=generation_config_override
        )
        
        analysis_content = {}
        # --- FIX 1: Use .output_text instead of .content ---
        if llm_result.status == "success" and llm_result.output_text:
            try:
                # Clean the response to extract only the JSON part
                json_str = llm_result.output_text.strip().lstrip("```json").lstrip("```").rstrip("```")
                analysis_content = json.loads(json_str)
                analysis_content["status"] = "success"
                logger.info(f"Successfully parsed LLM analysis for '{filename}'.")
            except json.JSONDecodeError as e:
                logger.error(
                    f"Failed to decode JSON from LLM response for '{filename}': {e}. Response: {llm_result.output_text}"
                )
                analysis_content = {
                    "status": "failed",
                    "error": f"JSONDecodeError: {e}",
                    "raw_response": llm_result.output_text,
                }
        else:
             analysis_content = {
                "status": "failed",
                "error": llm_result.error or "LLM generation failed to produce content.",
            }
        
        return {"analysis_results": analysis_content}

    except Exception as e:
        logger.error(
            f"Unhandled exception during RAG analysis for '{filename}': {e}",
            exc_info=True,
        )
        return {
            "analysis_results": {"status": "failed", "error": str(e)},
        }
    finally:
        # --- FIX 2: Use .prompt_tokens instead of .input_tokens ---
        if llm_result:
            estimated_cost = estimate_cost(
                llm_result.prompt_tokens,
                llm_result.completion_tokens,
                llm_result.model_name,
            )
            # Use a separate async function to save to not block the return
            await save_llm_interaction(
                submission_id=submission_id,
                agent_name="ContextAnalysisAgent",
                prompt=prompt,
                response=llm_result.output_text,
                prompt_tokens=llm_result.prompt_tokens,
                completion_tokens=llm_result.completion_tokens,
                total_tokens=llm_result.total_tokens,
                latency_ms=llm_result.latency_ms,
                model_name=llm_result.model_name,
                status=llm_result.status,
                error_message=llm_result.error,
                estimated_cost=estimated_cost,
                # Add filename to context for better logging
                context={"filename": filename}
            )

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
