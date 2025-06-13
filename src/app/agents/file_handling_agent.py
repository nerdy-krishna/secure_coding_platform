import logging
import json
from typing import TypedDict, List, Optional, Dict, Any
from uuid import UUID

from langchain_core.pydantic_v1 import BaseModel, Field
from langgraph.graph import StateGraph, END
from sqlalchemy.ext.asyncio import AsyncSession

from src.app.db.crud import save_llm_interaction
from src.app.db.database import get_session
from src.app.llm.llm_client import get_llm_client
from src.app.llm.providers import LLMResult

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

AGENT_NAME = "FileHandlingAgent"

# --- Constants for Prompts ---

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

# --- Pydantic Models for Structured Output ---


class VulnerabilityFinding(BaseModel):
    vulnerability: str = Field(
        description="A brief, specific title for the vulnerability found."
    )
    description: str = Field(
        description="A detailed explanation of the vulnerability, its potential impact, and why it's a risk."
    )
    line_number: int = Field(
        description="The specific line number where the vulnerability is located (or 0 if architectural)."
    )
    severity: str = Field(
        description="The severity of the vulnerability (e.g., Critical, High, Medium, Low, Info)."
    )
    cwe: str = Field(
        description="The most relevant CWE ID for this vulnerability, e.g., 'CWE-22'."
    )
    recommendation: str = Field(
        description="Actionable advice on how to fix the vulnerability."
    )


class AnalysisResult(BaseModel):
    findings: List[VulnerabilityFinding] = Field(
        description="A list of vulnerabilities found in the code."
    )


class FixSuggestion(BaseModel):
    description: str = Field(description="A brief description of the proposed fix.")
    fixed_code: str = Field(description="The complete, corrected code snippet.")


class FixResult(BaseModel):
    suggestions: List[FixSuggestion] = Field(
        description="A list of suggestions to fix the identified vulnerabilities."
    )


# --- Agent State ---


class SpecializedAgentState(TypedDict):
    submission_id: UUID
    file_path: str
    code_snippet: str
    language: str
    task_context: Dict[str, Any]
    findings: Optional[List[Dict[str, Any]]]
    fixes: Optional[List[Dict[str, Any]]]
    final_results: Optional[Dict[str, Any]]
    error: Optional[str]


# --- Agent Nodes ---


async def assess_vulnerabilities_node(
    state: SpecializedAgentState,
) -> SpecializedAgentState:
    logger.info(f"[{AGENT_NAME}] Assessing vulnerabilities for: {state['file_path']}")
    llm_client = get_llm_client()

    prompt = f"""
    You are an expert security analyst specializing in {AGENT_NAME}.
    Your task is to analyze the following code snippet for vulnerabilities related to the OWASP ASVS V12 category.

    **Security Domain Context:**
    {ASVS_V12_GUIDELINES}

    **Code Snippet ({state["language"]}):**
    ```
    {state["code_snippet"]}
    ```

    Analyze the code and identify any file and resource management vulnerabilities. For each finding, provide a detailed description, line number, severity, the most appropriate CWE ID, and a clear recommendation for fixing it.
    If no vulnerabilities are found, return an empty list of findings.
    Respond with a JSON object that strictly adheres to the provided schema.
    """

    db: AsyncSession = await get_session().__anext__()
    try:
        llm_result: LLMResult = await llm_client.generate_structured_output(
            prompt, AnalysisResult
        )

        interaction_context = {
            "file_name": state["file_path"],
            "operation": "Assess Vulnerabilities",
        }
        await save_llm_interaction(
            db=db,
            result=llm_result,
            submission_id=state["submission_id"],
            agent_name=AGENT_NAME,
            interaction_context=interaction_context,
        )

        if llm_result.error:
            logger.error(
                f"[{AGENT_NAME}] LLM error during assessment: {llm_result.error}"
            )
            return {**state, "error": llm_result.error, "findings": []}

        parsed_output = llm_result.parsed_output
        findings = parsed_output.dict().get("findings", []) if parsed_output else []
        logger.info(
            f"[{AGENT_NAME}] Found {len(findings)} potential vulnerabilities in {state['file_path']}."
        )

        return {**state, "findings": findings}

    except Exception as e:
        logger.exception(
            f"[{AGENT_NAME}] Unexpected error during vulnerability assessment: {e}"
        )
        return {**state, "error": str(e), "findings": []}
    finally:
        await db.close()


async def generate_fixes_node(state: SpecializedAgentState) -> SpecializedAgentState:
    if not state.get("findings"):
        logger.info(f"[{AGENT_NAME}] No findings to fix for: {state['file_path']}")
        return {**state, "fixes": []}

    logger.info(f"[{AGENT_NAME}] Generating fixes for: {state['file_path']}")
    llm_client = get_llm_client()

    prompt = f"""
    You are an expert secure coding assistant specializing in {AGENT_NAME}.
    Based on the vulnerabilities identified in the code snippet below, provide concrete suggestions for fixes.
    For each suggestion, provide a brief description and the complete, corrected code snippet.

    **Vulnerabilities Found:**
    {json.dumps(state["findings"], indent=2)}

    **Original Code Snippet ({state["language"]}):**
    ```
    {state["code_snippet"]}
    ```

    Provide the corrected code that remediates the identified vulnerabilities.
    Respond with a JSON object that strictly adheres to the provided schema.
    """

    db: AsyncSession = await get_session().__anext__()
    try:
        llm_result: LLMResult = await llm_client.generate_structured_output(
            prompt, FixResult
        )

        interaction_context = {
            "file_name": state["file_path"],
            "operation": "Generate Fixes",
            "findings_count": len(state.get("findings", [])),
        }
        await save_llm_interaction(
            db=db,
            result=llm_result,
            submission_id=state["submission_id"],
            agent_name=AGENT_NAME,
            interaction_context=interaction_context,
        )

        if llm_result.error:
            logger.error(
                f"[{AGENT_NAME}] LLM error during fix generation: {llm_result.error}"
            )
            return {**state, "error": llm_result.error, "fixes": []}

        parsed_output = llm_result.parsed_output
        fixes = parsed_output.dict().get("suggestions", []) if parsed_output else []
        logger.info(
            f"[{AGENT_NAME}] Generated {len(fixes)} fix suggestions for {state['file_path']}."
        )

        return {**state, "fixes": fixes}

    except Exception as e:
        logger.exception(f"[{AGENT_NAME}] Unexpected error during fix generation: {e}")
        return {**state, "error": str(e), "fixes": []}
    finally:
        await db.close()


def map_to_standards_node(state: SpecializedAgentState) -> SpecializedAgentState:
    """Formats the findings into the final structure for collation."""
    findings = state.get("findings", [])
    fixes = state.get("fixes", [])

    final_results = []
    for finding in findings:
        result = {
            **finding,
            "asvs_id": "ASVS-V12",
            "agent_name": AGENT_NAME,
            "file_path": state["file_path"],
        }
        final_results.append(result)

    if fixes:
        for i, fix in enumerate(fixes):
            if i < len(final_results):
                final_results[i]["suggested_fix"] = fix

    return {**state, "final_results": {"findings": final_results}}


# --- Graph Builder ---


def build_specialized_agent_graph():
    workflow = StateGraph(SpecializedAgentState)
    workflow.add_node("assess_vulnerabilities", assess_vulnerabilities_node)
    workflow.add_node("generate_fixes", generate_fixes_node)
    workflow.add_node("map_to_standards", map_to_standards_node)

    workflow.set_entry_point("assess_vulnerabilities")
    workflow.add_edge("assess_vulnerabilities", "generate_fixes")
    workflow.add_edge("generate_fixes", "map_to_standards")
    workflow.add_edge("map_to_standards", END)

    return workflow.compile()
