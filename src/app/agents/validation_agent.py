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

AGENT_NAME = "ValidationAgent"

# --- Constants for Prompts ---

ASVS_V5_GUIDELINES = """
V5.1 Input Validation:
    - V5.1.1 Verify that all input is validated using positive validation (allow-lists).
    - V5.1.2 Verify that variable typing, range, length, and format are enforced on all inputs.
    - V5.1.3 Verify that all input data is validated on the server-side.
    - V5.1.4 Verify that structured data is strongly typed and validated against a defined schema.
    - V5.1.5 Verify that validation of untrusted data is based on the assumption that it is malicious.
    - V5.1.6 Verify that URL inputs are validated, e.g. to ensure they are mapped to an expected function rather than a file path.

V5.2 Sanitization and Sandboxing:
    - V5.2.1 Verify that output encoding is contextual and relevant for the output interpreter. (Moved to V5.3 but often related)
    - V5.2.2 Verify that untrusted HTML input is appropriately sanitized using a library or framework.
    - V5.2.3 Verify that URL redirects and forwards only allow whitelisted destinations, or show a warning.
    - V5.2.4 Verify that when user-supplied data is sent to an OS command, it is appropriately validated and shell metacharacters are escaped.
    - V5.2.5 Verify that when user-supplied data is used in SQL queries, it is appropriately validated and parameterized queries or ORMs are used.
    - V5.2.6 Verify that user-supplied data is appropriately validated and sanitized before being used in LDAP, XPath, NoSQL queries, or SMTP/IMAP commands.
    - V5.2.7 Verify that user-supplied data is appropriately validated before being used to create or interact with XML parsers, to prevent XXE.

V5.3 Output Encoding and Injection Prevention:
    - V5.3.1 Verify that context-aware output encoding is applied to user-controllable data.
    - V5.3.2 Verify that output encoding is applied just before the content is sent to the interpreter.
    - V5.3.3 Verify that data selection or database queries are not built by concatenating unsanitized user input.
    - V5.3.4 Verify that the application protects against reflected, stored, and DOM based XSS.
    - V5.3.5 Verify that HTTP responses have Content-Type headers that specify a secure character set (e.g., UTF-8).
    - V5.3.6 Verify that Content Security Policy (CSP) is used to mitigate XSS.

V5.4 Memory, String, and Unmanaged Code: (Less common for typical web app code, but good to keep)
    - V5.4.1 Verify that code uses secure memory copying and handling functions.
    - V5.4.2 Verify that buffer overflow protection mechanisms are used.
    - V5.4.3 Verify that code protects against user-supplied format strings.

V5.5 Deserialization Prevention:
    - V5.5.1 Verify that serialized objects use integrity checks or encryption if the content is sensitive.
    - V5.5.2 Verify that deserialization of untrusted data is avoided or protected.
    - V5.5.3 Verify that strict type constraints are applied during deserialization.
"""

# --- Pydantic Models for Structured Output ---

class VulnerabilityFinding(BaseModel):
    vulnerability: str = Field(description="A brief, specific title for the vulnerability found.")
    description: str = Field(description="A detailed explanation of the vulnerability, its potential impact, and why it's a risk.")
    line_number: int = Field(description="The specific line number where the vulnerability is located (or 0 if architectural).")
    severity: str = Field(description="The severity of the vulnerability (e.g., Critical, High, Medium, Low, Info).")
    cwe: str = Field(description="The most relevant CWE ID for this vulnerability, e.g., 'CWE-79'.")
    recommendation: str = Field(description="Actionable advice on how to fix the vulnerability.")

class AnalysisResult(BaseModel):
    findings: List[VulnerabilityFinding] = Field(description="A list of vulnerabilities found in the code.")

class FixSuggestion(BaseModel):
    description: str = Field(description="A brief description of the proposed fix.")
    fixed_code: str = Field(description="The complete, corrected code snippet.")

class FixResult(BaseModel):
    suggestions: List[FixSuggestion] = Field(description="A list of suggestions to fix the identified vulnerabilities.")

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

async def assess_vulnerabilities_node(state: SpecializedAgentState) -> SpecializedAgentState:
    logger.info(f"[{AGENT_NAME}] Assessing vulnerabilities for: {state['file_path']}")
    llm_client = get_llm_client()
    
    prompt = f"""
    You are an expert security analyst specializing in {AGENT_NAME}.
    Your task is to analyze the following code snippet for vulnerabilities related to the OWASP ASVS V5 category.

    **Security Domain Context:**
    {ASVS_V5_GUIDELINES}

    **Code Snippet ({state['language']}):**
    ```
    {state['code_snippet']}
    ```

    Analyze the code and identify any validation, sanitization, or encoding vulnerabilities. For each finding, provide a detailed description, line number, severity, the most appropriate CWE ID, and a clear recommendation for fixing it.
    If no vulnerabilities are found, return an empty list of findings.
    Respond with a JSON object that strictly adheres to the provided schema.
    """
    
    db: AsyncSession = await get_session().__anext__()
    try:
        llm_result: LLMResult = await llm_client.generate_structured_output(prompt, AnalysisResult)
        
        interaction_context = {
            "file_name": state["file_path"],
            "operation": "Assess Vulnerabilities"
        }
        await save_llm_interaction(
            db=db,
            result=llm_result,
            submission_id=state["submission_id"],
            agent_name=AGENT_NAME,
            interaction_context=interaction_context
        )
        
        if llm_result.error:
            logger.error(f"[{AGENT_NAME}] LLM error during assessment: {llm_result.error}")
            return {**state, "error": llm_result.error, "findings": []}
        
        parsed_output = llm_result.parsed_output
        findings = parsed_output.dict().get("findings", []) if parsed_output else []
        logger.info(f"[{AGENT_NAME}] Found {len(findings)} potential vulnerabilities in {state['file_path']}.")
        
        return {**state, "findings": findings}
    
    except Exception as e:
        logger.exception(f"[{AGENT_NAME}] Unexpected error during vulnerability assessment: {e}")
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
    {json.dumps(state['findings'], indent=2)}

    **Original Code Snippet ({state['language']}):**
    ```
    {state['code_snippet']}
    ```

    Provide the corrected code that remediates the identified vulnerabilities.
    Respond with a JSON object that strictly adheres to the provided schema.
    """
    
    db: AsyncSession = await get_session().__anext__()
    try:
        llm_result: LLMResult = await llm_client.generate_structured_output(prompt, FixResult)
        
        interaction_context = {
            "file_name": state["file_path"],
            "operation": "Generate Fixes",
            "findings_count": len(state.get("findings", []))
        }
        await save_llm_interaction(
            db=db,
            result=llm_result,
            submission_id=state["submission_id"],
            agent_name=AGENT_NAME,
            interaction_context=interaction_context
        )
        
        if llm_result.error:
            logger.error(f"[{AGENT_NAME}] LLM error during fix generation: {llm_result.error}")
            return {**state, "error": llm_result.error, "fixes": []}
        
        parsed_output = llm_result.parsed_output
        fixes = parsed_output.dict().get("suggestions", []) if parsed_output else []
        logger.info(f"[{AGENT_NAME}] Generated {len(fixes)} fix suggestions for {state['file_path']}.")
        
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
            "asvs_id": "ASVS-V5",
            "agent_name": AGENT_NAME,
            "file_path": state["file_path"]
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