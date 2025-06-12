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

AGENT_NAME = "ArchitectureAgent"

# --- Constants for Prompts ---

# This detailed context is critical for guiding the LLM, as we discussed.
ASVS_V1_GUIDELINES = """
V1.1 Secure Software Development Lifecycle:
    - Verify use of secure software development lifecycle
    - Verify threat modeling for all design changes
    - Verify secure design principles are applied
    - Verify security is addressed throughout all lifecycle phases

V1.2 Authentication Architecture:
    - Verify centralized authentication mechanisms
    - Verify decoupling of authentication logic
    - Verify components are properly separated
    - Verify authentication is secure by design

V1.3 Session Management Architecture:
    - Verify server-side session management
    - Verify secure session handling techniques
    - Verify protection against session attacks

V1.4 Access Control Architecture:
    - Verify principle of least privilege
    - Verify "deny by default" is applied
    - Verify access control failures are logged
    - Verify secure handling of access control decisions

V1.5 Input and Output Architecture:
    - Verify input validation and output encoding
    - Verify encoding and escaping are appropriate
    - Verify defense in depth for sensitive operations
    - Verify parameterized interfaces where possible

V1.6 Cryptographic Architecture:
    - Verify cryptographic module is used for sensitive operations
    - Verify no sensitive data in logs/cache
    - Verify cryptographic keys are securely managed
    - Verify secrets are properly protected

V1.7 Error, Logging, and Auditing Architecture:
    - Verify centralized error handling
    - Verify no sensitive data in logs
    - Verify appropriate logging for security events
    - Verify consistent time source for logs

V1.8 Data Protection and Privacy Architecture:
    - Verify sensitive data properly classified
    - Verify data minimization techniques
    - Verify proper controls for sensitive data
    - Verify compliance with privacy regulations

V1.9 Communications Architecture:
    - Verify encrypted communications for sensitive data
    - Verify proper use of TLS
    - Verify secure channel setup

V1.10 Malicious Software Architecture:
    - Verify upload validation and handling
    - Verify virus scanning or sandboxing
    - Verify prevention of code execution

V1.11 Business Logic Architecture:
    - Verify business logic flows prevent exploitation
    - Verify proper sequence enforcement
    - Verify protection against business logic attacks

V1.12 Secure File Upload Architecture:
    - Verify secure file handling
    - Verify validation of uploaded content
    - Verify secure storage of uploads

V1.14 Configuration Architecture:
    - Verify secure application deployment
    - Verify automated security check during build
    - Verify secure and repeatable environments
"""  # Combined citation for the guideline block

# --- Pydantic Models for Structured Output ---

class VulnerabilityFinding(BaseModel):
    vulnerability: str = Field(description="A brief, specific title for the vulnerability found.")
    description: str = Field(description="A detailed explanation of the vulnerability, its potential impact, and why it's a risk.")
    line_number: int = Field(description="The specific line number where the vulnerability is located (or 0 if architectural).")
    severity: str = Field(description="The severity of the vulnerability (e.g., Critical, High, Medium, Low, Info).")
    cwe: str = Field(description="The most relevant CWE ID for this vulnerability, e.g., 'CWE-1173'.")
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
    Your task is to analyze the following code snippet for vulnerabilities related to the OWASP ASVS V1 category.

    **Security Domain Context:**
    {ASVS_V1_GUIDELINES}

    **Code Snippet ({state['language']}):**
    ```
    {state['code_snippet']}
    ```

    Analyze the code and identify any vulnerabilities. For each finding, provide a detailed description, line number, severity, the most appropriate CWE ID, and a clear recommendation for fixing it.
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
            "asvs_id": "ASVS-V1",
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