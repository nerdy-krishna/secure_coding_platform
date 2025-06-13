# src/app/agents/access_control_agent.py
import logging
from typing import List, TypedDict, Dict, Any

from langgraph.graph import StateGraph, END
from pydantic import BaseModel, Field

from ..db import crud
# FIX: Import 'AsyncSessionLocal' which is the correct name from database.py
from ..db.database import AsyncSessionLocal
from ..llm.llm_client import get_llm_client
from ..rag.rag_service import get_rag_service

# Configure logging
logger = logging.getLogger(__name__)

AGENT_NAME = "AccessControlAgent"

class VulnerabilityFinding(BaseModel):
    description: str = Field(..., description="A detailed description of the vulnerability found.")
    cwe: str = Field(..., description="The most relevant Common Weakness Enumeration (CWE) ID for the finding.")
    recommendation: str = Field(..., description="Suggestions for how to fix the vulnerability.")

class AnalysisResult(BaseModel):
    findings: List[VulnerabilityFinding] = Field(..., description="A list of vulnerabilities identified in the code.")

class FixSuggestion(BaseModel):
    description: str = Field(..., description="A detailed explanation of the proposed fix.")
    code: str = Field(..., description="The secure code snippet to replace the vulnerable part.")

class FixResult(BaseModel):
    fixes: List[FixSuggestion] = Field(..., description="A list of suggested fixes for the identified vulnerabilities.")

class SpecializedAgentState(TypedDict):
    submission_id: int
    code_snippet: str
    context_analysis: Dict[str, Any]
    vulnerability_findings: List[Dict[str, Any]]
    suggested_fixes: List[Dict[str, Any]]
    final_report: Dict[str, Any]

async def assess_vulnerabilities_node(state: SpecializedAgentState) -> Dict[str, Any]:
    logger.info(f"[{AGENT_NAME}] Assessing vulnerabilities for submission ID: {state['submission_id']}")
    
    rag_service = get_rag_service()
    query = "access control, authorization, insecure direct object references, IDOR, permissions, roles, path traversal"
    retrieved_guidelines = rag_service.query_asvs(query_texts=[query], n_results=10)
    guidelines_context = "\n".join(f"- {g}" for g in retrieved_guidelines)
    
    llm_client = get_llm_client()
    prompt = f"""
    You are an expert security analyst for {AGENT_NAME}.
    Analyze the following code snippet for vulnerabilities.
    Use the dynamically retrieved OWASP ASVS 5.0 guidelines below as your primary context for the analysis.

    Retrieved ASVS 5.0 Guidelines:
    {guidelines_context}

    Code Snippet:
    ```
    {state['code_snippet']}
    ```

    Identify and list all access control vulnerabilities based on the rules above.
    For each finding, provide a description, the most relevant CWE ID, and a recommendation.
    """
    
    llm_response = await llm_client.generate_structured_output(prompt, AnalysisResult)

    # FIX: Use 'AsyncSessionLocal' to get a session
    async with AsyncSessionLocal() as db:
        # Call 'save_llm_interaction' with individual arguments as expected by your crud.py
        await crud.save_llm_interaction(
            db=db,
            submission_id=state["submission_id"],
            agent_name=AGENT_NAME,
            prompt=prompt,
            result=llm_response,
            estimated_cost=llm_response.cost,
            status=llm_response.status,
            error_message=llm_response.error_message
        )

    if llm_response.parsed_output and llm_response.parsed_output.findings:
        findings = [f.dict() for f in llm_response.parsed_output.findings]
        logger.info(f"[{AGENT_NAME}] Found {len(findings)} vulnerabilities.")
        return {"vulnerability_findings": findings}
    
    logger.info(f"[{AGENT_NAME}] No vulnerabilities found.")
    return {"vulnerability_findings": []}


async def generate_fixes_node(state: SpecializedAgentState) -> Dict[str, Any]:
    findings = state.get("vulnerability_findings")
    if not findings:
        logger.info(f"[{AGENT_NAME}] No vulnerabilities to fix.")
        return {"suggested_fixes": []}

    logger.info(f"[{AGENT_NAME}] Generating fixes for {len(findings)} vulnerabilities.")
    llm_client = get_llm_client()
    
    prompt = f"""
    Based on the following vulnerabilities and code, provide secure code replacements.

    Code Snippet:
    ```
    {state['code_snippet']}
    ```

    Vulnerabilities Found:
    {findings}

    Generate a list of fixes. For each fix, provide a description and the corresponding secure code snippet.
    """

    llm_response = await llm_client.generate_structured_output(prompt, FixResult)

    async with AsyncSessionLocal() as db:
        await crud.save_llm_interaction(
            db=db,
            submission_id=state["submission_id"],
            agent_name=AGENT_NAME,
            prompt=prompt,
            result=llm_response,
            estimated_cost=llm_response.cost,
            status=llm_response.status,
            error_message=llm_response.error_message
        )

    if llm_response.parsed_output and llm_response.parsed_output.fixes:
        fixes = [f.dict() for f in llm_response.parsed_output.fixes]
        logger.info(f"[{AGENT_NAME}] Generated {len(fixes)} fixes.")
        return {"suggested_fixes": fixes}
        
    logger.info(f"[{AGENT_NAME}] Could not generate any fixes.")
    return {"suggested_fixes": []}


def map_to_standards_node(state: SpecializedAgentState) -> Dict[str, Any]:
    findings = state.get("vulnerability_findings", [])
    fixes = state.get("suggested_fixes", [])
    
    for i, finding in enumerate(findings):
        if i < len(fixes):
            finding['suggested_fix'] = fixes[i]

    logger.info(f"[{AGENT_NAME}] Mapped {len(findings)} findings to standards and fixes.")
    
    return {
        "final_report": {
            "agent": AGENT_NAME,
            "findings": findings
        }
    }


def build_specialized_agent_graph():
    """Builds the graph for the specialized agent."""
    workflow = StateGraph(SpecializedAgentState)
    workflow.add_node("assess_vulnerabilities", assess_vulnerabilities_node)
    workflow.add_node("generate_fixes", generate_fixes_node)
    workflow.add_node("map_to_standards", map_to_standards_node)

    workflow.set_entry_point("assess_vulnerabilities")
    workflow.add_edge("assess_vulnerabilities", "generate_fixes")
    workflow.add_edge("generate_fixes", "map_to_standards")
    workflow.add_edge("map_to_standards", END)
    
    return workflow.compile()