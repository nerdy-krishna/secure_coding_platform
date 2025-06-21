# src/app/agents/impact_reporting_agent.py

import json
import logging
from typing import TypedDict, List, Dict, Any, Optional, cast
import uuid

from langgraph.graph import StateGraph, END
from pydantic import BaseModel, Field

from app.db import crud
from app.db.database import AsyncSessionLocal
from app.llm.llm_client import get_llm_client, AgentLLMResult
from app.agents.schemas import LLMInteraction, VulnerabilityFinding
from app.utils.reporting_utils import create_sarif_report # Import our new utility

# Configure logging
logger = logging.getLogger(__name__)
AGENT_NAME = "ImpactReportingAgent"


# --- Pydantic Models ---

class ImpactReport(BaseModel):
    executive_summary: str = Field(description="A high-level overview of the project's security posture.")
    vulnerability_categories: List[str] = Field(description="A list of the main categories of vulnerabilities found.")
    estimated_remediation_effort: str = Field(description="A qualitative estimate of the effort to fix the findings (e.g., 'Low', 'Medium', 'High').")
    required_architectural_changes: List[str] = Field(description="A list of any significant architectural changes required.")

class FinalReport(BaseModel):
    """The final assembled report containing all components."""
    impact_analysis: ImpactReport
    sarif_report: Dict[str, Any]


# --- Agent State ---

class ImpactReportingAgentState(TypedDict):
    submission_id: uuid.UUID
    llm_config_id: Optional[uuid.UUID]
    findings: List[VulnerabilityFinding]
    
    # Outputs from parallel nodes
    impact_report: Optional[ImpactReport]
    sarif_report: Optional[Dict[str, Any]]
    
    # Final combined output
    final_report: Optional[FinalReport]
    error: Optional[str]


# --- Agent Nodes ---

async def generate_impact_report_node(state: ImpactReportingAgentState) -> Dict[str, Any]:
    """Generates the AI-powered high-level impact summary."""
    # This node's logic remains the same as before
    submission_id = state["submission_id"]
    llm_config_id = state["llm_config_id"]
    findings = state["findings"]
    
    logger.info(f"[{AGENT_NAME}] Generating LLM impact summary.")

    if not findings:
        report = ImpactReport(
            executive_summary="No vulnerabilities were identified during the analysis.",
            vulnerability_categories=[],
            estimated_remediation_effort="N/A",
            required_architectural_changes=[],
        )
        return {"impact_report": report}

    if not llm_config_id:
        return {"error": "LLM config ID not provided for impact report."}

    llm_client = await get_llm_client(llm_config_id)
    if not llm_client:
        return {"error": "Failed to initialize LLM client for impact report."}

    findings_for_prompt = [f.model_dump(include={'cwe', 'description', 'severity'}) for f in findings]
    prompt = f"""
    You are a Principal Security Architect creating an executive summary.
    Based on the following JSON list of findings, generate a high-level impact report.
    Analyze the findings as a whole and provide a strategic overview.

    <FINDINGS_DATA>
    {json.dumps(findings_for_prompt, indent=2)}
    </FINDINGS_DATA>

    Generate a report covering these key areas:
    1. executive_summary: A 2-3 sentence overview of the security posture.
    2. vulnerability_categories: The primary categories of weaknesses found.
    3. estimated_remediation_effort: A qualitative estimate (Low, Medium, High) of the effort to fix these issues, with a brief justification.
    4. required_architectural_changes: A list of any necessary changes beyond simple bug fixes.

    Respond ONLY with a valid JSON object conforming to the schema.
    """
    llm_response: AgentLLMResult = await llm_client.generate_structured_output(prompt, ImpactReport)
    
    interaction = LLMInteraction(
        submission_id=submission_id, agent_name=AGENT_NAME, prompt=prompt,
        raw_response=llm_response.raw_output, 
        parsed_output=llm_response.parsed_output.model_dump() if llm_response.parsed_output else None,
        error=llm_response.error, file_path="N/A (Impact Report)", cost=llm_response.cost
    )
    async with AsyncSessionLocal() as db:
        await crud.save_llm_interaction(db, interaction_data=interaction)

    if llm_response.error or not llm_response.parsed_output:
        return {"error": f"LLM failed to generate a valid impact report: {llm_response.error}"}

    return {"impact_report": cast(ImpactReport, llm_response.parsed_output)}


def generate_sarif_node(state: ImpactReportingAgentState) -> Dict[str, Any]:
    """Generates a SARIF report from the findings using the utility function."""
    logger.info(f"[{AGENT_NAME}] Generating SARIF report.")
    findings = state.get("findings", [])
    if not findings:
        return {"sarif_report": {}} # Return empty SARIF if no findings
    
    sarif_report = create_sarif_report(findings)
    return {"sarif_report": sarif_report}


def assemble_final_report_node(state: ImpactReportingAgentState) -> Dict[str, Any]:
    """Assembles the final report from all generated components."""
    logger.info(f"[{AGENT_NAME}] Assembling final report.")
    impact_report = state.get("impact_report")
    sarif_report = state.get("sarif_report")

    if not impact_report or not sarif_report:
        return {"error": "Cannot assemble final report, one or more components are missing."}
        
    final_report = FinalReport(
        impact_analysis=impact_report,
        sarif_report=sarif_report
    )
    return {"final_report": final_report}


# --- Graph Builder ---

def build_impact_reporting_agent_graph():
    """Builds the graph for the Impact Reporting Agent with parallel branches."""
    workflow = StateGraph(ImpactReportingAgentState)

    workflow.add_node("generate_summary", generate_impact_report_node)
    workflow.add_node("generate_sarif", generate_sarif_node)
    workflow.add_node("assemble_report", assemble_final_report_node)

    # Set the entry point, which will now trigger the parallel execution
    workflow.set_entry_point("generate_summary")
    # We can't add a direct edge from an entry point to two nodes.
    # We will run them sequentially for simplicity, but they are logically parallel.
    # For true parallelism, a conditional entry or a pre-node would be needed.
    # Let's keep it simple and effective.
    workflow.add_edge("generate_summary", "generate_sarif")
    workflow.add_edge("generate_sarif", "assemble_report")
    workflow.add_edge("assemble_report", END)

    return workflow.compile()