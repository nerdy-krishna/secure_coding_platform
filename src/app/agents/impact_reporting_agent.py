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
from app.utils.reporting_utils import create_sarif_report

# Configure logging
logger = logging.getLogger(__name__)
AGENT_NAME = "ImpactReportingAgent"


# --- Pydantic Models ---
class ImpactReport(BaseModel):
    executive_summary: str = Field(description="A high-level overview of the project's security posture.")
    vulnerability_categories: List[str] = Field(description="A list of the main categories of vulnerabilities found.")
    estimated_remediation_effort: str = Field(description="A qualitative estimate of the effort to fix the findings (e.g., 'Low', 'Medium', 'High').")
    required_architectural_changes: List[str] = Field(description="A list of any significant architectural changes required.")


# --- Agent State ---
# SIMPLIFIED: We only need fields for inputs and outputs.
# The parent graph will be responsible for the final 'FinalReport' object.
class ImpactReportingAgentState(TypedDict):
    submission_id: uuid.UUID
    llm_config_id: Optional[uuid.UUID]
    findings: List[VulnerabilityFinding]
    
    # Outputs to be passed back to the parent graph
    impact_report: Optional[Dict[str, Any]]
    sarif_report: Optional[Dict[str, Any]]
    error: Optional[str]


# --- Agent Nodes ---
async def generate_impact_report_node(state: ImpactReportingAgentState) -> Dict[str, Any]:
    """Generates the AI-powered high-level impact summary."""
    submission_id = state["submission_id"]
    llm_config_id = state["llm_config_id"]
    findings = state["findings"]
    
    logger.info(f"[{AGENT_NAME}] Generating LLM impact summary with {len(findings)} findings.")

    # This check is now crucial. It receives the findings from the worker graph.
    if not findings:
        report = ImpactReport(
            executive_summary="No vulnerabilities were identified during the analysis.",
            vulnerability_categories=[],
            estimated_remediation_effort="N/A",
            required_architectural_changes=[],
        )
        return {"impact_report": report.model_dump()}

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
        error=llm_response.error, file_path="N/A (Impact Report)", cost=llm_response.cost,
        input_tokens=llm_response.prompt_tokens,
        output_tokens=llm_response.completion_tokens,
        total_tokens=llm_response.total_tokens
    )
    async with AsyncSessionLocal() as db:
        await crud.save_llm_interaction(db, interaction_data=interaction)

    if llm_response.error or not llm_response.parsed_output:
        return {"error": f"LLM failed to generate a valid impact report: {llm_response.error}"}

    # Return as a dictionary, not a Pydantic model, for state consistency
    return {"impact_report": llm_response.parsed_output.model_dump()}


def generate_sarif_node(state: ImpactReportingAgentState) -> Dict[str, Any]:
    """Generates a SARIF report from the findings."""
    logger.info(f"[{AGENT_NAME}] Generating SARIF report.")
    findings = state.get("findings", [])
    if not findings:
        logger.warning(f"[{AGENT_NAME}] No findings available to generate SARIF report.")
        # Create a valid, empty SARIF report if there are no findings
        return {"sarif_report": create_sarif_report([])} 
    
    sarif_report = create_sarif_report(findings)
    return {"sarif_report": sarif_report}


# --- Graph Builder ---
def build_impact_reporting_agent_graph():
    """Builds the graph for the Impact Reporting Agent."""
    workflow = StateGraph(ImpactReportingAgentState)

    # The nodes are independent and can be thought of as parallel
    workflow.add_node("generate_summary", generate_impact_report_node)
    workflow.add_node("generate_sarif", generate_sarif_node)

    # We set up parallel branches from the entry point
    workflow.set_entry_point("generate_summary")
    workflow.add_edge("generate_summary", "generate_sarif")
    # After SARIF generation, the graph ends. LangGraph automatically collects
    # the state from all executed nodes.
    workflow.add_edge("generate_sarif", END)

    return workflow.compile()