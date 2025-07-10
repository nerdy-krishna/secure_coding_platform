import json
import logging
from typing import TypedDict, List, Dict, Any, Optional
import uuid

from langgraph.graph import StateGraph, END
from pydantic import BaseModel, Field

from app.infrastructure.database.repositories.scan_repo import ScanRepository
from app.infrastructure.database import AsyncSessionLocal
from app.infrastructure.llm_client import get_llm_client, AgentLLMResult
from app.core.schemas import LLMInteraction, VulnerabilityFinding
from app.shared.lib.reporting import create_sarif_report

logger = logging.getLogger(__name__)
AGENT_NAME = "ImpactReportingAgent"


class ImpactReport(BaseModel):
    executive_summary: str = Field(
        description="A high-level overview of the project's security posture."
    )
    vulnerability_overview: str = Field(
        description="A paragraph summarizing the types and distribution of vulnerabilities found."
    )
    high_risk_findings_summary: List[str] = Field(
        description="A bulleted list summarizing the most critical or high-risk findings."
    )
    remediation_strategy: str = Field(
        description="A paragraph outlining a strategic approach to remediation, such as which categories to prioritize."
    )
    vulnerability_categories: List[str] = Field(
        description="A list of the main categories of vulnerabilities found."
    )
    estimated_remediation_effort: str = Field(
        description="A qualitative estimate of the effort to fix the findings (e.g., 'Low', 'Medium', 'High')."
    )
    required_architectural_changes: List[str] = Field(
        description="A list of any significant architectural changes required."
    )


class ImpactReportingAgentState(TypedDict):
    scan_id: uuid.UUID
    llm_config_id: Optional[uuid.UUID]
    findings: List[VulnerabilityFinding]
    impact_report: Optional[Dict[str, Any]]
    sarif_report: Optional[Dict[str, Any]]
    error: Optional[str]


async def generate_impact_report_node(
    state: ImpactReportingAgentState,
) -> Dict[str, Any]:
    """Generates the AI-powered high-level impact summary."""
    scan_id = state["scan_id"]
    llm_config_id = state["llm_config_id"]
    findings = state["findings"]

    logger.info(
        f"[{AGENT_NAME}] Generating LLM impact summary with {len(findings)} findings."
    )

    if not findings:
        report = ImpactReport(
            executive_summary="No vulnerabilities were identified during the analysis.",
            vulnerability_categories=[],
            estimated_remediation_effort="N/A",
            required_architectural_changes=[],
            vulnerability_overview="The scan completed successfully without finding any vulnerabilities.",
            high_risk_findings_summary=[],
            remediation_strategy="No remediation is necessary at this time."
        )
        return {"impact_report": report.model_dump()}

    if not llm_config_id:
        return {"error": "LLM config ID not provided for impact report."}

    llm_client = await get_llm_client(llm_config_id)
    if not llm_client:
        return {"error": "Failed to initialize LLM client for impact report."}

    findings_for_prompt = [
        f.model_dump(include={"cwe", "description", "severity"}) for f in findings
    ]
    prompt = f"""
    You are a Principal Security Architect creating an executive summary for a C-level audience and development team leads.
    Based on the following JSON list of findings, generate a detailed, multi-section impact report.
    The tone should be professional, clear, and strategic.
    <FINDINGS_DATA>
    {json.dumps(findings_for_prompt, indent=2)}
    </FINDINGS_DATA>

    Generate a report with the following structure:
    1.  **executive_summary**: A 2-3 sentence high-level overview of the project's security posture, suitable for non-technical stakeholders.
    2.  **vulnerability_overview**: A paragraph summarizing the types of vulnerabilities discovered (e.g., input validation, access control) and their severity distribution.
    3.  **high_risk_findings_summary**: A bulleted list of the 2-3 most critical findings. For each, briefly explain the risk in simple terms.
    4.  **remediation_strategy**: A paragraph outlining a strategic approach to fixing these issues. Suggest which categories of vulnerabilities (e.g., all 'Input Validation' issues) should be prioritized to achieve the biggest risk reduction.
    5.  **vulnerability_categories**: A simple list of the main ASVS categories of vulnerabilities found (e.g., "Validation", "Cryptography").
    6.  **estimated_remediation_effort**: A single qualitative estimate (Low, Medium, High) of the overall effort to fix these issues, with a brief justification.
    7.  **required_architectural_changes**: A bulleted list of any necessary changes that go beyond simple code fixes (e.g., "Implement a centralized authentication service"). List "None" if no such changes are required.

    Respond ONLY with a valid JSON object conforming to the schema.
    """
    llm_response: AgentLLMResult = await llm_client.generate_structured_output(
        prompt, ImpactReport
    )

    prompt_context_for_log = { "findings": findings_for_prompt }
    interaction = LLMInteraction(
        scan_id=scan_id,
        agent_name=AGENT_NAME,
        prompt_template_name="Impact Report Generation",
        prompt_context=prompt_context_for_log,
        raw_response=llm_response.raw_output,
        parsed_output=llm_response.parsed_output.model_dump()
        if llm_response.parsed_output
        else None,
        error=llm_response.error,
        file_path="N/A (Impact Report)",
        cost=llm_response.cost,
        input_tokens=llm_response.prompt_tokens,
        output_tokens=llm_response.completion_tokens,
        total_tokens=llm_response.total_tokens,
    )
    async with AsyncSessionLocal() as db:
        repo = ScanRepository(db)
        await repo.save_llm_interaction(interaction_data=interaction)

    if llm_response.error or not llm_response.parsed_output:
        return {
            "error": f"LLM failed to generate a valid impact report: {llm_response.error}"
        }

    return {"impact_report": llm_response.parsed_output.model_dump()}


def generate_sarif_node(state: ImpactReportingAgentState) -> Dict[str, Any]:
    """Generates a SARIF report from the findings."""
    logger.info(f"[{AGENT_NAME}] Generating SARIF report.")
    findings = state.get("findings", [])
    if not findings:
        logger.warning(
            f"[{AGENT_NAME}] No findings available to generate SARIF report."
        )
        return {"sarif_report": create_sarif_report([])}

    sarif_report = create_sarif_report(findings)
    return {"sarif_report": sarif_report}


def build_impact_reporting_agent_graph():
    """Builds the graph for the Impact Reporting Agent."""
    workflow = StateGraph(ImpactReportingAgentState)

    workflow.add_node("generate_summary", generate_impact_report_node)
    workflow.add_node("generate_sarif", generate_sarif_node)

    workflow.set_entry_point("generate_summary")
    workflow.add_edge("generate_summary", "generate_sarif")
    workflow.add_edge("generate_sarif", END)

    return workflow.compile()