import json
import logging
from typing import TypedDict, List, Dict, Any, Optional
from uuid import UUID

from langgraph.graph import StateGraph, END
from sqlalchemy.ext.asyncio import AsyncSession

from src.app.db.crud import save_llm_interaction
from src.app.db.database import get_session
from src.app.llm.llm_client import get_llm_client
from src.app.llm.providers import LLMResult

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# --- Agent State ---

class ReportingAgentState(TypedDict):
    submission_id: UUID
    collated_findings: List[Dict[str, Any]]
    original_code: Dict[str, str]  # filename -> content
    fixed_code: Dict[str, str]  # filename -> content
    final_report: Optional[Dict[str, Any]]
    error: Optional[str]

# --- Agent Utility Functions ---

def create_sarif_report(findings: List[Dict[str, Any]], original_code: Dict[str, str]) -> Dict[str, Any]:
    """Creates a SARIF-compliant report from the findings."""
    results = []
    for finding in findings:
        # Basic SARIF result structure
        result = {
            "ruleId": finding.get("cwe", "CWE-Unknown"),
            "message": {
                "text": finding.get("description", "No description provided.")
            },
            "locations": [
                {
                    "physicalLocation": {
                        "artifactLocation": {
                            "uri": finding.get("file_path", "N/A")
                        },
                        "region": {
                            "startLine": finding.get("line_number", 1),
                            # SARIF snippets can be more detailed, but this is a start
                            "snippet": {
                                "text": original_code.get(finding.get("file_path", ""), "Code not available.")
                            }
                        }
                    }
                }
            ],
            "properties": {
                "severity": finding.get("severity", "Medium"),
                "asvs_id": finding.get("asvs_id", "N/A"),
                "attack_name_summary": finding.get("attack_name_summary", "N/A")
            }
        }
        results.append(result)

    sarif_log = {
        "$schema": "https://schemastore.azurewebsites.net/schemas/json/sarif-2.1.0-rtm.5.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "Secure Coding Platform AI Analyzer",
                        "rules": list({f.get("cwe", "CWE-Unknown"): {"id": f.get("cwe", "CWE-Unknown"), "shortDescription": {"text": f.get("vulnerability", "Unknown Vulnerability")}} for f in findings}.values())
                    }
                },
                "results": results
            }
        ]
    }
    return sarif_log

async def generate_report_summary(state: ReportingAgentState) -> Dict[str, Any]:
    """Generates a high-level summary of the findings using an LLM."""
    logger.info(f"ReportingAgent: Generating summary for submission {state['submission_id']}")
    findings_for_prompt = json.dumps(state['collated_findings'], indent=2)
    llm_client = get_llm_client()

    prompt_template = """
    You are a principal security analyst delivering a report to a development team.
    Based on the following JSON list of findings, write a concise, high-level summary.
    - Start with an executive summary of the security posture.
    - Mention the total number of vulnerabilities found.
    - Group findings by severity (e.g., Critical, High, Medium, Low) and mention the count for each.
    - Highlight the most critical vulnerability and briefly explain its potential impact.
    - Conclude with a positive, encouraging statement about the value of this analysis for improving code security.

    Findings:
    ```json
    {findings}
    ```

    Do not repeat the full list of findings. Provide only the summary text.
    """
    prompt = prompt_template.format(findings=findings_for_prompt)
    db: AsyncSession = await get_session().__anext__()

    try:
        llm_result: LLMResult = await llm_client.generate_text(prompt)

        # Correctly save the full LLM interaction result
        interaction_context = {"operation": "Generate Report Summary"}
        await save_llm_interaction(
            db=db,
            result=llm_result,
            submission_id=state["submission_id"],
            agent_name="ReportingAgent",
            interaction_context=interaction_context
        )

        if llm_result.error:
            logger.error(f"ReportingAgent LLM call failed: {llm_result.error}")
            # We can proceed without a summary if the LLM fails
            return {"summary_text": "Failed to generate AI summary."}

        return {"summary_text": llm_result.output_text}
    except Exception as e:
        logger.exception(f"An unexpected error occurred during report summary generation: {e}")
        return {"summary_text": f"An error occurred while generating the summary: {e}"}
    finally:
        await db.close()


# --- Agent Nodes ---

async def assemble_final_report(state: ReportingAgentState) -> ReportingAgentState:
    """
    Assembles the final report, including SARIF, summary, and detailed findings.
    """
    logger.info(f"ReportingAgent: Assembling final report for submission {state['submission_id']}")
    collated_findings = state.get("collated_findings", [])
    original_code = state.get("original_code", {})

    if not collated_findings:
        logger.info("No findings to report.")
        summary_result = {"summary_text": "No vulnerabilities were found. Great job!"}
        sarif_report = create_sarif_report([], original_code)
    else:
        # Generate AI summary
        summary_result = await generate_report_summary(state)
        # Create SARIF report
        sarif_report = create_sarif_report(collated_findings, original_code)

    final_report = {
        "summary": summary_result.get("summary_text", "No summary available."),
        "statistics": {
            "total_findings": len(collated_findings),
            "by_severity": {
                sev: len([f for f in collated_findings if f.get("severity") == sev])
                for sev in ["Critical", "High", "Medium", "Low", "Info"]
            }
        },
        "findings": collated_findings,
        "sarif_report": sarif_report,
    }

    logger.info(f"ReportingAgent: Final report assembled for submission {state['submission_id']}")
    return {**state, "final_report": final_report}


# --- Graph Builder ---

def build_reporting_agent_graph():
    """
    Builds the LangGraph workflow for the Reporting Agent.
    """
    workflow = StateGraph(ReportingAgentState)
    workflow.add_node("assemble_final_report", assemble_final_report)
    workflow.set_entry_point("assemble_final_report")
    workflow.add_edge("assemble_final_report", END)
    
    return workflow.compile()