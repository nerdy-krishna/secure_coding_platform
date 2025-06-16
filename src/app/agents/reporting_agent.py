# src/app/agents/reporting_agent.py
import json                                                                                                                                                                                                        
import logging                                                                                                                                                                                                     
from typing import TypedDict, List, Dict, Any, Optional, cast
import uuid                                                                                                                                                                                           
                                                                                                                                                                                                                   
from langgraph.graph import StateGraph, END                                                                                                                                                                        
from langgraph.pregel import Pregel                                                                                                                                             
from pydantic import BaseModel                                                                                                                                                                                     
                                                                                                                                                                                                                   
from app.db import crud                                                                                                                                                                                            
from app.db.database import AsyncSessionLocal                                                                                                                
from app.llm.llm_client import get_llm_client, AgentLLMResult                                                                                                                                                      
from app.db.models import CodeSubmission                                                                                                                                                                           
from app.api.models import VulnerabilityFindingResponse                                                                                                                                                            
from app.agents.schemas import LLMInteraction # Added LLMInteraction

# Configure logging
logger = logging.getLogger(__name__)
AGENT_NAME = "ReportingAgent"

# --- Pydantic Models ---


class ReportSummary(BaseModel):
    """Pydantic model for the structured output of the summary generation LLM call."""

    summary_text: str


# --- Agent State ---


class ReportingAgentState(TypedDict):
    submission_id: uuid.UUID # Changed from int to uuid.UUID                                                                                                                                                       
    llm_config_id: Optional[uuid.UUID] # Added for LLM client                                                                                                                                                      
    submission_data: Optional[CodeSubmission]                                                                                                                                                                      
    original_code: Dict[str, str]
    summary_text: Optional[str]
    sarif_report: Optional[Dict[str, Any]]
    final_report: Optional[Dict[str, Any]]
    error: Optional[str]


# --- Agent Utility Functions ---


def _create_sarif_report(
    findings: List[Dict[str, Any]], original_code: Dict[str, str]
) -> Dict[str, Any]:
    """Creates a SARIF-compliant report from the findings."""
    results = []
    rules = {}

    for finding in findings:
        rule_id = finding.get("cwe", "CWE-Unknown")
        if rule_id not in rules:
            rules[rule_id] = {
                "id": rule_id,
                "shortDescription": {"text": f"Vulnerability Type: {rule_id}"},
            }

        file_path = finding.get("file_path", "N/A")
        # Ensure the snippet comes from the correct file's content
        snippet_text = original_code.get(file_path, "Code not available.")

        result = {
            "ruleId": rule_id,
            "message": {"text": finding.get("description", "No description provided.")},
            "locations": [
                {
                    "physicalLocation": {
                        "artifactLocation": {"uri": file_path},
                        "region": {
                            "startLine": finding.get("line_number", 1),
                            "snippet": {"text": snippet_text},
                        },
                    }
                }
            ],
            "properties": {
                "severity": finding.get("severity", "Medium"),
                "confidence": finding.get("confidence", "Medium"),
                "remediation": finding.get("remediation", "N/A"),
            },
        }
        results.append(result)

    return {
        "$schema": "https://schemastore.azurewebsites.net/schemas/json/sarif-2.1.0-rtm.5.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "4th Secure Coding Platform AI Analyzer",
                        "rules": list(rules.values()),
                    }
                },
                "results": results,
            }
        ],
    }


# --- Agent Nodes ---


async def fetch_submission_data_node(state: ReportingAgentState) -> Dict[str, Any]:
    """Fetches all necessary data for the report from the database."""
    submission_id = state["submission_id"]                                                                                                                                                                         
    logger.info(f"[{AGENT_NAME}] Fetching data for submission ID: {submission_id}")                                                                                                                                
                                                                                                                                                                                                                   
    async with AsyncSessionLocal() as db: # Use AsyncSessionLocal directly                                                                                                                                         
        # Ensure submission_id is UUID for crud.get_submission                                                                                                                                                     
        submission_uuid = uuid.UUID(str(submission_id)) if not isinstance(submission_id, uuid.UUID) else submission_id                                                                                             
        submission = await crud.get_submission(db, submission_id=submission_uuid)                                                                                                                                  
        if not submission:                                                                                                                                                                                         
            logger.error(f"[{AGENT_NAME}] Submission {submission_uuid} not found in fetch_submission_data_node.")                                                                                                  
            return {"error": f"Submission {submission_uuid} not found."}                                                                                                                                           
                                                                                                                                                                                                                   
        # Use the newly added crud.get_submitted_files_for_submission                                                                                                                                              
        submitted_files_db = await crud.get_submitted_files_for_submission(db, submission_id=submission_uuid)                                                                                                      
        original_code = {                                                                                                                                                                                          
            file.file_path: file.content                                                                                                                                                                           
            for file in submitted_files_db                                                                                                                                                                         
            if file.content is not None                                                                                                                                                                            
        }                                                                                                                                                                                                          
        if not original_code and submitted_files_db:                                                                                                                                                               
             logger.warning(f"[{AGENT_NAME}] All files for submission {submission_uuid} had no content.")                                                                                                          
                                                                                                                                                                                                                   
                                                                                                                                                                                                                   
    return {"submission_data": submission, "original_code": original_code}


async def generate_summary_node(state: ReportingAgentState) -> Dict[str, Any]:
    """Generates a high-level summary of the findings using an LLM."""
    submission = state.get("submission_data")                                                                                                                                                                      
    llm_config_id = state.get("llm_config_id")                                                                                                                                                                     
                                                                                                                                                                                                                   
    if not submission or not submission.findings:                                                                                                                                                                  
        return {"summary_text": "No findings were identified in the submission."}                                                                                                                                  
                                                                                                                                                                                                                   
    if not llm_config_id:                                                                                                                                                                                          
        logger.error(f"[{AGENT_NAME}] LLM configuration ID not found in state for summary generation.")                                                                                                            
        return {"summary_text": "Failed to generate AI summary due to missing LLM configuration."}                                                                                                                 
                                                                                                                                                                                                                   
    logger.info(f"[{AGENT_NAME}] Generating summary for submission {submission.id}")                                                                                                                               
                                                                                                                                                                                                                   
    # Create a simplified list of findings for the prompt                                                                                                                                                          
    findings_for_prompt = [                                                                                                                                                                                        
        {                                                                                                                                                                                                          
            "severity": f.severity,                                                                                                                                                                                
            "description": f.description,                                                                                                                                                                          
            "cwe": f.cwe,                                                                                                                                                                                          
        }                                                                                                                                                                                                          
        for f in submission.findings                                                                                                                                                                               
    ]                                                                                                                                                                                                              
                                                                                                                                                                                                                   
    llm_client = await get_llm_client(llm_config_id=llm_config_id)                                                                                                                                                 
    if not llm_client:                                                                                                                                                                                             
        logger.error(f"[{AGENT_NAME}] Failed to get LLM client for config ID: {llm_config_id}")                                                                                                                    
        return {"summary_text": "Failed to generate AI summary due to LLM client initialization failure."}                                                                                                         
                                                                                                                                                                                                                   
    prompt = f"""                                                                                                                                                                                                  
    You are a principal security analyst delivering a report to a development team.
    Based on the following JSON list of findings, write a concise, high-level summary.
    - Start with an executive summary of the security posture.
    - Mention the total number of vulnerabilities found.
    - Group findings by severity and mention the count for each.
    - Highlight the most critical type of vulnerability found and briefly explain its potential impact.
    - Conclude with a positive, encouraging statement about the value of this analysis.

    Findings:
    ```json
    {json.dumps(findings_for_prompt, indent=2)}
    ```
    Provide only the summary text in a `summary_text` field.
    """

    llm_response: AgentLLMResult = await llm_client.generate_structured_output(                                                                                                                                    
        prompt, ReportSummary                                                                                                                                                                                      
    )                                                                                                                                                                                                              
                                                                                                                                                                                                                   
    parsed_output_dict = None                                                                                                                                                                                      
    if llm_response.parsed_output:                                                                                                                                                                                 
        # Assuming llm_response.parsed_output is a Pydantic model (ReportSummary instance)                                                                                                                         
        parsed_output_dict = llm_response.parsed_output.dict()                                                                                                                                                     
                                                                                                                                                                                                                   
    interaction = LLMInteraction(                                                                                                                                                                                  
        submission_id=submission.id, # submission.id is already UUID                                                                                                                                               
        agent_name=AGENT_NAME,                                                                                                                                                                                     
        prompt=prompt,                                                                                                                                                                                             
        raw_response=llm_response.raw_output,                                                                                                                                                                      
        parsed_output=parsed_output_dict,                                                                                                                                                                          
        error=llm_response.error,                                                                                                                                                                                  
        file_path="N/A (Report Summary)", # Specific to this interaction                                                                                                                                           
        cost=llm_response.cost,                                                                                                                                                                                    
    )                                                                                                                                                                                                              
    async with AsyncSessionLocal() as db:                                                                                                                                                                          
        await crud.save_llm_interaction(db, interaction_data=interaction)                                                                                                                                          
                                                                                                                                                                                                                   
    if llm_response.error or not llm_response.parsed_output:                                                                                                                                                       
        return {"summary_text": "Failed to generate AI summary."}                                                                                                                                                  
                                                                                                                                                                                                                   
    # Cast parsed_output to ReportSummary for Pylance                                                                                                                                                              
    report_summary = cast(ReportSummary, llm_response.parsed_output)                                                                                                                                               
    return {"summary_text": report_summary.summary_text}


async def generate_sarif_node(state: ReportingAgentState) -> Dict[str, Any]:
    """Generates a SARIF report from the findings."""
    submission = state.get("submission_data")
    original_code = state.get("original_code", {})
    if not submission:
        return {"error": "Submission data not available for SARIF report."}

    logger.info(
        f"[{AGENT_NAME}] Generating SARIF report for submission {submission.id}"
    )
    # Convert SQLAlchemy models to dicts for JSON serialization
    findings_list = [
        {
            "cwe": f.cwe,
            "description": f.description,
            "file_path": f.file_path,
            "line_number": f.line_number,
            "severity": f.severity,
            "confidence": f.confidence,
            "remediation": f.remediation,
        }
        for f in submission.findings
    ]
    sarif_report = _create_sarif_report(findings_list, original_code)
    return {"sarif_report": sarif_report}


async def assemble_final_report_node(state: ReportingAgentState) -> Dict[str, Any]:
    """Assembles the final report from all generated components."""
    submission = state.get("submission_data")
    if not submission:
        return {"error": "Cannot assemble report, submission data is missing."}

    logger.info(
        f"[{AGENT_NAME}] Assembling final report for submission {submission.id}"
    )

    # Convert findings to a list of dicts for the final JSON report
    findings_list = [
        json.loads(VulnerabilityFindingResponse.from_orm(f).json())
        for f in submission.findings
    ]

    final_report = {
        "summary": state.get("summary_text", "Summary not available."),
        "statistics": {
            "total_findings": len(findings_list),
            "by_severity": {
                sev: len([f for f in findings_list if f.get("severity") == sev])
                for sev in ["Critical", "High", "Medium", "Low", "Info"]
            },
        },
        "findings": findings_list,
        "sarif_report": state.get(
            "sarif_report", {"error": "SARIF report not generated."}
        ),
    }
    return {"final_report": final_report}


# --- Graph Builder ---


def build_reporting_agent_graph() -> Pregel:
    """Builds the LangGraph workflow for the Reporting Agent."""
    workflow = StateGraph(ReportingAgentState)

    workflow.add_node("fetch_data", fetch_submission_data_node)

    # These two nodes can run in parallel after fetching the data
    workflow.add_node("generate_summary", generate_summary_node)
    workflow.add_node("generate_sarif", generate_sarif_node)

    workflow.add_node("assemble_report", assemble_final_report_node)

    workflow.set_entry_point("fetch_data")
    workflow.add_edge("fetch_data", "generate_summary")
    workflow.add_edge("fetch_data", "generate_sarif")

    # We need a joiner node to wait for both parallel branches to complete
    workflow.add_edge(["generate_summary", "generate_sarif"], "assemble_report")

    workflow.add_edge("assemble_report", END)

    return workflow.compile()
