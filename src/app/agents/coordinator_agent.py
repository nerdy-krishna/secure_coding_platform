# src/app/agents/coordinator_agent.py
import asyncio
import logging
from typing import Any, Dict, List, TypedDict, Optional

from langgraph.graph import END, StateGraph

from src.app.agents.schemas import (
    SpecializedAgentState,
    VulnerabilityFinding as VulnerabilityFindingModel,
    FixResult as FixResultModel
)
from src.app.agents.access_control_agent import build_specialized_agent_graph as build_access_control_agent
from src.app.agents.api_security_agent import build_specialized_agent_graph as build_api_security_agent
from src.app.agents.architecture_agent import build_specialized_agent_graph as build_architecture_agent
from src.app.agents.authentication_agent import build_specialized_agent_graph as build_authentication_agent
from src.app.agents.business_logic_agent import build_specialized_agent_graph as build_business_logic_agent
from src.app.agents.code_integrity_agent import build_specialized_agent_graph as build_code_integrity_agent
from src.app.agents.communication_agent import build_specialized_agent_graph as build_communication_agent
from src.app.agents.configuration_agent import build_specialized_agent_graph as build_configuration_agent
from src.app.agents.context_analysis_agent import build_context_analysis_agent_graph, ContextAnalysisAgentState
from src.app.agents.cryptography_agent import build_specialized_agent_graph as build_cryptography_agent
from src.app.agents.data_protection_agent import build_specialized_agent_graph as build_data_protection_agent
from src.app.agents.error_handling_agent import build_specialized_agent_graph as build_error_handling_agent
from src.app.agents.file_handling_agent import build_specialized_agent_graph as build_file_handling_agent
from src.app.agents.session_management_agent import build_specialized_agent_graph as build_session_management_agent
from src.app.agents.validation_agent import build_specialized_agent_graph as build_validation_agent
from src.app.db import crud
from src.app.db.database import get_db_session
from src.app.db.models import CodeSubmission

logger = logging.getLogger(__name__)
AGENT_NAME = "CoordinatorAgent"

AGENT_BUILDER_MAP = {
    "AccessControlAgent": build_access_control_agent,
    "ApiSecurityAgent": build_api_security_agent,
    "ArchitectureAgent": build_architecture_agent,
    "AuthenticationAgent": build_authentication_agent,
    "BusinessLogicAgent": build_business_logic_agent,
    "CodeIntegrityAgent": build_code_integrity_agent,
    "CommunicationAgent": build_communication_agent,
    "ConfigurationAgent": build_configuration_agent,
    "CryptographyAgent": build_cryptography_agent,
    "DataProtectionAgent": build_data_protection_agent,
    "ErrorHandlingAgent": build_error_handling_agent,
    "FileHandlingAgent": build_file_handling_agent,
    "SessionManagementAgent": build_session_management_agent,
    "ValidationAgent": build_validation_agent,
}


class CoordinatorState(TypedDict):
    submission_id: int
    submission: Optional[CodeSubmission]
    code_snippets_and_paths: List[Dict[str, str]]
    relevant_agents: Dict[str, List[str]]
    results: Dict[str, Any]
    error: Optional[str]


async def retrieve_submission_node(state: CoordinatorState) -> Dict[str, Any]:
    submission_id = state["submission_id"]
    logger.info(f"[{AGENT_NAME}] Retrieving submission {submission_id}")
    async with get_db_session() as db:
        submission = await crud.get_submission(db, submission_id)
        if not submission:
            logger.error(f"[{AGENT_NAME}] Submission {submission_id} not found.")
            return {"error": "Submission not found"}

        files = await crud.get_submission_files(db, submission_id)
        code_snippets_and_paths = [
            {"path": file.file_path, "code": file.content, "language": file.language}
            for file in files
        ]

    return {
        "submission": submission,
        "code_snippets_and_paths": code_snippets_and_paths,
    }


async def initial_analysis_and_routing_node(state: CoordinatorState) -> Dict[str, Any]:
    submission_id = state["submission_id"]
    code_snippets_and_paths = state["code_snippets_and_paths"]
    logger.info(f"[{AGENT_NAME}] Starting initial analysis for submission {submission_id}")

    relevant_agents: Dict[str, List[str]] = {}
    context_analysis_workflow = build_context_analysis_agent_graph()

    for file_info in code_snippets_and_paths:
        file_path = file_info["path"]
        logger.info(f"[{AGENT_NAME}] Analyzing context for file: {file_path}")

        initial_state: ContextAnalysisAgentState = {
            "submission_id": submission_id, "filename": file_path,
            "code_snippet": file_info["code"], "language": file_info["language"],
            "analysis_summary": None, "identified_components": None,
            "asvs_analysis": None, "error_message": None
        }
        result_state = await context_analysis_workflow.ainvoke(initial_state)

        if result_state.get("error_message"):
            logger.error(f"Context analysis failed for {file_path}: {result_state['error_message']}")
            continue

        asvs_analysis = result_state.get("asvs_analysis", {})
        async with get_db_session() as db:
            await crud.update_submission_file_context(
                db=db, submission_id=submission_id, file_path=file_path,
                analysis_summary=result_state.get("analysis_summary"),
                identified_components=result_state.get("identified_components"),
                asvs_analysis=asvs_analysis,
            )

        for agent, details in asvs_analysis.items():
            if details.get("is_relevant"):
                if agent not in relevant_agents:
                    relevant_agents[agent] = []
                relevant_agents[agent].append(file_path)

    logger.info(f"[{AGENT_NAME}] Relevant agents identified: {list(relevant_agents.keys())}")
    return {"relevant_agents": relevant_agents}


def should_continue(state: CoordinatorState) -> str:
    if state.get("error"):
        return "end"
    if not state.get("relevant_agents"):
        logger.info(f"[{AGENT_NAME}] No relevant agents identified. Finalizing analysis.")
        return "finalize_analysis"
    return "run_specialized_agents"


async def run_specialized_agents_node(state: CoordinatorState) -> Dict[str, Any]:
    submission_id = state["submission_id"]
    relevant_agents = state["relevant_agents"]
    logger.info(f"[{AGENT_NAME}] Beginning specialized agent runs for submission {submission_id}")

    code_map = {item['path']: item['code'] for item in state["code_snippets_and_paths"]}
    tasks = []

    for agent_name, file_paths in relevant_agents.items():
        agent_builder = AGENT_BUILDER_MAP.get(agent_name)
        if not agent_builder:
            logger.warning(f"[{AGENT_NAME}] No builder found for agent: {agent_name}. Skipping.")
            continue

        agent_graph = agent_builder()
        for file_path in file_paths:
            code_snippet = code_map.get(file_path)
            if not code_snippet:
                logger.warning(f"Could not find code for file {file_path} for agent {agent_name}. Skipping.")
                continue

            initial_agent_state: SpecializedAgentState = {
                "submission_id": submission_id, "filename": file_path, "code_snippet": code_snippet,
                "findings": [], "fixes": [], "error": None,
            }
            tasks.append(agent_graph.ainvoke(initial_agent_state))

    if not tasks:
        logger.warning(f"[{AGENT_NAME}] No tasks were created for specialized agent runs.")
        return {"results": {"findings": [], "fixes": []}}

    logger.info(f"[{AGENT_NAME}] Executing {len(tasks)} specialized agent tasks concurrently.")
    agent_results = await asyncio.gather(*tasks, return_exceptions=True)

    all_findings: List[VulnerabilityFindingModel] = []
    all_fixes: List[FixResultModel] = []
    for result in agent_results:
        if isinstance(result, Exception):
            logger.error(f"[{AGENT_NAME}] An agent task failed: {result}", exc_info=result)
        elif result.get("error"):
            logger.error(f"[{AGENT_NAME}] An agent task completed with an error: {result['error']}")
        else:
            all_findings.extend(result.get("findings", []))
            all_fixes.extend(result.get("fixes", []))

    logger.info(f"[{AGENT_NAME}] Collated {len(all_findings)} findings and {len(all_fixes)} fixes from all agents.")
    return {"results": {"findings": all_findings, "fixes": all_fixes}}


async def finalize_analysis_node(state: CoordinatorState) -> Dict[str, Any]:
    submission_id = state["submission_id"]
    results = state.get("results", {})
    findings_to_save = results.get("findings", [])
    fixes_to_save = results.get("fixes", [])

    logger.info(f"[{AGENT_NAME}] Finalizing analysis for submission {submission_id}.")

    if findings_to_save:
        async with get_db_session() as db:
            persisted_findings = await crud.save_findings(db, submission_id, findings_to_save)
            
            finding_map = {
                (f.file_path, f.line_number, f.cwe, f.description): f.id
                for f in persisted_findings
            }

            if fixes_to_save:
                logger.info(f"Saving {len(fixes_to_save)} fix suggestions.")
                for fix_result in fixes_to_save:
                    pydantic_finding = fix_result.finding
                    finding_key = (pydantic_finding.file_path, pydantic_finding.line_number, pydantic_finding.cwe, pydantic_finding.description)
                    finding_id = finding_map.get(finding_key)

                    if finding_id:
                        await crud.save_fix_suggestion(db, finding_id, fix_result.suggestion)
                    else:
                        logger.warning(f"Could not find a matching saved finding for fix: '{fix_result.suggestion.description}'. Fix will not be saved.")

    async with get_db_session() as db:
        await crud.update_submission_status(db, submission_id, "Completed")

    results["final_status"] = "Analysis complete."
    logger.info(f"[{AGENT_NAME}] Analysis for submission {submission_id} has been completed.")
    return {"results": results}


def build_coordinator_graph():
    """Builds the main coordinator graph."""
    workflow = StateGraph(CoordinatorState)

    workflow.add_node("retrieve_submission", retrieve_submission_node)
    workflow.add_node("initial_analysis_and_routing", initial_analysis_and_routing_node)
    workflow.add_node("run_specialized_agents", run_specialized_agents_node)
    workflow.add_node("finalize_analysis", finalize_analysis_node)

    workflow.set_entry_point("retrieve_submission")
    workflow.add_edge("retrieve_submission", "initial_analysis_and_routing")
    workflow.add_conditional_edges(
        "initial_analysis_and_routing",
        should_continue,
        {"run_specialized_agents": "run_specialized_agents", "finalize_analysis": "finalize_analysis", "end": END}
    )
    workflow.add_edge("run_specialized_agents", "finalize_analysis")
    workflow.add_edge("finalize_analysis", END)
    
    return workflow.compile()