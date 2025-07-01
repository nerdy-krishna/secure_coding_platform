# src/app/infrastructure/agents/coordinator_agent.py

import asyncio
import logging
from typing import Any, Dict, List, TypedDict, Optional, Coroutine
import uuid

from langgraph.graph import END, StateGraph

from app.shared.analysis_tools.context_bundler import ContextBundlingEngine, ContextBundle
from app.shared.analysis_tools.repository_map import RepositoryMap
from app.core.schemas import (
    SpecializedAgentState,
    VulnerabilityFinding as VulnerabilityFindingModel,
    FixResult as FixResultModel,
    WorkflowMode,
)
from app.shared.lib import cost_estimation

from app.infrastructure.database.repositories.submission_repo import SubmissionRepository
from app.infrastructure.database.repositories.llm_config_repo import LLMConfigRepository
from app.infrastructure.database import AsyncSessionLocal as async_session_factory

from app.infrastructure.agents.access_control_agent import build_specialized_agent_graph as build_access_control_agent
from app.infrastructure.agents.api_security_agent import build_specialized_agent_graph as build_api_security_agent
from app.infrastructure.agents.architecture_agent import build_specialized_agent_graph as build_architecture_agent
from app.infrastructure.agents.authentication_agent import build_specialized_agent_graph as build_authentication_agent
from app.infrastructure.agents.business_logic_agent import build_specialized_agent_graph as build_business_logic_agent
from app.infrastructure.agents.code_integrity_agent import build_specialized_agent_graph as build_code_integrity_agent
from app.infrastructure.agents.communication_agent import build_specialized_agent_graph as build_communication_agent
from app.infrastructure.agents.configuration_agent import build_specialized_agent_graph as build_configuration_agent
from app.infrastructure.agents.cryptography_agent import build_specialized_agent_graph as build_cryptography_agent
from app.infrastructure.agents.data_protection_agent import build_specialized_agent_graph as build_data_protection_agent
from app.infrastructure.agents.error_handling_agent import build_specialized_agent_graph as build_error_handling_agent
from app.infrastructure.agents.file_handling_agent import build_specialized_agent_graph as build_file_handling_agent
from app.infrastructure.agents.session_management_agent import build_specialized_agent_graph as build_session_management_agent
from app.infrastructure.agents.validation_agent import build_specialized_agent_graph as build_validation_agent

logger = logging.getLogger(__name__)

AGENT_NAME = "CoordinatorAgent"
CONCURRENT_LLM_LIMIT = 5
STATUS_PENDING_APPROVAL = "PENDING_COST_APPROVAL"
STATUS_COST_APPROVED = "Approved - Queued"

AGENT_BUILDER_MAP = {
    "AccessControlAgent": build_access_control_agent, "ApiSecurityAgent": build_api_security_agent,
    "ArchitectureAgent": build_architecture_agent, "AuthenticationAgent": build_authentication_agent,
    "BusinessLogicAgent": build_business_logic_agent, "CodeIntegrityAgent": build_code_integrity_agent,
    "CommunicationAgent": build_communication_agent, "ConfigurationAgent": build_configuration_agent,
    "CryptographyAgent": build_cryptography_agent, "DataProtectionAgent": build_data_protection_agent,
    "ErrorHandlingAgent": build_error_handling_agent, "FileHandlingAgent": build_file_handling_agent,
    "SessionManagementAgent": build_session_management_agent, "ValidationAgent": build_validation_agent,
}


class CoordinatorState(TypedDict):
    submission_id: uuid.UUID
    llm_config_id: Optional[uuid.UUID]
    files: Dict[str, str]
    repository_map: RepositoryMap
    asvs_analysis: Dict[str, Any]
    workflow_mode: WorkflowMode
    context_bundles: Optional[List[ContextBundle]]
    relevant_agents: Dict[str, List[str]]
    estimated_cost: Optional[Dict[str, float]]
    cost_approval_met: Optional[bool] 
    current_submission_status: Optional[str]
    live_codebase: Optional[Dict[str, str]]
    findings: List[VulnerabilityFindingModel]
    fixes: List[FixResultModel]
    final_status: Optional[str]
    error: Optional[str]


def determine_relevant_agents_node(state: CoordinatorState) -> Dict[str, Any]:
    """Determines which specialized agents are relevant based on the codebase context."""
    submission_id = state['submission_id']
    logger.info(f"[{AGENT_NAME}] Determining relevant agents for submission.", extra={"submission_id": str(submission_id)})
    asvs_analysis = state.get("asvs_analysis", {})
    relevant_agents: Dict[str, List[str]] = {}
    repository_map = state.get("repository_map")
    if not repository_map:
        return {"error": "Repository map is missing, cannot determine agent assignments."}
    files_to_scan = list(repository_map.files.keys())
    for agent_name, details in asvs_analysis.items():
        agent_key = agent_name if agent_name.endswith("Agent") else f"{agent_name}Agent"
        if agent_key in AGENT_BUILDER_MAP and details.get("is_relevant"):
            relevant_agents[agent_key] = files_to_scan
    logger.info(f"[{AGENT_NAME}] Relevant agents identified: {list(relevant_agents.keys())}")
    return {"relevant_agents": relevant_agents}


def create_context_bundles_node(state: CoordinatorState) -> Dict[str, Any]:
    """Creates context-rich code bundles for each file to be analyzed."""
    submission_id = state['submission_id']
    logger.info(f"[{AGENT_NAME}] Creating context bundles for submission.", extra={"submission_id": str(submission_id)})
    repository_map = state.get("repository_map")
    files = state.get("files")
    if not repository_map or not files:
        return {"error": "Repository map or files missing, cannot create bundles."}
    try:
        engine = ContextBundlingEngine(repository_map, files)
        bundles = engine.create_bundles()
        logger.info(f"[{AGENT_NAME}] Successfully created {len(bundles)} context bundles.", extra={"submission_id": str(submission_id)})
        return {"context_bundles": bundles}
    except Exception as e:
        logger.error(f"[{AGENT_NAME}] Failed to create context bundles: {e}", exc_info=True, extra={"submission_id": str(submission_id)})
        return {"error": f"Failed to create context bundles: {e}"}


async def estimate_cost_node(state: CoordinatorState) -> Dict[str, Any]:
    """Estimates analysis cost. If a cost has not been approved, it pauses the graph."""
    submission_id = state["submission_id"]
    logger.info(f"[{AGENT_NAME}] Evaluating cost and approval status for submission.", extra={"submission_id": str(submission_id)})
    
    async with async_session_factory() as db:
        submission_repo = SubmissionRepository(db)
        llm_config_repo = LLMConfigRepository(db)

        submission = await submission_repo.get_submission(submission_id)
        if not submission:
            logger.error(f"[{AGENT_NAME}] Submission not found during cost evaluation.", extra={"submission_id": str(submission_id)})
            return {"error": f"Submission {submission_id} not found.", "current_submission_status": "ERROR_NO_SUBMISSION"}

        current_status = submission.status
        estimated_cost_from_db = submission.estimated_cost

        if current_status == STATUS_COST_APPROVED:
            logger.info(f"[{AGENT_NAME}] Cost for submission is already approved. Proceeding.", extra={"submission_id": str(submission_id)})
            return {"cost_approval_met": True, "current_submission_status": current_status, "estimated_cost": estimated_cost_from_db}

        if current_status == STATUS_PENDING_APPROVAL:
            logger.info(f"[{AGENT_NAME}] Submission is still {STATUS_PENDING_APPROVAL}. Waiting.", extra={"submission_id": str(submission_id)})
            return {"cost_approval_met": False, "current_submission_status": current_status, "estimated_cost": estimated_cost_from_db}

        logger.info(f"[{AGENT_NAME}] Performing new cost estimation for submission.", extra={"submission_id": str(submission_id)})
        bundles = state.get("context_bundles")
        llm_config_id = state.get("llm_config_id")

        if not bundles or not llm_config_id:
            return {"error": "Bundles or LLM config ID missing, cannot estimate cost."}
        
        try:
            llm_config = await llm_config_repo.get_by_id_with_decrypted_key(llm_config_id)
            if not llm_config:
                return {"error": f"LLM Configuration with ID {llm_config_id} not found."}

            full_bundle_text = "".join(content for bundle in bundles for content in bundle.context_files.values())
            
            total_input_tokens = await cost_estimation.count_tokens(
                text=full_bundle_text, 
                config=llm_config, 
                api_key=getattr(llm_config, 'decrypted_api_key', None)
            )
            cost_details = cost_estimation.estimate_cost_for_prompt(config=llm_config, input_tokens=total_input_tokens)
            
            await submission_repo.update_cost_and_status(submission_id, STATUS_PENDING_APPROVAL, cost_details)
            logger.info(f"[{AGENT_NAME}] Submission status set to {STATUS_PENDING_APPROVAL}.", extra={"submission_id": str(submission_id)})
            return {"estimated_cost": cost_details, "cost_approval_met": False, "current_submission_status": STATUS_PENDING_APPROVAL}
        except Exception as e:
            logger.error(f"[{AGENT_NAME}] Failed to estimate cost for {submission_id}: {e}", exc_info=True)
            return {"error": f"Failed to estimate cost: {e}"}


def route_after_cost_estimation(state: CoordinatorState) -> str:
    if state.get("error"):
        logger.error(f"[{AGENT_NAME}] Error in coordinator state after cost estimation: {state['error']}")
        return "end_with_error"
    if state.get("cost_approval_met"):
        logger.info(f"[{AGENT_NAME}] Cost approval met for submission. Proceeding.", extra={"submission_id": str(state['submission_id'])})
        return "run_specialized_agents"
    logger.info(f"[{AGENT_NAME}] Cost approval not met. Coordinator ending.", extra={"submission_id": str(state['submission_id'])})
    return END


async def run_specialized_agents_node(state: CoordinatorState) -> Dict[str, Any]:
    submission_id = state["submission_id"]
    relevant_agents = state["relevant_agents"]
    context_bundles = state["context_bundles"]
    specialized_llm_id = state.get("llm_config_id")
    workflow_mode = state["workflow_mode"]
    files = state["files"]

    logger.info(f"[{AGENT_NAME}] Beginning agent runs in '{workflow_mode}' mode with concurrency limit {CONCURRENT_LLM_LIMIT}.", extra={"submission_id": str(submission_id), "mode": workflow_mode})
    if not context_bundles or not files:
        return {"error": "Context bundles or files not found."}

    if workflow_mode == "audit":
        semaphore = asyncio.Semaphore(CONCURRENT_LLM_LIMIT)
        async def run_with_semaphore(coro: Coroutine) -> Any:
            async with semaphore:
                return await coro
        bundle_map: Dict[str, ContextBundle] = {b.target_file_path: b for b in context_bundles}
        tasks = []
        for agent_name, file_paths in relevant_agents.items():
            agent_builder = AGENT_BUILDER_MAP.get(agent_name)
            if not agent_builder: continue
            agent_graph = agent_builder()
            for file_path in file_paths:
                bundle = bundle_map.get(file_path)
                if not bundle: continue
                formatted_bundle_content = "".join(f"--- FILE: {path} ---\n{content}\n\n" for path, content in bundle.context_files.items())
                initial_agent_state: SpecializedAgentState = {"submission_id": submission_id, "llm_config_id": specialized_llm_id, "filename": file_path, "code_snippet": formatted_bundle_content, "workflow_mode": workflow_mode, "findings": [], "fixes": [], "error": None}
                tasks.append(run_with_semaphore(agent_graph.ainvoke(initial_agent_state)))
        
        if not tasks: return {"findings": [], "fixes": []}
        agent_results = await asyncio.gather(*tasks, return_exceptions=True)
        
        all_findings = [r.get("findings", []) for r in agent_results if isinstance(r, dict)]
        all_fixes = [r.get("fixes", []) for r in agent_results if isinstance(r, dict)]
        return {"findings": [item for sublist in all_findings for item in sublist], "fixes": [item for sublist in all_fixes for item in sublist], "live_codebase": None}

    elif workflow_mode == "remediate":
        live_codebase = files.copy()
        all_findings: List[VulnerabilityFindingModel] = []
        all_fixes: List[FixResultModel] = []
        bundle_map: Dict[str, ContextBundle] = {b.target_file_path: b for b in context_bundles}
        for agent_name, file_paths in relevant_agents.items():
            agent_builder = AGENT_BUILDER_MAP.get(agent_name)
            if not agent_builder: continue
            agent_graph = agent_builder()
            for file_path in file_paths:
                bundle = bundle_map.get(file_path)
                if not bundle: continue
                formatted_bundle_content = "".join(f"--- FILE: {path} ---\n{live_codebase.get(path, '')}\n\n" for path in bundle.context_files.keys())
                logger.info(f"[{AGENT_NAME}] Sequentially remediating '{file_path}' with '{agent_name}'.", extra={"submission_id": str(submission_id)})
                initial_agent_state: SpecializedAgentState = {"submission_id": submission_id, "llm_config_id": specialized_llm_id, "filename": file_path, "code_snippet": formatted_bundle_content, "workflow_mode": workflow_mode, "findings": [], "fixes": [], "error": None}
                agent_result = await agent_graph.ainvoke(initial_agent_state)
                if isinstance(agent_result, dict) and not agent_result.get('error'):
                    fixes_from_run = agent_result.get("fixes", [])
                    all_findings.extend(agent_result.get("findings", []))
                    all_fixes.extend(fixes_from_run)
                    for fix_result in fixes_from_run:
                        target_file, original_snippet, new_code = fix_result.finding.file_path, fix_result.suggestion.original_snippet, fix_result.suggestion.code
                        if target_file in live_codebase and original_snippet in live_codebase[target_file]:
                            live_codebase[target_file] = live_codebase[target_file].replace(original_snippet, new_code, 1)
                            logger.info(f"Applied fix in '{target_file}'.", extra={"submission_id": str(submission_id)})
                        else:
                            logger.warning(f"Could not find original snippet in '{target_file}' to apply fix.", extra={"submission_id": str(submission_id)})
        return {"findings": all_findings, "fixes": all_fixes, "live_codebase": live_codebase}
    else:
        return {"error": f"Unknown workflow_mode: {workflow_mode}"}


async def finalize_analysis_node(state: CoordinatorState) -> Dict[str, Any]:
    """Saves all findings and fixes from the agent runs into the database."""
    submission_id, findings_to_save, fixes_to_save, live_codebase, workflow_mode = state["submission_id"], state.get("findings", []), state.get("fixes", []), state.get("live_codebase"), state["workflow_mode"]
    logger.info(f"[{AGENT_NAME}] Finalizing analysis for submission in '{workflow_mode}' mode.", extra={"submission_id": str(submission_id), "mode": workflow_mode, "findings_count": len(findings_to_save)})
    async with async_session_factory() as db:
        repo = SubmissionRepository(db)
        try:
            if findings_to_save:
                persisted_findings = await repo.save_findings(submission_id, findings_to_save)
                logger.info(f"[{AGENT_NAME}] Saved {len(persisted_findings)} findings.")
                if fixes_to_save:
                    finding_map = {(f.file_path, f.line_number, f.cwe): f.id for f in persisted_findings}
                    for fix_result in fixes_to_save:
                        pydantic_finding, finding_key = fix_result.finding, (fix_result.finding.file_path, fix_result.finding.line_number, fix_result.finding.cwe)
                        if finding_id := finding_map.get(finding_key):
                            await repo.save_fix_suggestion(finding_id, fix_result.suggestion)
                    logger.info(f"[{AGENT_NAME}] Saved {len(fixes_to_save)} fix suggestions.")
            if workflow_mode == 'remediate' and live_codebase:
                await repo.update_remediated_code_and_status(submission_id, "Remediation-Completed", live_codebase)
                logger.info(f"[{AGENT_NAME}] Saved fixed code map and updated status to 'Remediation-Completed'.")
            else:
                risk_score = sum(10 if f.severity.upper() == "CRITICAL" else 5 if f.severity.upper() == "HIGH" else 2 if f.severity.upper() == "MEDIUM" else 1 for f in findings_to_save)
                # This will be replaced by the reporting agent's output
                await repo.save_final_reports_and_status(submission_id, "Completed", {}, {}, risk_score)
                logger.info(f"[{AGENT_NAME}] Updated status to 'Completed' for submission {submission_id}.")
        except Exception as e:
            logger.error(f"[{AGENT_NAME}] Error saving results to DB for {submission_id}: {e}", exc_info=True)
            return {"error": f"DB error: {e}"}
    return {"final_status": "Analysis complete."}


def build_coordinator_graph():
    workflow = StateGraph(CoordinatorState)
    workflow.add_node("determine_relevant_agents", determine_relevant_agents_node)
    workflow.add_node("create_context_bundles", create_context_bundles_node)
    workflow.add_node("estimate_cost", estimate_cost_node)
    workflow.add_node("run_specialized_agents", run_specialized_agents_node)
    workflow.add_node("finalize_analysis", finalize_analysis_node)
    workflow.add_node("end_with_error", lambda s: s)
    workflow.set_entry_point("determine_relevant_agents")
    workflow.add_edge("determine_relevant_agents", "create_context_bundles")
    workflow.add_conditional_edges("create_context_bundles", lambda s: "estimate_cost" if not s.get("error") else "end_with_error", {"estimate_cost": "estimate_cost", "end_with_error": "end_with_error"})
    workflow.add_conditional_edges("estimate_cost", route_after_cost_estimation, {"run_specialized_agents": "run_specialized_agents", END: END, "end_with_error": "end_with_error"})
    workflow.add_edge("run_specialized_agents", "finalize_analysis")
    workflow.add_edge("finalize_analysis", END)
    workflow.add_edge("end_with_error", END)
    return workflow.compile()