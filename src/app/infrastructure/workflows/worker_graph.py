# src/app/infrastructure/workflows/worker_graph.py

import asyncio
import logging
import psycopg
import uuid
from typing import Any, Dict, List, Optional, TypedDict

from langchain_core.runnables import RunnableConfig
from langgraph.checkpoint.postgres.aio import AsyncPostgresSaver
from langgraph.graph import END, StateGraph
from langgraph.pregel import Pregel
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.orm import selectinload

from app.config.config import settings
from app.core.schemas import FixResult, SpecializedAgentState, VulnerabilityFinding
from app.infrastructure.agents.generic_specialized_agent import build_generic_specialized_agent_graph
from app.infrastructure.agents.impact_reporting_agent import ImpactReportingAgentState, build_impact_reporting_agent_graph
from app.infrastructure.database import AsyncSessionLocal
from app.infrastructure.database import models as db_models
from app.infrastructure.database.repositories.llm_config_repo import LLMConfigRepository
from app.infrastructure.database.repositories.scan_repo import ScanRepository
from app.infrastructure.llm_client import AgentLLMResult, get_llm_client
from app.shared.analysis_tools.context_bundler import ContextBundlingEngine
from app.shared.analysis_tools.repository_map import RepositoryMappingEngine
from app.shared.lib import cost_estimation

logger = logging.getLogger(__name__)

CONCURRENT_LLM_LIMIT = 5

STATUS_PENDING_APPROVAL = "PENDING_COST_APPROVAL"
STATUS_QUEUED = "QUEUED"
STATUS_QUEUED_FOR_SCAN = "QUEUED_FOR_SCAN"
STATUS_REMEDIATION_COMPLETE = "REMEDIATION_COMPLETED"
STATUS_COMPLETED = "COMPLETED"


class WorkerState(TypedDict):
    scan_id: uuid.UUID
    llm_config_id: Optional[uuid.UUID] 
    files: Optional[Dict[str, str]]
    scan_type: str
    current_scan_status: Optional[str]
    repository_map: Optional[Any]
    asvs_analysis: Optional[Dict[str, Any]]
    context_bundles: Optional[List[Any]]
    relevant_agents: Dict[str, str]
    excluded_files: Optional[List[str]]  # ADD THIS LINE
    findings: List[VulnerabilityFinding]
    fixes: List[FixResult] 
    live_codebase: Optional[Dict[str, str]]
    impact_report: Optional[Dict[str, Any]]
    sarif_report: Optional[Dict[str, Any]]
    error_message: Optional[str]

class CorrectedSnippet(BaseModel):
    corrected_original_snippet: str

# --- NODE AND ROUTER DEFINITIONS ---
# --- Data models and definitions needed for the analysis node ---  

AGENT_DESCRIPTIONS = {
    "AccessControlAgent": "Analyzes for vulnerabilities related to user permissions, authorization, and insecure direct object references.",
    "ApiSecurityAgent": "Focuses on the security of API endpoints, including REST, GraphQL, and other web services.",
    "ArchitectureAgent": "Assesses the overall security architecture, design patterns, and data flow.",
    "AuthenticationAgent": "Scrutinizes login mechanisms, password policies, multi-factor authentication, and credential management.",
    "BusinessLogicAgent": "Looks for flaws in the application's business logic that could be exploited.",
    "CodeIntegrityAgent": "Verifies the integrity of code and dependencies to prevent tampering.",
    "CommunicationAgent": "Checks for secure data transmission, use of TLS, and protection against network-level attacks.",
    "ConfigurationAgent": "Inspects for misconfigurations in the application, server, or third-party services.",
    "CryptographyAgent": "Evaluates the use of encryption, hashing algorithms, and key management.",
    "DataProtectionAgent": "Focuses on the protection of sensitive data at rest and in transit, including PII.",
    "ErrorHandlingAgent": "Analyzes error handling routines to prevent information leakage.",
    "FileHandlingAgent": "Scrutinizes file upload, download, and processing functionality for vulnerabilities.",
    "SessionManagementAgent": "Checks for secure session handling, token management, and protection against session hijacking.",
    "ValidationAgent": "Focuses on input validation, output encoding, and prevention of injection attacks like SQLi and XSS.",
}

class AgentRelevance(BaseModel):
    is_relevant: bool = Field(..., description="True if the agent's security domain is relevant to the code, otherwise False.")
    reasoning: str = Field(..., description="A brief explanation for why the agent is or is not relevant.")

class TaskBreakdown(BaseModel):
    AccessControlAgent: AgentRelevance
    ApiSecurityAgent: AgentRelevance
    ArchitectureAgent: AgentRelevance
    AuthenticationAgent: AgentRelevance
    BusinessLogicAgent: AgentRelevance
    CodeIntegrityAgent: AgentRelevance
    CommunicationAgent: AgentRelevance
    ConfigurationAgent: AgentRelevance
    CryptographyAgent: AgentRelevance
    DataProtectionAgent: AgentRelevance
    ErrorHandlingAgent: AgentRelevance
    FileHandlingAgent: AgentRelevance
    SessionManagementAgent: AgentRelevance
    ValidationAgent: AgentRelevance

class FullContextAnalysis(BaseModel):
    analysis_summary: str = Field(description="A brief, one-paragraph summary of the entire project's functionality based on the repository map.")
    identified_components: List[str] = Field(description="A list of key components, frameworks, or libraries used (e.g., 'FastAPI', 'SQLAlchemy').")
    asvs_analysis: TaskBreakdown = Field(description="The relevance analysis for each security agent based on the code.")


async def analyze_repository_context_node(state: WorkerState) -> Dict[str, Any]:
    """
    Analyzes the complete repository map to provide a summary, identify components,
    and determine which specialized security agents are relevant.
    """
    scan_id, llm_config_id, repository_map = state['scan_id'], state['llm_config_id'], state['repository_map']

    if not repository_map:
        return {"error_message": "Cannot analyze context, repository map is missing."}
        
    logger.info(f"[ContextAnalysisAgent] Starting repository context analysis for scan.", extra={"scan_id": str(scan_id)})

    if not llm_config_id:
        return {"error_message": "LLM configuration ID not found in state for context analysis."}

    llm_client = await get_llm_client(llm_config_id)
    if not llm_client:
        return {"error_message": f"Failed to initialize LLM Client for config ID {llm_config_id}."}

    repo_map_json = repository_map.model_dump_json(indent=2)
    prompt = f"""
    You are an expert security architect. Your task is to analyze the provided repository map, which outlines the structure of a codebase.
    First, provide a brief, one-paragraph summary of the project's overall functionality in `analysis_summary`.
    Second, identify key components, frameworks, or libraries and list them in `identified_components`.
    Third, for each security agent in the `asvs_analysis` object, determine if its security domain is relevant for a detailed vulnerability scan of the project, and provide your reasoning.
    AGENT DESCRIPTIONS:
    {AGENT_DESCRIPTIONS}

    REPOSITORY MAP:
    ```json
    {repo_map_json}
    ```
    Respond ONLY with a valid JSON object that strictly adheres to the provided schema.
    """

    llm_response = await llm_client.generate_structured_output(prompt, FullContextAnalysis)

    if llm_response.error or not llm_response.parsed_output:
        error_msg = llm_response.error or "Failed to get a valid structured response from the LLM."
        return {"error_message": error_msg}

    if isinstance(llm_response.parsed_output, FullContextAnalysis):
        parsed_output = llm_response.parsed_output
        return {
            "analysis_summary": parsed_output.analysis_summary,
            "identified_components": parsed_output.identified_components,
            "asvs_analysis": parsed_output.asvs_analysis.model_dump(),
            "error_message": None,
        }
    else:
        return {"error_message": "LLM output did not match the expected FullContextAnalysis schema."}

async def retrieve_scan_data(state: WorkerState) -> Dict[str, Any]:
    scan_id = state['scan_id']
    logger.info(f"Entering node to retrieve data and status for scan.", extra={"scan_id": str(scan_id)})
    async with AsyncSessionLocal() as db:
        try:
            repo = ScanRepository(db)
            scan = await repo.get_scan_with_details(scan_id)
            if not scan:
                return {"error_message": f"Scan with ID {scan_id} not found."}
            
            logger.info(f"Scan {scan_id} starting with type: '{scan.scan_type}'")
            original_snapshot = next((s for s in scan.snapshots if s.snapshot_type == "ORIGINAL_SUBMISSION"), None)
            if not original_snapshot:
                return {"error_message": f"Original code snapshot not found for scan {scan_id}."}

            files_map = await repo.get_source_files_by_hashes(list(original_snapshot.file_map.values()))
            
            return {
                "files": {path: files_map.get(h, "") for path, h in original_snapshot.file_map.items()},
                "llm_config_id": scan.main_llm_config_id, 
                "scan_type": scan.scan_type,
                "current_scan_status": scan.status,
                "error_message": None,
            }
        except Exception as e:
            logger.error(f"Error retrieving data for scan {scan_id}: {e}", exc_info=True)
            return {"error_message": str(e)}

def create_repository_map_node(state: WorkerState) -> Dict[str, Any]:
    """
    Creates a repository map from the provided files, respecting exclusions.
    """
    scan_id = state['scan_id']
    logger.info(f"[ContextAnalysisAgent] Starting repository map creation for scan.", extra={"scan_id": str(scan_id)})
    
    all_files = state.get("files")
    if not all_files:
        return {"error_message": "No files found in state for repository mapping."}

    # Restore the logic for handling excluded files
    excluded_files_set = set(state.get("excluded_files") or [])
    
    if excluded_files_set:
        logger.info(f"Excluding {len(excluded_files_set)} files from analysis.")
        files_to_process = {
            path: content for path, content in all_files.items() if path not in excluded_files_set
        }
    else:
        files_to_process = all_files

    if not files_to_process:
        logger.warning("No files remaining for analysis after exclusions.", extra={"scan_id": str(scan_id)})
        return {"error_message": "No files remaining for analysis after exclusions."}

    try:
        mapping_engine = RepositoryMappingEngine()
        repository_map = mapping_engine.create_map(files_to_process)
        return {"repository_map": repository_map}
    except Exception as e:
        error_msg = f"Failed during repository map creation: {e}"
        logger.error(f"[ContextAnalysisAgent] {error_msg}", exc_info=True, extra={"scan_id": str(scan_id)})
        return {"error_message": error_msg}

async def determine_relevant_agents_node(state: WorkerState) -> Dict[str, Any]:
    scan_id = state['scan_id']
    logger.info(f"[COORDINATOR] Determining relevant agents for scan from DB.", extra={"scan_id": str(scan_id)})
    relevant_agents: Dict[str, str] = {}
    async with AsyncSessionLocal() as db:
        try:
            scan = await ScanRepository(db).get_scan(scan_id)
            if not scan or not scan.frameworks:
                logger.warning(f"Scan {scan_id} has no frameworks selected. No agents will run.")
                return {"relevant_agents": {}}
            
            framework_details = await db.execute(
                select(db_models.Framework).options(selectinload(db_models.Framework.agents)).where(db_models.Framework.name.in_(scan.frameworks))
            )
            for framework in framework_details.scalars().all():
                for agent in framework.agents:
                    if agent.name not in relevant_agents:
                        relevant_agents[agent.name] = agent.domain_query
        except Exception as e:
            return {"error_message": f"Failed to determine relevant agents from DB: {e}"}
    return {"relevant_agents": relevant_agents}

def create_context_bundles_node(state: WorkerState) -> Dict[str, Any]:
    scan_id = state['scan_id']
    logger.info(f"[COORDINATOR] Creating context bundles for scan.", extra={"scan_id": str(scan_id)})
    repository_map, files = state.get("repository_map"), state.get("files")
    if not repository_map or not files:
        return {"error_message": "Repository map or files missing for bundle creation."}
    try:
        engine = ContextBundlingEngine(repository_map, files)
        return {"context_bundles": engine.create_bundles()}
    except Exception as e:
        return {"error_message": f"Failed to create context bundles: {e}"}

async def estimate_cost_node(state: WorkerState) -> Dict[str, Any]:
    scan_id = state["scan_id"]
    logger.info(f"[COORDINATOR] Performing new cost estimation for scan.", extra={"scan_id": str(scan_id)})
    bundles, llm_config_id = state.get("context_bundles"), state.get("llm_config_id")
    if not bundles or not llm_config_id:
        return {"error_message": "Bundles or LLM config ID missing for cost estimation."}
    try:
        async with AsyncSessionLocal() as db:
            scan_repo, llm_config_repo = ScanRepository(db), LLMConfigRepository(db)
            llm_config = await llm_config_repo.get_by_id_with_decrypted_key(llm_config_id)
            if not llm_config:
                return {"error_message": f"LLM Config {llm_config_id} not found."}
            
            full_bundle_text = "".join(content for bundle in bundles for content in bundle.context_files.values())
            total_input_tokens = await cost_estimation.count_tokens(full_bundle_text, llm_config, getattr(llm_config, 'decrypted_api_key', None))
            cost_details = cost_estimation.estimate_cost_for_prompt(llm_config, total_input_tokens)
            
            await scan_repo.update_cost_and_status(scan_id, STATUS_PENDING_APPROVAL, cost_details)
        return {"current_scan_status": STATUS_PENDING_APPROVAL}
    except Exception as e:
        return {"error_message": f"Failed to estimate cost: {e}"}

async def run_specialized_agents_node(state: WorkerState) -> Dict[str, Any]:
    scan_id, scan_type = state["scan_id"], state["scan_type"]
    relevant_agents, context_bundles, files = state.get("relevant_agents"), state.get("context_bundles"), state.get("files")
    if not all([relevant_agents, context_bundles, files]):
        return {"error_message": "State is missing data for agent run."}

    async with AsyncSessionLocal() as db:
        scan = await db.get(db_models.Scan, scan_id)
        if not scan or not scan.specialized_llm_config_id:
            return {"error_message": f"Could not get specialized LLM config for scan {scan_id}"}
        specialized_llm_id = scan.specialized_llm_config_id
    
    logger.info(f"[COORDINATOR] Beginning agent runs in '{scan_type}' mode with concurrency {CONCURRENT_LLM_LIMIT}.", extra={"scan_id": str(scan_id)})
    generic_agent_graph, semaphore = build_generic_specialized_agent_graph(), asyncio.Semaphore(CONCURRENT_LLM_LIMIT)
    
    async def run_with_semaphore(coro):
            async with semaphore: return await coro

    tasks = []
    
    # Add this assertion to fix the "Optional Iterable" error
    assert context_bundles is not None 

    for agent_name, domain_query in relevant_agents.items():
        for bundle in context_bundles:
            agent_run_config: RunnableConfig = {"configurable": {"agent_name": agent_name, "domain_query": domain_query}}
            initial_agent_state: SpecializedAgentState = {
                "scan_id": scan_id, "llm_config_id": specialized_llm_id, "filename": bundle.target_file_path,
                "code_snippet": "".join(f"--- FILE: {p} ---\n{c}\n\n" for p, c in bundle.context_files.items()),
                "workflow_mode": "remediate" if scan_type == "AUDIT_AND_REMEDIATE" else "audit",
                "findings": [], "fixes": [], "error": None
            }
            tasks.append(run_with_semaphore(generic_agent_graph.ainvoke(initial_agent_state, config=agent_run_config)))
    
    agent_results = await asyncio.gather(*tasks, return_exceptions=True)
    all_findings, all_fixes = [], []
    for res in agent_results:
        if isinstance(res, Exception) or (isinstance(res, dict) and res.get("error")):
            logger.error(f"[COORDINATOR] Agent task failed: {res}")
            return {"error_message": "One or more specialized agents failed."}
        elif isinstance(res, dict):
            all_findings.extend(res.get("findings", []))
            all_fixes.extend(res.get("fixes", []))
    
    logger.debug(f"[DEBUG] Agents completed. Findings: {len(all_findings)}, Fixes: {len(all_fixes)}", extra={"scan_id": str(scan_id)})
    return {"findings": all_findings, "fixes": all_fixes, "live_codebase": None}

def should_run_cost_estimation(state: WorkerState) -> str:
    """Routes to the correct path based on the scan's initial status."""
    if state.get("error_message"):
        return "handle_error"
    
    status = state.get("current_scan_status")
    if status == STATUS_QUEUED:
        logger.info(f"Routing scan {state['scan_id']} to pre-approval path (setup and cost estimation).")
        return "run_setup_steps"
    elif status == STATUS_QUEUED_FOR_SCAN:
        logger.info(f"Routing scan {state['scan_id']} to post-approval path (agent execution).")
        return "run_setup_steps" # Both paths need the setup steps
    else:
        logger.error(f"Unknown status '{status}' for routing, sending to error handler.")
        return "handle_error"

async def patch_and_verify_node(state: WorkerState) -> Dict[str, Any]:
    """
    Verifies and applies code patches for REMEDIATE scans. Includes a retry mechanism.
    """
    scan_id = state['scan_id']
    fixes = state.get('fixes', [])
    original_files = state.get('files', {})
    
    # Use the specialized agent LLM config for patch retries
    async with AsyncSessionLocal() as db:
        scan = await ScanRepository(db).get_scan(scan_id)
        if not scan or not scan.specialized_llm_config_id:
            return {"error_message": "Could not retrieve specialized LLM config for patching."}
        llm_config_id = scan.specialized_llm_config_id
    
    if not original_files or not llm_config_id:
        return {"error_message": "Original files or LLM config missing for patching."}

    logger.info(f"Entering Patch & Verify node for scan {scan_id} with {len(fixes)} potential fixes.")
    live_codebase = original_files.copy()
    llm_client = await get_llm_client(llm_config_id)

    if not llm_client:
        return {"error_message": "Could not initialize LLM client for patch retries."}

    for fix in fixes:
        file_path = fix.finding.file_path
        original_snippet = fix.suggestion.original_snippet
        suggested_fix = fix.suggestion.code

        if file_path not in live_codebase:
            logger.warning(f"File '{file_path}' not in codebase, skipping fix.")
            continue

        for attempt in range(4):
            current_file_content = live_codebase[file_path]
            if original_snippet in current_file_content:
                live_codebase[file_path] = current_file_content.replace(original_snippet, suggested_fix, 1)
                logger.info(f"Successfully applied patch for CWE-{fix.finding.cwe} in {file_path}")
                break
            
            if attempt == 3:
                logger.error(f"Final attempt failed to apply patch in {file_path}. Discarding fix.")
                break

            logger.warning(f"Snippet not found in {file_path}. Attempting LLM correction (Attempt {attempt + 1}/3).")
            
            correction_prompt = f"""
            The following 'original_snippet' was not found in the 'source_code' provided.
            Please analyze the 'source_code' and the 'suggested_fix' to identify the correct 'original_snippet' that the fix should replace.
            The code may have been slightly modified by a previous fix. Find the logical equivalent of the original snippet.
            Respond ONLY with a JSON object containing the 'corrected_original_snippet'.

            <source_code>
            {current_file_content}
            </source_code>

            <original_snippet>
            {original_snippet}
            </original_snippet>

            <suggested_fix>
            {suggested_fix}
            </suggested_fix>
            """
            
            try:
                correction_result: AgentLLMResult = await llm_client.generate_structured_output(correction_prompt, CorrectedSnippet)
                if isinstance(correction_result.parsed_output, CorrectedSnippet):
                    original_snippet = correction_result.parsed_output.corrected_original_snippet
                    logger.info(f"Received corrected snippet from LLM: '{original_snippet[:50]}...'")
                else:
                    logger.warning("LLM failed to provide a corrected snippet.")
            except Exception as e:
                logger.error(f"Error during LLM patch correction: {e}")

    async with AsyncSessionLocal() as db:
        repo = ScanRepository(db)
        # Use the specific snapshot type for remediated code
        await repo.create_code_snapshot(scan_id, file_map=live_codebase, snapshot_type="POST_REMEDIATION")
        logger.info(f"Saved post-remediation code snapshot for scan {scan_id}")

    return {"live_codebase": live_codebase}

async def run_impact_reporting(state: WorkerState) -> Dict[str, Any]:
    """Invokes the ImpactReportingAgent sub-graph to generate the final reports."""
    scan_id_str = str(state['scan_id'])
    logger.info(f"Entering node to run ImpactReportingAgent.", extra={"scan_id": scan_id_str})
    
    # Use the main LLM for reporting
    llm_id_to_use = state.get("llm_config_id")

    reporting_input_state: ImpactReportingAgentState = {
        "scan_id": state["scan_id"],
        "llm_config_id": llm_id_to_use,
        "findings": state.get("findings", []),
        "impact_report": None,
        "sarif_report": None,
        "error": None,
    }

    reporting_graph = build_impact_reporting_agent_graph()
    report_output_state = await reporting_graph.ainvoke(reporting_input_state)

    if report_output_state.get("error"):
        error_msg = f"ImpactReportingAgent sub-graph failed: {report_output_state['error']}"
        logger.error(error_msg, extra={"scan_id": scan_id_str})
        return {"error_message": error_msg}
    
    logger.info("Received successful output from ImpactReportingAgent.", extra={"scan_id": scan_id_str})
    return {
        "impact_report": report_output_state.get("impact_report"),
        "sarif_report": report_output_state.get("sarif_report"),
    }

async def save_final_report_node(state: WorkerState) -> Dict[str, Any]:
    """Saves the final reports (impact, SARIF) and risk score to the database."""
    scan_id = state["scan_id"]
    impact_report = state.get("impact_report")
    sarif_report = state.get("sarif_report")
    findings = state.get("findings", [])

    # --- ADD THIS LOGGING BLOCK ---
    logger.debug(
        f"[DEBUG] Entering save_final_report_node. Findings in state: {len(findings)}. "
        f"Impact report exists: {bool(impact_report)}. SARIF report exists: {bool(sarif_report)}.",
        extra={"scan_id": str(scan_id)}
    )
    # --- END LOGGING BLOCK ---

    logger.info("Entering node to save final reports and risk score.", extra={"scan_id": str(scan_id)})

    if not impact_report and not sarif_report:
        logger.warning(f"No reports were found in state for scan.", extra={"scan_id": str(scan_id)})

    risk_score = 0.0
    severity_map = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFORMATIONAL": 0}
    if findings:
        for f in findings:
            sev = f.severity.upper() if f.severity else "LOW"
            if sev in severity_map:
                severity_map[sev] += 1
        
        if severity_map["CRITICAL"] > 0:
            risk_score = min(10.0, 9.0 + (severity_map["CRITICAL"] * 0.1))
        elif severity_map["HIGH"] > 0:
            risk_score = min(8.9, 7.0 + (severity_map["HIGH"] * 0.1))
        elif severity_map["MEDIUM"] > 0:
            risk_score = min(6.9, 4.0 + (severity_map["MEDIUM"] * 0.1))
        elif severity_map["LOW"] > 0:
            risk_score = min(3.9, 1.0 + (severity_map["LOW"] * 0.1))
    
    final_risk_score = int(round(risk_score, 0))
    
    summary_data = {
        "summary": {
            "total_findings_count": len(findings),
            "files_analyzed_count": len(set(f.file_path for f in findings)),
            "severity_counts": severity_map,
        },
        "overall_risk_score": {
            "score": final_risk_score,
            "severity": "High" # Placeholder
        }
    }
            
    # FIX: Ensure this logic correctly uses the 'scan_type' key
    final_status = STATUS_REMEDIATION_COMPLETE if state['scan_type'] == 'AUDIT_AND_REMEDIATE' else STATUS_COMPLETED

    async with AsyncSessionLocal() as db:
        repo = ScanRepository(db)
        await repo.save_final_reports_and_status(
            scan_id=scan_id,
            status=final_status,
            impact_report=impact_report,    
            sarif_report=sarif_report,
            summary=summary_data,
            risk_score=final_risk_score
        )
    
    logger.info("Successfully saved final reports and risk score.", extra={"scan_id": str(scan_id)})
    return {}


async def handle_error_node(state: WorkerState) -> Dict[str, Any]:
    """A terminal node to handle any errors that occurred during the workflow."""
    error = state.get("error_message") or state.get("error") or "An unknown error occurred."
    scan_id = state['scan_id']
    logger.error(f"Workflow for scan failed: {error}", extra={"scan_id": str(scan_id), "error_message": error})
    async with AsyncSessionLocal() as db:
        repo = ScanRepository(db)
        await repo.update_status(scan_id, "Failed")
    return {}


def should_continue(state: WorkerState) -> str:
    return "handle_error" if state.get("error_message") or state.get("error") else "continue"

def route_after_setup(state: WorkerState) -> str:
    if state.get("error_message"): return "handle_error"
    status = state.get("current_scan_status")
    if status == STATUS_QUEUED: return "estimate_cost"
    elif status == STATUS_QUEUED_FOR_SCAN: return "run_specialized_agents"
    else: return "handle_error"

def route_after_agents(state: WorkerState) -> str:
    if state.get("error_message"): return "handle_error"
    return "patch_and_verify" if state.get("scan_type") == 'AUDIT_AND_REMEDIATE' else "run_impact_reporting"


# --- WORKFLOW WIRING ---
workflow = StateGraph(WorkerState)
workflow.add_node("retrieve_scan_data", retrieve_scan_data)
workflow.add_node("create_repository_map", create_repository_map_node)
workflow.add_node("analyze_repository_context", analyze_repository_context_node)
workflow.add_node("determine_relevant_agents", determine_relevant_agents_node)
workflow.add_node("create_context_bundles", create_context_bundles_node)
workflow.add_node("estimate_cost", estimate_cost_node)
workflow.add_node("run_specialized_agents", run_specialized_agents_node)
workflow.add_node("patch_and_verify", patch_and_verify_node)
workflow.add_node("run_impact_reporting", run_impact_reporting)
workflow.add_node("save_final_report", save_final_report_node)
workflow.add_node("handle_error", handle_error_node)

# --- Define the new, linear workflow ---
workflow.set_entry_point("retrieve_scan_data")

# Initial routing based on scan status from DB
workflow.add_conditional_edges(
    "retrieve_scan_data",
    should_run_cost_estimation,
    {
        "run_setup_steps": "create_repository_map",
        "handle_error": "handle_error",
    }
)

# Common setup path
workflow.add_edge("create_repository_map", "analyze_repository_context")
workflow.add_edge("analyze_repository_context", "determine_relevant_agents")
workflow.add_edge("determine_relevant_agents", "create_context_bundles")

# After setup, a new router decides the next step
workflow.add_conditional_edges("create_context_bundles", route_after_setup, {
    "estimate_cost": "estimate_cost",
    "run_specialized_agents": "run_specialized_agents",
    "handle_error": "handle_error"
})
workflow.add_conditional_edges("estimate_cost", lambda s: END if s.get("current_scan_status") == STATUS_PENDING_APPROVAL else "handle_error", {
    END: END, "handle_error": "handle_error"
})
workflow.add_conditional_edges("run_specialized_agents", route_after_agents, {
    "patch_and_verify": "patch_and_verify",
    "run_impact_reporting": "run_impact_reporting",
    "handle_error": "handle_error"
})
workflow.add_conditional_edges("patch_and_verify", should_continue, {"continue": "run_impact_reporting", "handle_error": "handle_error"})
workflow.add_conditional_edges("run_impact_reporting", should_continue, {"continue": "save_final_report", "handle_error": "handle_error"})
workflow.add_edge("save_final_report", END)
workflow.add_edge("handle_error", END)


_workflow: Optional[Pregel] = None
_checkpointer_conn: Optional[psycopg.AsyncConnection] = None

async def get_workflow() -> Pregel:
    global _workflow, _checkpointer_conn
    if _workflow is not None:
        return _workflow

    if not settings.ASYNC_DATABASE_URL:
        raise ValueError("ASYNC_DATABASE_URL must be configured.")

    if _checkpointer_conn is None or _checkpointer_conn.closed:
        logger.info("Creating new psycopg async connection for checkpointer...")
        try:
            conn_url = settings.ASYNC_DATABASE_URL.replace("postgresql+asyncpg://", "postgresql://")
            _checkpointer_conn = await psycopg.AsyncConnection.connect(conn_url)
        except Exception as e:
            logger.error(f"Failed to create psycopg async connection for checkpointer: {e}", exc_info=True)
            raise

    checkpointer = AsyncPostgresSaver(conn=_checkpointer_conn) # type: ignore
    
    _workflow = workflow.compile(checkpointer=checkpointer)
    logger.info("Main worker workflow compiled and ready with PostgreSQL checkpointer.")
    return _workflow

async def close_workflow_resources():
    global _checkpointer_conn
    if _checkpointer_conn and not _checkpointer_conn.closed:
        logger.info("Closing checkpointer database connection.")
        await _checkpointer_conn.close()
        _checkpointer_conn = None