# src/app/infrastructure/agents/context_analysis_agent.py

import logging
import uuid
import hashlib
from typing import Dict, Any, TypedDict, Optional, List, cast

from langgraph.graph import StateGraph, END
from pydantic import BaseModel, Field

from app.shared.analysis_tools.repository_map import RepositoryMappingEngine, RepositoryMap
from app.infrastructure.llm_client import get_llm_client
from app.infrastructure.database import AsyncSessionLocal
from app.infrastructure.database.repositories.cache_repo import CacheRepository

# Configure logging
logger = logging.getLogger(__name__)
AGENT_NAME = "ContextAnalysisAgent"

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
    is_relevant: bool = Field(
        ...,
        description="True if the agent's security domain is relevant to the code, otherwise False.",
    )
    reasoning: str = Field(
        ..., description="A brief explanation for why the agent is or is not relevant."
    )


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
    """The complete structured output for the context analysis agent."""

    analysis_summary: str = Field(
        description="A brief, one-paragraph summary of the entire project's functionality based on the repository map."
    )
    identified_components: List[str] = Field(
        description="A list of key components, frameworks, or libraries used (e.g., 'FastAPI', 'SQLAlchemy')."
    )
    asvs_analysis: TaskBreakdown = Field(
        description="The relevance analysis for each security agent based on the code."
    )

class ContextAnalysisAgentState(TypedDict):
    """
    Defines the state for the Context Analysis Agent's workflow.
    """
    llm_config_id: uuid.UUID
    submission_id: uuid.UUID
    files: Dict[str, str]
    excluded_files: Optional[List[str]]
    repository_map: Optional[RepositoryMap]
    analysis_summary: Optional[str]
    identified_components: Optional[List[str]]
    asvs_analysis: Optional[Dict[str, Any]]
    error_message: Optional[str]


# --- Updated Node with Caching Logic ---
async def create_repository_map_node(state: ContextAnalysisAgentState) -> Dict[str, Any]:
    """
    Creates a repository map. It first checks for a cached version based on
    a hash of the codebase. If not found, it generates a new map and saves
    it to the cache. It now respects the `excluded_files` list.
    """
    logger.info(f"[{AGENT_NAME}] Starting repository map creation for submission {state['submission_id']}.")
    
    all_files = state["files"]
    excluded_files_set = set(state.get("excluded_files") or [])
    
    if excluded_files_set:
        logger.info(f"[{AGENT_NAME}] Excluding {len(excluded_files_set)} files from analysis.")
        files_to_process = {
            path: content for path, content in all_files.items() if path not in excluded_files_set
        }
        logger.debug(f"[{AGENT_NAME}] Files remaining for analysis: {len(files_to_process)}")
    else:
        files_to_process = all_files

    if not files_to_process:
        return {"error_message": "No files remaining after exclusions."}

    sorted_files = sorted(files_to_process.items())
    hasher = hashlib.sha256()
    for _, content in sorted_files:
        hasher.update(content.encode('utf-8'))
    codebase_hash = hasher.hexdigest()
    
    logger.info(f"[{AGENT_NAME}] Calculated codebase_hash: {codebase_hash}")

    async with AsyncSessionLocal() as db:
        try:
            cache_repo = CacheRepository(db)
            cached_map = await cache_repo.get_repository_map(codebase_hash)
            if cached_map:
                logger.info(f"[{AGENT_NAME}] Cache hit! Using cached repository map for hash {codebase_hash}.")
                return {"repository_map": cached_map}

            logger.info(f"[{AGENT_NAME}] Cache miss. Generating new repository map.")
            mapping_engine = RepositoryMappingEngine()
            repository_map = mapping_engine.create_map(files_to_process)
            
            await cache_repo.create_repository_map(codebase_hash, repository_map)
            logger.info(f"[{AGENT_NAME}] New repository map saved to cache.")
            
            return {"repository_map": repository_map}
        
        except Exception as e:
            error_msg = f"Failed during repository map creation/caching: {e}"
            logger.error(f"[{AGENT_NAME}] {error_msg}")
            return {"error_message": error_msg}


async def analyze_repository_context_node(state: ContextAnalysisAgentState) -> Dict[str, Any]:
    """
    Analyzes the complete repository map to provide a summary, identify components,
    and determine which specialized security agents are relevant.
    """
    submission_id = state['submission_id']
    llm_config_id = state['llm_config_id']
    repository_map = state['repository_map']

    if not repository_map:
        return {"error_message": "Cannot analyze context, repository map is missing."}
        
    logger.info(f"[{AGENT_NAME}] Starting repository context analysis for submission: {submission_id}")

    llm_client = await get_llm_client(cast(uuid.UUID, llm_config_id))
    if not llm_client:
        error_msg = f"Failed to initialize LLM Client for config ID {llm_config_id}."
        logger.error(f"[{AGENT_NAME}] {error_msg}")
        return {"error_message": error_msg}

    repo_map_json = repository_map.model_dump_json(indent=2)

    prompt = f"""
    You are an expert security architect.
    Your task is to analyze the provided repository map, which outlines the structure, files, imports, and symbols of an entire codebase.
    First, provide a brief, one-paragraph summary of the project's overall functionality in `analysis_summary`.
    Second, identify key components, frameworks, or libraries from the imports and file structures and list them in `identified_components`.
    Third, for each security agent in the `asvs_analysis` object, determine if its security domain is relevant for a detailed vulnerability scan of the entire project, and provide your reasoning.
    AGENT DESCRIPTIONS:
    {AGENT_DESCRIPTIONS}

    REPOSITORY MAP:
    ```json
    {repo_map_json}
    ```

    Respond with a single, valid JSON object that strictly adheres to the provided schema.
    """

    llm_response = await llm_client.generate_structured_output(
        prompt, FullContextAnalysis
    )

    if llm_response.error or not llm_response.parsed_output:
        error_msg = (
            llm_response.error
            or "Failed to get a valid structured response from the LLM."
        )
        logger.error(
            f"[{AGENT_NAME}] Failed to get full context analysis from LLM for submission {submission_id}: {error_msg}"
        )
        return {"error_message": error_msg}

    parsed_output = cast(FullContextAnalysis, llm_response.parsed_output)
    logger.info(
        f"[{AGENT_NAME}] Repository context analysis complete for submission {submission_id}."
    )

    return {
        "analysis_summary": parsed_output.analysis_summary,
        "identified_components": parsed_output.identified_components,
        "asvs_analysis": parsed_output.asvs_analysis.model_dump(),
        "error_message": None,
    }


def build_context_analysis_agent_graph():
    """Builds the graph for the context analysis agent."""
    workflow = StateGraph(ContextAnalysisAgentState)
    
    workflow.add_node("create_repository_map", create_repository_map_node)
    workflow.add_node("analyze_repository_context", analyze_repository_context_node)

    workflow.set_entry_point("create_repository_map")
    workflow.add_edge("create_repository_map", "analyze_repository_context")
    workflow.add_edge("analyze_repository_context", END)
    
    return workflow.compile()