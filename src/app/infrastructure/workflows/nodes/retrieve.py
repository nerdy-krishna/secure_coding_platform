"""`retrieve_and_prepare_data` worker-graph node.

Fetches the scan, builds the repository map + dependency graph, and
resolves the relevant agents from the selected frameworks.

The string name registered via `workflow.add_node("retrieve_and_prepare_data", ...)`
is part of the LangGraph checkpointer's on-disk contract — do not rename.
"""

from __future__ import annotations

import logging
from typing import Any, Dict

import networkx as nx
from sqlalchemy import select
from sqlalchemy.orm import selectinload

from app.infrastructure.database import AsyncSessionLocal
from app.infrastructure.database import models as db_models
from app.infrastructure.database.repositories.scan_repo import ScanRepository
from app.infrastructure.workflows.state import RelevantAgent, WorkerState
from app.shared.analysis_tools.context_bundler import ContextBundlingEngine
from app.shared.analysis_tools.repository_map import RepositoryMappingEngine
from app.shared.lib.scan_status import STATUS_ANALYZING_CONTEXT

logger = logging.getLogger(__name__)


async def retrieve_and_prepare_data_node(state: WorkerState) -> Dict[str, Any]:
    """
    Node to retrieve all initial data, create the repo map, and dependency graph.
    """
    scan_id = state["scan_id"]
    logger.info(f"Entering node to retrieve and prepare data for scan {scan_id}.")
    try:
        async with AsyncSessionLocal() as db:
            repo = ScanRepository(db)

            # --- FETCH SCAN FIRST to get its status ---
            scan = await repo.get_scan_with_details(scan_id)
            if not scan:
                return {"error_message": f"Scan with ID {scan_id} not found."}

            # Capture the status before updating the DB
            current_status = scan.status

            # Now, update the status to show progress
            await repo.update_status(scan_id, STATUS_ANALYZING_CONTEXT)

            original_snapshot = next(
                (s for s in scan.snapshots if s.snapshot_type == "ORIGINAL_SUBMISSION"),
                None,
            )
            if not original_snapshot:
                return {
                    "error_message": f"Original code snapshot not found for scan {scan_id}."
                }

            files_map = await repo.get_source_files_by_hashes(
                list(original_snapshot.file_map.values())
            )
            files = {
                path: files_map.get(h, "")
                for path, h in original_snapshot.file_map.items()
            }

            # Create Repo Map
            mapping_engine = RepositoryMappingEngine()
            repository_map = mapping_engine.create_map(files)
            logger.info(f"DEBUG: repository_map content: {repository_map.model_dump()}")

            # Create Dependency Graph
            bundling_engine = ContextBundlingEngine(repository_map, files)
            dependency_graph = bundling_engine.graph
            logger.info(
                f"DEBUG: dependency_graph content: {nx.node_link_data(dependency_graph)}"
            )

            # Determine Relevant Agents
            framework_details = await db.execute(
                select(db_models.Framework)
                .options(selectinload(db_models.Framework.agents))
                .where(db_models.Framework.name.in_(scan.frameworks or []))
            )
            # Store full agent details for the triage step
            all_relevant_agents = {
                agent.name: RelevantAgent(
                    name=agent.name,
                    description=agent.description,
                    domain_query=agent.domain_query,
                )
                for framework in framework_details.scalars().all()
                for agent in framework.agents
            }

            # --- FIX: Add this block to explicitly save the artifacts ---
            serialized_graph = nx.node_link_data(dependency_graph)
            await repo.update_scan_artifacts(
                scan_id,
                {
                    "repository_map": repository_map.model_dump(),
                    "dependency_graph": serialized_graph,
                },
            )
            # --- End of FIX ---

            return {
                "scan_type": scan.scan_type,
                "current_scan_status": current_status,
                "reasoning_llm_config_id": scan.reasoning_llm_config_id,
                "files": files,
                "initial_file_map": original_snapshot.file_map,
                "live_codebase": files.copy(),
                "repository_map": repository_map,
                "dependency_graph": nx.node_link_data(dependency_graph),
                "findings": [],
                "all_relevant_agents": all_relevant_agents,
            }
    except Exception as e:
        logger.error(f"Error preparing data for scan {scan_id}: {e}", exc_info=True)
        return {"error_message": str(e)}
