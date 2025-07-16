import logging
import uuid
import datetime
import hashlib
from typing import List, Dict, Optional, Any

from sqlalchemy import String, case, cast, func, select, update, or_
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload, aliased

from app.infrastructure.database import models as db_models
from app.core import schemas as agent_schemas

logger = logging.getLogger(__name__)


class ScanRepository:
    """
    Handles all database operations related to projects, scans, code snapshots,
    findings, and their associated data.
    """

    def __init__(self, db_session: AsyncSession):
        self.db = db_session

    async def get_or_create_project(self, name: str, user_id: int, repo_url: Optional[str] = None) -> db_models.Project:
        """Retrieves a project by name for a user, or creates it if it doesn't exist."""
        stmt = select(db_models.Project).filter_by(name=name, user_id=user_id)
        result = await self.db.execute(stmt)
        project = result.scalars().first()

        if not project:
            logger.info(f"Creating new project '{name}' for user {user_id}.")
            project = db_models.Project(name=name, user_id=user_id, repository_url=repo_url)
            self.db.add(project)
            await self.db.commit()
            await self.db.refresh(project)
        
        return project

    async def create_scan(self, project_id: uuid.UUID, user_id: int, scan_type: str, main_llm_config_id: uuid.UUID, specialized_llm_config_id: uuid.UUID, frameworks: List[str]) -> db_models.Scan:
        """Creates a new Scan record."""
        logger.info(f"Creating new scan for project {project_id} with type '{scan_type}'.")
        scan = db_models.Scan(
            project_id=project_id, 
            user_id=user_id, 
            scan_type=scan_type, 
            status="QUEUED",
            main_llm_config_id=main_llm_config_id,
            specialized_llm_config_id=specialized_llm_config_id,
            frameworks=frameworks
        )
        self.db.add(scan)
        await self.db.commit()
        await self.db.refresh(scan)
        return scan

    async def get_or_create_source_files(self, files_data: List[Dict[str, Any]]) -> List[str]:
        """
        Accepts a list of files, hashes them, and saves new ones to the database.
        Returns a list of all file hashes for the given input.
        """
        file_hashes = []
        new_files_to_add = []
        for file_data in files_data:
            content = file_data["content"]
            hasher = hashlib.sha256()
            hasher.update(content.encode('utf-8'))
            file_hash = hasher.hexdigest()
            file_hashes.append(file_hash)

            # Check if this file hash already exists
            existing_file = await self.db.get(db_models.SourceCodeFile, file_hash)
            if not existing_file:
                new_files_to_add.append(
                    db_models.SourceCodeFile(
                        hash=file_hash,
                        content=content,
                        language=file_data.get("language", "unknown")
                    )
                )
        
        if new_files_to_add:
            logger.info(f"Adding {len(new_files_to_add)} new unique source files to the database.")
            self.db.add_all(new_files_to_add)
            await self.db.commit()
            
        return file_hashes

    async def create_code_snapshot(self, scan_id: uuid.UUID, file_map: Dict[str, str], snapshot_type: str) -> db_models.CodeSnapshot:
        """Creates a code snapshot record for a scan."""
        snapshot = db_models.CodeSnapshot(
            scan_id=scan_id,
            file_map=file_map,
            snapshot_type=snapshot_type
        )
        self.db.add(snapshot)
        await self.db.commit()
        await self.db.refresh(snapshot)
        return snapshot
        
    async def get_scan(self, scan_id: uuid.UUID) -> Optional[db_models.Scan]:
        """Retrieves a single scan by its ID."""
        logger.debug("Fetching scan from DB.", extra={"scan_id": str(scan_id)})
        result = await self.db.execute(
            select(db_models.Scan).filter(db_models.Scan.id == scan_id)
        )
        return result.scalars().first()

    async def get_scan_with_details(self, scan_id: uuid.UUID) -> Optional[db_models.Scan]:
        """Retrieves a scan with its related snapshots, findings, and project."""
        logger.debug("Fetching scan with details from DB.", extra={"scan_id": str(scan_id)})
        result = await self.db.execute(
            select(db_models.Scan)
            .options(
                selectinload(db_models.Scan.project),
                selectinload(db_models.Scan.snapshots),
                selectinload(db_models.Scan.findings)
            )
            .filter(db_models.Scan.id == scan_id)
        )
        return result.scalars().first()

    async def update_scan_artifacts(self, scan_id: uuid.UUID, artifacts: Dict[str, Any]):
        """Updates a scan record with large artifact JSONB data."""
        logger.info(f"Updating artifacts for scan {scan_id} in DB.", extra={"scan_id": str(scan_id), "artifacts": list(artifacts.keys())})
        stmt = update(db_models.Scan).where(db_models.Scan.id == scan_id).values(**artifacts)
        await self.db.execute(stmt)
        await self.db.commit()

    async def update_status(self, scan_id: uuid.UUID, status: str):
        """Updates the status of a single scan."""
        logger.info("Updating scan status in DB.", extra={"scan_id": str(scan_id), "new_status": status})
        stmt = update(db_models.Scan).where(db_models.Scan.id == scan_id).values(status=status)
        await self.db.execute(stmt)
        await self.db.commit()

    async def create_scan_event(self, scan_id: uuid.UUID, stage_name: str, status: str = "STARTED"):
        """Adds a new event to the scan's timeline."""
        logger.debug(f"Adding timeline event '{stage_name}:{status}' for scan {scan_id}")
        event = db_models.ScanEvent(scan_id=scan_id, stage_name=stage_name, status=status)
        self.db.add(event)
        await self.db.commit()
        
    async def save_llm_interaction(self, interaction_data: agent_schemas.LLMInteraction):
        """Saves a single LLM interaction record to the database."""
        logger.debug(
            "Saving LLM interaction to DB.",
            extra={
                "scan_id": str(interaction_data.scan_id),
                "agent_name": interaction_data.agent_name
            }
        )
        db_interaction = db_models.LLMInteraction(**interaction_data.model_dump())
        self.db.add(db_interaction)
        await self.db.commit()

    async def save_findings(self, scan_id: uuid.UUID, findings: List[agent_schemas.VulnerabilityFinding]):
        """Saves a list of vulnerability findings for a scan."""
        if not findings:
            return
        logger.info("Saving vulnerability findings to DB.", extra={"scan_id": str(scan_id), "finding_count": len(findings)})
        db_findings = [db_models.Finding(scan_id=scan_id, **f.model_dump()) for f in findings]
        self.db.add_all(db_findings)
        await self.db.commit()

    async def update_cost_and_status(self, scan_id: uuid.UUID, status: str, estimated_cost: Dict[str, Any]):
        """Atomically updates the status and the estimated cost of a scan."""
        logger.info(
            "Updating cost and status in DB.",
            extra={
                "scan_id": str(scan_id),
                "new_status": status,
                "total_estimated_cost": estimated_cost.get("total_estimated_cost")
            }
        )
        stmt = update(db_models.Scan).where(db_models.Scan.id == scan_id).values(status=status, cost_details=estimated_cost)
        await self.db.execute(stmt)
        await self.db.commit()

    async def save_final_reports_and_status(
        self,
        scan_id: uuid.UUID,
        status: str,
        impact_report: Optional[Dict[str, Any]],
        sarif_report: Optional[Dict[str, Any]],
        summary: Optional[Dict[str, Any]],
        risk_score: Optional[int],
    ):
        """Saves the final analysis reports, sets the completion timestamp, and updates the status."""
        logger.info("Saving final reports and status to DB.", extra={"scan_id": str(scan_id), "new_status": status})
        completed_at_aware = datetime.datetime.now(datetime.timezone.utc)
        values = {
            "status": status,
            "completed_at": completed_at_aware,
            "risk_score": risk_score,
            "impact_report": impact_report,
            "sarif_report": sarif_report,
            "summary": summary
        }
        stmt = update(db_models.Scan).where(db_models.Scan.id == scan_id).values(**values)
        await self.db.execute(stmt)
        await self.db.commit()

    async def get_project_by_id(self, project_id: uuid.UUID) -> Optional[db_models.Project]:
        """Retrieves a single project by its ID."""
        logger.debug("Fetching project from DB.", extra={"project_id": str(project_id)})
        result = await self.db.execute(
            select(db_models.Project).filter(db_models.Project.id == project_id)
        )
        return result.scalars().first()

    async def get_scans_count_for_project(self, project_id: uuid.UUID) -> int:
        """Counts the total number of scans for a specific project."""
        stmt = select(func.count(db_models.Scan.id)).where(db_models.Scan.project_id == project_id)
        result = await self.db.execute(stmt)
        return result.scalar_one() or 0

    async def get_paginated_scans_for_project(self, project_id: uuid.UUID, skip: int, limit: int) -> List[db_models.Scan]:
        """Retrieves a paginated list of scans for a specific project."""
        stmt = (
            select(db_models.Scan)
            .options(selectinload(db_models.Scan.events))
            .where(db_models.Scan.project_id == project_id)
            .order_by(db_models.Scan.created_at.desc())
            .offset(skip)
            .limit(limit)
        )
        result = await self.db.execute(stmt)
        return list(result.scalars().all())
    
    async def get_paginated_projects(self, user_id: int, skip: int, limit: int, search: Optional[str]) -> List[db_models.Project]:
        """Retrieves a paginated list of projects for a user."""
        stmt = (
            select(db_models.Project)
            .options(selectinload(db_models.Project.scans).joinedload(db_models.Scan.user))
            .where(db_models.Project.user_id == user_id)
        )
        if search:
            stmt = stmt.filter(db_models.Project.name.ilike(f"%{search}%"))
        stmt = stmt.order_by(db_models.Project.updated_at.desc()).offset(skip).limit(limit)
        result = await self.db.execute(stmt)
        return list(result.scalars().all())

    async def get_projects_count(self, user_id: int, search: Optional[str]) -> int:
        """Counts the total number of projects for a specific user."""
        stmt = select(func.count(db_models.Project.id)).where(db_models.Project.user_id == user_id)
        if search:
            stmt = stmt.filter(db_models.Project.name.ilike(f"%{search}%"))
        result = await self.db.execute(stmt)
        return result.scalar_one() or 0

    async def get_llm_interactions_for_scan(self, scan_id: uuid.UUID) -> List[db_models.LLMInteraction]:
        """Retrieves all LLM interactions for a specific scan."""
        stmt = (
            select(db_models.LLMInteraction)
            .where(db_models.LLMInteraction.scan_id == scan_id)
            .order_by(db_models.LLMInteraction.timestamp.asc())
        )
        result = await self.db.execute(stmt)
        return list(result.scalars().all())

    async def get_source_files_by_hashes(self, file_hashes: List[str]) -> Dict[str, str]:
        """Retrieves a dictionary of file content keyed by their hashes."""
        if not file_hashes:
            return {}
        stmt = select(db_models.SourceCodeFile).where(db_models.SourceCodeFile.hash.in_(file_hashes))
        result = await self.db.execute(stmt)
        return {file.hash: file.content for file in result.scalars().all()}
    
    async def delete_scan(self, scan_id: uuid.UUID) -> bool:
        """Deletes a scan record from the database."""
        scan = await self.db.get(db_models.Scan, scan_id)
        if scan:
            await self.db.delete(scan)
            await self.db.commit()
            return True
        return False

    async def delete_project(self, project_id: uuid.UUID) -> bool:
        """Deletes a project record and its cascade-deleted scans."""
        project = await self.db.get(db_models.Project, project_id)
        if project:
            await self.db.delete(project)
            await self.db.commit()
            return True
        return False

