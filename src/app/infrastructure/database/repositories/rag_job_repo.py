# src/app/infrastructure/database/repositories/rag_job_repo.py
import hashlib
import logging
import uuid
from typing import Any, Dict, List, Optional

from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.infrastructure.database import models as db_models

logger = logging.getLogger(__name__)


class RAGJobRepository:
    """Handles DB operations for RAGPreprocessingJob."""

    def __init__(self, db_session: AsyncSession):
        self.db = db_session

    def hash_content(self, content: bytes) -> str:
        """Generates a SHA-256 hash of the file content."""
        return hashlib.sha256(content).hexdigest()

    async def find_completed_job_by_hash(
        self, file_hash: str, llm_config_id: uuid.UUID
    ) -> Optional[db_models.RAGPreprocessingJob]:
        """Finds a successfully completed job by file hash and LLM config."""
        stmt = select(db_models.RAGPreprocessingJob).where(
            db_models.RAGPreprocessingJob.original_file_hash == file_hash,
            db_models.RAGPreprocessingJob.llm_config_id == llm_config_id,
            db_models.RAGPreprocessingJob.status == "COMPLETED",
        )
        result = await self.db.execute(stmt)
        return result.scalars().first()

    async def create_job(
        self,
        user_id: int,
        framework_name: str,
        llm_config_id: uuid.UUID,
        file_hash: str,
    ) -> db_models.RAGPreprocessingJob:
        """Creates a new job record in the database."""
        job = db_models.RAGPreprocessingJob(
            user_id=user_id,
            framework_name=framework_name,
            llm_config_id=llm_config_id,
            original_file_hash=file_hash,
            status="PENDING",
        )
        self.db.add(job)
        await self.db.commit()
        await self.db.refresh(job)
        return job

    async def get_job_by_id(
        self, job_id: uuid.UUID, user_id: int
    ) -> Optional[db_models.RAGPreprocessingJob]:
        """Retrieves a job by its ID, ensuring user has access."""
        stmt = select(db_models.RAGPreprocessingJob).where(
            db_models.RAGPreprocessingJob.id == job_id,
            db_models.RAGPreprocessingJob.user_id == user_id,
        )
        result = await self.db.execute(stmt)
        return result.scalars().first()

    async def update_job(self, job_id: uuid.UUID, data: Dict[str, Any]):
        """Updates a job record with the given data."""
        stmt = (
            update(db_models.RAGPreprocessingJob)
            .where(db_models.RAGPreprocessingJob.id == job_id)
            .values(**data)
        )
        await self.db.execute(stmt)
        await self.db.commit()