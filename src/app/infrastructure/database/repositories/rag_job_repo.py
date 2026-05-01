# src/app/infrastructure/database/repositories/rag_job_repo.py
import hashlib
import logging
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, Optional

from sqlalchemy import select, update
from sqlalchemy.exc import SQLAlchemyError
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
        try:
            await self.db.commit()
            await self.db.refresh(job)
        except SQLAlchemyError:
            logger.error(
                "rag_job.create.failed",
                extra={
                    "job_id": None,
                    "user_id": user_id,
                    "framework_name": framework_name,
                },
                exc_info=True,
            )
            raise
        logger.info(
            "rag_job.created",
            extra={
                "job_id": str(job.id),
                "user_id": user_id,
                "framework_name": framework_name,
                "llm_config_id": str(llm_config_id),
            },
        )
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
        row = result.scalars().first()
        if row is None:
            logger.warning(
                "rag_job.access.denied_or_missing",
                extra={"job_id": str(job_id), "user_id": user_id},
            )
        return row

    async def update_job(self, job_id: uuid.UUID, data: Dict[str, Any]):
        """Updates a job record with the given data."""
        stmt = (
            update(db_models.RAGPreprocessingJob)
            .where(db_models.RAGPreprocessingJob.id == job_id)
            .values(**data)
        )
        await self.db.execute(stmt)
        try:
            await self.db.commit()
        except SQLAlchemyError:
            logger.error(
                "rag_job.update.failed",
                extra={"job_id": str(job_id)},
                exc_info=True,
            )
            raise
        logger.info(
            "rag_job.updated",
            extra={"job_id": str(job_id), "updated_fields": list(data.keys())},
        )
        if data.get("status") == "FAILED":
            logger.warning(
                "rag_job.failed",
                extra={
                    "job_id": str(job_id),
                    "error_class": type(data.get("error_message")).__name__,
                },
            )

    async def get_latest_job_for_framework(
        self, framework_name: str, user_id: int
    ) -> Optional[db_models.RAGPreprocessingJob]:
        """Retrieves the most recent completed job for a framework to access raw content."""
        stmt = (
            select(db_models.RAGPreprocessingJob)
            .where(
                db_models.RAGPreprocessingJob.framework_name == framework_name,
                db_models.RAGPreprocessingJob.user_id == user_id,
                db_models.RAGPreprocessingJob.status == "COMPLETED",
                db_models.RAGPreprocessingJob.raw_content.isnot(None),
            )
            .order_by(db_models.RAGPreprocessingJob.created_at.desc())
            .limit(1)
        )
        result = await self.db.execute(stmt)
        return result.scalars().first()

    async def purge_old_raw_content(self, retention_days: int) -> int:
        """Nulls out raw_content on completed jobs older than retention_days.

        Default retention is 90 days. Call this from a periodic sweeper to
        limit the window in which uploaded file bytes remain in the database.
        """
        cutoff = datetime.now(timezone.utc) - timedelta(days=retention_days)
        stmt = (
            update(db_models.RAGPreprocessingJob)
            .where(db_models.RAGPreprocessingJob.status == "COMPLETED")
            .where(db_models.RAGPreprocessingJob.completed_at < cutoff)
            .where(db_models.RAGPreprocessingJob.raw_content.isnot(None))
            .values(raw_content=None)
        )
        res = await self.db.execute(stmt)
        await self.db.commit()
        return res.rowcount or 0
