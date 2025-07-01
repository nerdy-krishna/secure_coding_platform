# src/app/api/v1/dependencies.py

from fastapi import Depends
from sqlalchemy.ext.asyncio import AsyncSession
from app.infrastructure.database.database import get_db
from app.infrastructure.database.repositories.llm_config_repo import LLMConfigRepository
from app.infrastructure.database.repositories.submission_repo import SubmissionRepository
from app.core.services.admin_service import AdminService
from app.core.services.submission_service import SubmissionService


def get_llm_config_repository(
    db: AsyncSession = Depends(get_db),
) -> LLMConfigRepository:
    return LLMConfigRepository(db)


def get_admin_service(
    repo: LLMConfigRepository = Depends(get_llm_config_repository),
) -> AdminService:
    return AdminService(repo)


def get_submission_repository(
    db: AsyncSession = Depends(get_db),
) -> SubmissionRepository:
    return SubmissionRepository(db)


def get_submission_service(
    repo: SubmissionRepository = Depends(get_submission_repository),
) -> SubmissionService:
    return SubmissionService(repo)
