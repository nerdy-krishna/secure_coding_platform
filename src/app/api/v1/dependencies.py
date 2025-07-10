from fastapi import Depends
from sqlalchemy.ext.asyncio import AsyncSession
from app.infrastructure.database.database import get_db
from app.infrastructure.database.repositories.llm_config_repo import LLMConfigRepository
from app.infrastructure.database.repositories.scan_repo import ScanRepository
from app.core.services.admin_service import AdminService
from app.core.services.scan_service import SubmissionService as ScanService

def get_llm_config_repository(
    db: AsyncSession = Depends(get_db),
) -> LLMConfigRepository:
    return LLMConfigRepository(db)

def get_admin_service(
    repo: LLMConfigRepository = Depends(get_llm_config_repository),
) -> AdminService:
    return AdminService(repo)

def get_scan_repository(
    db: AsyncSession = Depends(get_db),
) -> ScanRepository:
    return ScanRepository(db)

def get_scan_service(
    repo: ScanRepository = Depends(get_scan_repository),
) -> ScanService:
    return ScanService(repo)