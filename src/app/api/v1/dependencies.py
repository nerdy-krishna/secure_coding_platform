from fastapi import Depends
from sqlalchemy.ext.asyncio import AsyncSession
from app.infrastructure.database.database import get_db
from app.infrastructure.database.repositories.llm_config_repo import LLMConfigRepository
from app.infrastructure.database.repositories.scan_repo import ScanRepository
from app.infrastructure.database.repositories.framework_repo import FrameworkRepository
from app.infrastructure.database.repositories.agent_repo import AgentRepository
from app.infrastructure.database.repositories.prompt_template_repo import (
    PromptTemplateRepository,
)
from app.infrastructure.database.repositories.chat_repo import ChatRepository
from app.infrastructure.database.repositories.rag_job_repo import RAGJobRepository
from app.core.services.admin_service import AdminService
from app.core.services.scan_service import SubmissionService as ScanService
from app.core.services.chat_service import ChatService
from app.core.services.rag_preprocessor_service import RAGPreprocessorService


def get_llm_config_repository(
    db: AsyncSession = Depends(get_db),
) -> LLMConfigRepository:
    return LLMConfigRepository(db)

def get_framework_repository(
    db: AsyncSession = Depends(get_db),
) -> FrameworkRepository:
    return FrameworkRepository(db)

def get_agent_repository(
    db: AsyncSession = Depends(get_db),
) -> AgentRepository:
    return AgentRepository(db)

def get_prompt_template_repository(
    db: AsyncSession = Depends(get_db),
) -> PromptTemplateRepository:
    return PromptTemplateRepository(db)


def get_admin_service(
    llm_repo: LLMConfigRepository = Depends(get_llm_config_repository),
    framework_repo: FrameworkRepository = Depends(get_framework_repository),
    agent_repo: AgentRepository = Depends(get_agent_repository),
    prompt_template_repo: PromptTemplateRepository = Depends(
        get_prompt_template_repository
    ),
) -> AdminService:
    return AdminService(
        llm_repo=llm_repo,
        framework_repo=framework_repo,
        agent_repo=agent_repo,
        prompt_template_repo=prompt_template_repo,
    )

def get_chat_repository(db: AsyncSession = Depends(get_db)) -> ChatRepository:
    """Dependency provider for the ChatRepository."""
    return ChatRepository(db)


def get_chat_service(
    chat_repo: ChatRepository = Depends(get_chat_repository),
) -> ChatService:
    """Dependency provider for the ChatService."""
    return ChatService(chat_repo)

def get_rag_job_repository(
    db: AsyncSession = Depends(get_db),
) -> RAGJobRepository:
    """Dependency provider for the RAGJobRepository."""
    return RAGJobRepository(db)


def get_rag_preprocessor_service(
    job_repo: RAGJobRepository = Depends(get_rag_job_repository),
    llm_config_repo: LLMConfigRepository = Depends(get_llm_config_repository),
) -> RAGPreprocessorService:
    """Dependency provider for the RAGPreprocessorService."""
    return RAGPreprocessorService(job_repo=job_repo, llm_config_repo=llm_config_repo)


def get_scan_repository(
    db: AsyncSession = Depends(get_db),
) -> ScanRepository:
    return ScanRepository(db)

def get_scan_service(
    repo: ScanRepository = Depends(get_scan_repository),
) -> ScanService:
    return ScanService(repo)