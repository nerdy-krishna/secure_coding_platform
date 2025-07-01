# src/app/core/services/admin_service.py
import uuid
from typing import List, Optional
from app.infrastructure.database.repositories.llm_config_repo import LLMConfigRepository
from app.api.v1 import models as api_models

logger = logging.getLogger(__name__)

class AdminService:
    def __init__(self, llm_repo: LLMConfigRepository):
        self.llm_repo = llm_repo

    async def get_all_configs(self) -> List[api_models.LLMConfigurationRead]:
        """Fetches all LLM configurations from the database."""
        logger.info("Fetching all LLM configurations.")
        configs_db = await self.llm_repo.get_all()
        return [api_models.LLMConfigurationRead.from_orm(c) for c in configs_db]

    async def create_config(
        self, config_create: api_models.LLMConfigurationCreate
    ) -> api_models.LLMConfigurationRead:
        """Creates a new LLM configuration."""
        logger.info(
            "Creating new LLM configuration.",
            extra={"name": config_create.name, "provider": config_create.provider},
        )
        config_db = await self.llm_repo.create(config_create)
        return api_models.LLMConfigurationRead.from_orm(config_db)

    async def update_config(
        self, config_id: uuid.UUID, config_update: api_models.LLMConfigurationUpdate
    ) -> Optional[api_models.LLMConfigurationRead]:
        """Updates an existing LLM configuration."""
        logger.info("Updating LLM configuration.", extra={"config_id": str(config_id)})
        updated_db = await self.llm_repo.update(config_id, config_update)
        if updated_db:
            return api_models.LLMConfigurationRead.from_orm(updated_db)
        logger.warning(
            "LLM configuration not found for update.",
            extra={"config_id": str(config_id)},
        )
        return None

    async def delete_config(self, config_id: uuid.UUID) -> bool:
        """Deletes an LLM configuration."""
        logger.info("Deleting LLM configuration.", extra={"config_id": str(config_id)})
        deleted = await self.llm_repo.delete(config_id)
        return deleted is not None

