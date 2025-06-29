# src/app/core/services/admin_service.py
import uuid
from typing import List, Optional
from app.infrastructure.database.repositories.llm_config_repo import LLMConfigRepository
from app.api.v1 import models as api_models


class AdminService:
    def __init__(self, llm_repo: LLMConfigRepository):
        self.llm_repo = llm_repo

    async def get_all_configs(self) -> List[api_models.LLMConfigurationRead]:
        configs_db = await self.llm_repo.get_all()
        return [api_models.LLMConfigurationRead.from_orm(c) for c in configs_db]

    async def create_config(
        self, config_create: api_models.LLMConfigurationCreate
    ) -> api_models.LLMConfigurationRead:
        config_db = await self.llm_repo.create(config_create)
        return api_models.LLMConfigurationRead.from_orm(config_db)

    async def update_config(
        self, config_id: uuid.UUID, config_update: api_models.LLMConfigurationUpdate
    ) -> Optional[api_models.LLMConfigurationRead]:
        updated_db = await self.llm_repo.update(config_id, config_update)
        if updated_db:
            return api_models.LLMConfigurationRead.from_orm(updated_db)
        return None

    async def delete_config(self, config_id: uuid.UUID) -> bool:
        deleted = await self.llm_repo.delete(config_id)
        return deleted is not None
