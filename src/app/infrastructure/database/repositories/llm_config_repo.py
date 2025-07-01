# src/app/infrastructure/database/repositories/llm_config_repo.py

import logging
import uuid
from typing import List, Optional
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from app.infrastructure.database import models as db_models
from app.api.v1 import models as api_models
from app.shared.lib.encryption import FernetEncrypt

logger = logging.getLogger(__name__)


class LLMConfigRepository:
    def __init__(self, db_session: AsyncSession):
        self.db = db_session

    async def get_by_id(
        self, config_id: uuid.UUID
    ) -> Optional[db_models.LLMConfiguration]:
        result = await self.db.execute(
            select(db_models.LLMConfiguration).filter(
                db_models.LLMConfiguration.id == config_id
            )
        )
        return result.scalars().first()

    async def get_by_id_with_decrypted_key(
        self, config_id: uuid.UUID
    ) -> Optional[db_models.LLMConfiguration]:
        config = await self.get_by_id(config_id)
        if config:
            setattr(
                config,
                "decrypted_api_key",
                FernetEncrypt.decrypt(config.encrypted_api_key),
            )
        return config

    async def get_all(
        self, skip: int = 0, limit: int = 100
    ) -> List[db_models.LLMConfiguration]:
        result = await self.db.execute(
            select(db_models.LLMConfiguration)
            .order_by(db_models.LLMConfiguration.name)
            .offset(skip)
            .limit(limit)
        )
        return list(result.scalars().all())

    async def create(
        self, config: api_models.LLMConfigurationCreate
    ) -> db_models.LLMConfiguration:
        encrypted_key = FernetEncrypt.encrypt(config.api_key)
        db_config = db_models.LLMConfiguration(
            name=config.name,
            provider=config.provider,
            model_name=config.model_name,
            encrypted_api_key=encrypted_key,
            tokenizer_encoding=config.tokenizer_encoding,
            input_cost_per_million=config.input_cost_per_million,
            output_cost_per_million=config.output_cost_per_million,
        )
        self.db.add(db_config)
        await self.db.commit()
        await self.db.refresh(db_config)
        return db_config

    async def update(
        self, config_id: uuid.UUID, config_update: api_models.LLMConfigurationUpdate
    ) -> Optional[db_models.LLMConfiguration]:
        db_config = await self.get_by_id(config_id)
        if not db_config:
            return None
        update_data = config_update.model_dump(exclude_unset=True)
        for key, value in update_data.items():
            if key == "api_key":
                if value:
                    db_config.encrypted_api_key = FernetEncrypt.encrypt(value)
            elif hasattr(db_config, key):
                setattr(db_config, key, value)
        await self.db.commit()
        await self.db.refresh(db_config)
        return db_config

    async def delete(
        self, config_id: uuid.UUID
    ) -> Optional[db_models.LLMConfiguration]:
        config = await self.get_by_id(config_id)
        if config:
            await self.db.delete(config)
            await self.db.commit()
        return config
