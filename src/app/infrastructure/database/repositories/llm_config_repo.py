# src/app/infrastructure/database/repositories/llm_config_repo.py

import logging
import uuid
from typing import List, Optional
from fastapi import Depends
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from app.infrastructure.database.database import get_db, AsyncSessionLocal
from app.infrastructure.database import models as db_models
from app.api.v1 import models as api_models
from app.shared.lib.encryption import FernetEncrypt

logger = logging.getLogger(__name__)


class LLMConfigRepository:
    _instance = None

    def __init__(self, db_session: AsyncSession):
        self.db = db_session

    @classmethod
    def get_instance(cls, db_session: AsyncSession = Depends(AsyncSessionLocal)):
        if cls._instance is None:
            cls._instance = LLMConfigRepository(db_session)
        return cls._instance

    async def get_by_id(
        self, config_id: uuid.UUID
    ) -> Optional[db_models.LLMConfiguration]:
        """Retrieves a single LLM configuration by its UUID."""
        logger.debug("Fetching LLM config by ID.", extra={"config_id": str(config_id)})
        result = await self.db.execute(
            select(db_models.LLMConfiguration).filter(
                db_models.LLMConfiguration.id == config_id
            )
        )
        return result.scalars().first()

    async def get_by_id_with_decrypted_key(
        self, config_id: uuid.UUID
    ) -> Optional[db_models.LLMConfiguration]:
        """Retrieves a single LLM configuration and decrypts its API key."""
        logger.debug("Fetching LLM config by ID with decrypted key.", extra={"config_id": str(config_id)})
        config = await self.get_by_id(config_id)
        if config:
            # Use a try-except block for safer decryption
            try:
                setattr(
                    config,
                    "decrypted_api_key",
                    FernetEncrypt.decrypt(config.encrypted_api_key),
                )
            except Exception as e:
                logger.error(
                    "Failed to decrypt API key for LLM config.",
                    extra={"config_id": str(config_id), "error": str(e)}
                )
                # Set key to None or handle error as per security policy
                setattr(config, "decrypted_api_key", None)
        return config

    async def get_all(
        self, skip: int = 0, limit: int = 100
    ) -> List[db_models.LLMConfiguration]:
        """Retrieves all LLM configurations, with pagination."""
        logger.debug("Fetching all LLM configs from DB.", extra={"skip": skip, "limit": limit})
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
        """Creates a new LLM configuration in the database with an encrypted API key."""
        logger.info("Creating new LLM config in DB.", extra={"config_name": config.name})
        encrypted_key = FernetEncrypt.encrypt(config.api_key)
        db_config = db_models.LLMConfiguration(
            name=config.name,
            provider=config.provider,
            model_name=config.model_name,
            encrypted_api_key=encrypted_key,
            input_cost_per_million=config.input_cost_per_million,
            output_cost_per_million=config.output_cost_per_million,
        )
        self.db.add(db_config)
        await self.db.commit()
        await self.db.refresh(db_config)
        logger.info("Successfully created new LLM config in DB.", extra={"config_id": str(db_config.id)})
        return db_config

    async def update(
        self, config_id: uuid.UUID, config_update: api_models.LLMConfigurationUpdate
    ) -> Optional[db_models.LLMConfiguration]:
        """Updates an existing LLM configuration. Encrypts the API key if a new one is provided."""
        logger.info("Updating LLM config in DB.", extra={"config_id": str(config_id)})
        db_config = await self.get_by_id(config_id)
        if not db_config:
            logger.warning("LLM config not found for update.", extra={"config_id": str(config_id)})
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
        logger.info("Successfully updated LLM config in DB.", extra={"config_id": str(db_config.id)})
        return db_config

    async def delete(
        self, config_id: uuid.UUID
    ) -> Optional[db_models.LLMConfiguration]:
        """Deletes an LLM configuration from the database."""
        logger.info("Deleting LLM config from DB.", extra={"config_id": str(config_id)})
        config = await self.get_by_id(config_id)
        if config:
            await self.db.delete(config)
            await self.db.commit()
            logger.info("LLM config deleted successfully from DB.", extra={"config_id": str(config_id)})
        return config
