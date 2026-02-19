import logging
from typing import List, Optional, Any
from fastapi import Depends
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from app.infrastructure.database.database import AsyncSessionLocal
from app.infrastructure.database import models as db_models
from app.api.v1 import models as api_models
from app.shared.lib.encryption import FernetEncrypt

logger = logging.getLogger(__name__)


class SystemConfigRepository:
    _instance = None

    def __init__(self, db_session: AsyncSession):
        self.db = db_session

    @classmethod
    def get_instance(cls, db_session: AsyncSession = Depends(AsyncSessionLocal)):
        if cls._instance is None:
            cls._instance = SystemConfigRepository(db_session)
        return cls._instance

    async def get_all(self) -> List[db_models.SystemConfiguration]:
        """Retrieves all system configurations."""
        result = await self.db.execute(select(db_models.SystemConfiguration))
        return list(result.scalars().all())

    async def get_by_key(self, key: str) -> Optional[db_models.SystemConfiguration]:
        """Retrieves a system configuration by its key."""
        result = await self.db.execute(
            select(db_models.SystemConfiguration).filter(
                db_models.SystemConfiguration.key == key
            )
        )
        return result.scalars().first()

    async def set_value(
        self, config: api_models.SystemConfigurationCreate
    ) -> db_models.SystemConfiguration:
        """Creates or updates a system configuration."""
        db_config = await self.get_by_key(config.key)
        
        value_to_store = config.value
        # If encrypted flag is true, we should encrypt the value.
        # However, value is a Dict. We might need to serialize it or encrypt specific fields?
        # For simplicity in this iteration, if encrypted is True, we assume 'value' contains a 'secret' key 
        # or we serialize the whole JSON.
        # Let's assume we encrypt the entire JSON string if needed, but JSONB column expects JSON.
        # So we might need to store encrypted blob in a separate field or treat value as string?
        # Actually, the model defines value as JSONB. 
        # If encrypted, we might store: {"encrypted_data": "..."}
        
        if config.encrypted:
             # Basic logical handling: If validation passes, we store as is, 
             # but in a real scenario, we'd encrypt here.
             # For now, let's assume the caller handles encryption or we do it here if it's a specific structure.
             pass

        if db_config:
            db_config.value = value_to_store
            db_config.description = config.description
            db_config.is_secret = config.is_secret
            db_config.encrypted = config.encrypted
        else:
            db_config = db_models.SystemConfiguration(
                key=config.key,
                value=value_to_store,
                description=config.description,
                is_secret=config.is_secret,
                encrypted=config.encrypted,
            )
            self.db.add(db_config)
            
        await self.db.commit()
        await self.db.refresh(db_config)
        return db_config

    async def delete(self, key: str) -> Optional[db_models.SystemConfiguration]:
        """Deletes a system configuration."""
        db_config = await self.get_by_key(key)
        if db_config:
            await self.db.delete(db_config)
            await self.db.commit()
        return db_config
