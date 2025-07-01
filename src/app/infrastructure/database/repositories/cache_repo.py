# src/app/infrastructure/database/repositories/cache_repo.py

import logging
from typing import Optional
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from app.infrastructure.database import models as db_models
from app.shared.analysis_tools.repository_map import RepositoryMap

logger = logging.getLogger(__name__)

class CacheRepository:
    def __init__(self, db_session: AsyncSession):
        self.db = db_session

    async def get_repository_map(self, codebase_hash: str) -> Optional[RepositoryMap]:
        """
        Retrieves a cached RepositoryMap by the codebase hash.
        """
        result = await self.db.execute(
            select(db_models.RepositoryMapCache).filter(
                db_models.RepositoryMapCache.codebase_hash == codebase_hash
            )
        )
        cache_entry = result.scalars().first()
        if cache_entry:
            return RepositoryMap.model_validate(cache_entry.repository_map)
        return None

    async def create_repository_map(
        self, codebase_hash: str, repository_map: RepositoryMap
    ) -> db_models.RepositoryMapCache:
        """
        Saves a new RepositoryMap to the cache.
        """
        db_cache_entry = db_models.RepositoryMapCache(
            codebase_hash=codebase_hash,
            repository_map=repository_map.model_dump()
        )
        self.db.add(db_cache_entry)
        await self.db.commit()
        await self.db.refresh(db_cache_entry)
        return db_cache_entry