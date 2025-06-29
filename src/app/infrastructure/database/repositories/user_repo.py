# src/app/infrastructure/database/repositories/user_repo.py

import logging
from typing import Optional

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.infrastructure.database import models as db_models

logger = logging.getLogger(__name__)


class UserRepository:
    def __init__(self, db_session: AsyncSession):
        self.db = db_session

    async def get_by_email(self, email: str) -> Optional[db_models.User]:
        """Retrieves a user by their email address."""
        result = await self.db.execute(
            select(db_models.User).filter(db_models.User.email == email)
        )
        return result.scalars().first()
