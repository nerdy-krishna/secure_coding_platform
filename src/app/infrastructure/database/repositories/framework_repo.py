# src/app/infrastructure/database/repositories/framework_repo.py
import logging
import uuid
from typing import List, Optional

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.api.v1 import models as api_models
from app.infrastructure.database import models as db_models

logger = logging.getLogger(__name__)


class FrameworkRepository:
    """Handles all database operations related to Frameworks."""

    def __init__(self, db_session: AsyncSession):
        self.db = db_session

    async def create_framework(
        self, framework_data: api_models.FrameworkCreate
    ) -> db_models.Framework:
        """Creates a new Framework in the database."""
        db_framework = db_models.Framework(**framework_data.model_dump())
        self.db.add(db_framework)
        await self.db.commit()
        await self.db.refresh(db_framework)
        logger.info(
            f"Created framework '{db_framework.name}' with ID {db_framework.id}."
        )
        return db_framework

    async def get_framework_by_id(
        self, framework_id: uuid.UUID
    ) -> Optional[db_models.Framework]:
        """Retrieves a single framework by its UUID, including related agents."""
        stmt = (
            select(db_models.Framework)
            .options(selectinload(db_models.Framework.agents))
            .filter(db_models.Framework.id == framework_id)
        )
        result = await self.db.execute(stmt)
        return result.scalars().first()

    async def get_framework_by_name(self, name: str) -> Optional[db_models.Framework]:
        """Retrieves a single framework by its name."""
        stmt = (
            select(db_models.Framework)
            .options(selectinload(db_models.Framework.agents))
            .filter(db_models.Framework.name == name)
        )
        result = await self.db.execute(stmt)
        return result.scalars().first()

    async def get_all_frameworks(self) -> List[db_models.Framework]:
        """Retrieves all frameworks, including their related agents."""
        stmt = select(db_models.Framework).options(
            selectinload(db_models.Framework.agents)
        )
        result = await self.db.execute(stmt)
        return list(result.scalars().all())

    async def update_framework(
        self, framework_id: uuid.UUID, framework_data: api_models.FrameworkUpdate
    ) -> Optional[db_models.Framework]:
        """Updates an existing framework."""
        db_framework = await self.get_framework_by_id(framework_id)
        if not db_framework:
            return None

        update_data = framework_data.model_dump(exclude_unset=True)
        for key, value in update_data.items():
            setattr(db_framework, key, value)

        await self.db.commit()
        await self.db.refresh(db_framework)
        logger.info(f"Updated framework with ID {framework_id}.")
        return db_framework

    async def delete_framework(self, framework_id: uuid.UUID) -> bool:
        """Deletes a framework from the database."""
        db_framework = await self.get_framework_by_id(framework_id)
        if not db_framework:
            return False

        await self.db.delete(db_framework)
        await self.db.commit()
        logger.info(f"Deleted framework with ID {framework_id}.")
        return True

    async def update_agent_mappings_for_framework(
        self, framework_id: uuid.UUID, agent_ids: List[uuid.UUID]
    ) -> Optional[db_models.Framework]:
        """Sets the associated agents for a given framework."""
        db_framework = await self.get_framework_by_id(framework_id)
        if not db_framework:
            logger.warning(f"Framework not found during agent mapping: {framework_id}")
            return None

        # Fetch the agent objects to be associated
        if agent_ids:
            stmt = select(db_models.Agent).where(db_models.Agent.id.in_(agent_ids))
            result = await self.db.execute(stmt)
            agents_to_map = list(result.scalars().all())

            if len(agents_to_map) != len(agent_ids):
                logger.warning("Some agent IDs provided for mapping were not found.")
        else:
            agents_to_map = []

        # Update the relationship
        db_framework.agents = agents_to_map
        self.db.add(db_framework)
        await self.db.commit()
        await self.db.refresh(db_framework)
        logger.info(
            f"Updated agent mappings for framework {framework_id} with {len(agents_to_map)} agents."
        )
        return db_framework
