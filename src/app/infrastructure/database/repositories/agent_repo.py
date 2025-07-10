# src/app/infrastructure/database/repositories/agent_repo.py
import logging
import uuid
from typing import List, Optional

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.v1 import models as api_models
from app.infrastructure.database import models as db_models

logger = logging.getLogger(__name__)


class AgentRepository:
    """Handles all database operations related to Agents."""

    def __init__(self, db_session: AsyncSession):
        self.db = db_session

    async def create_agent(
        self, agent_data: api_models.AgentCreate
    ) -> db_models.Agent:
        """Creates a new Agent in the database."""
        db_agent = db_models.Agent(**agent_data.model_dump())
        self.db.add(db_agent)
        await self.db.commit()
        await self.db.refresh(db_agent)
        logger.info(f"Created agent '{db_agent.name}' with ID {db_agent.id}.")
        return db_agent

    async def get_agent_by_id(
        self, agent_id: uuid.UUID
    ) -> Optional[db_models.Agent]:
        """Retrieves a single agent by its UUID."""
        stmt = select(db_models.Agent).filter(db_models.Agent.id == agent_id)
        result = await self.db.execute(stmt)
        return result.scalars().first()

    async def get_all_agents(self) -> List[db_models.Agent]:
        """Retrieves all agents."""
        stmt = select(db_models.Agent).order_by(db_models.Agent.name)
        result = await self.db.execute(stmt)
        return list(result.scalars().all())

    async def update_agent(
        self, agent_id: uuid.UUID, agent_data: api_models.AgentUpdate
    ) -> Optional[db_models.Agent]:
        """Updates an existing agent."""
        db_agent = await self.get_agent_by_id(agent_id)
        if not db_agent:
            return None

        update_data = agent_data.model_dump(exclude_unset=True)
        for key, value in update_data.items():
            setattr(db_agent, key, value)

        await self.db.commit()
        await self.db.refresh(db_agent)
        logger.info(f"Updated agent with ID {agent_id}.")
        return db_agent

    async def delete_agent(self, agent_id: uuid.UUID) -> bool:
        """Deletes an agent from the database."""
        db_agent = await self.get_agent_by_id(agent_id)
        if not db_agent:
            return False

        await self.db.delete(db_agent)
        await self.db.commit()
        logger.info(f"Deleted agent with ID {agent_id}.")
        return True