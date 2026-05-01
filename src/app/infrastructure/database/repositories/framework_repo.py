# src/app/infrastructure/database/repositories/framework_repo.py
import logging
import uuid
from typing import List, Optional

from sqlalchemy import select
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.api.v1 import models as api_models
from app.infrastructure.database import models as db_models

logger = logging.getLogger(__name__)

_ALLOWED_FIELDS = {"name", "description"}


def _validate(name: str, description: str) -> None:
    """Validate framework name and description lengths."""
    if not (1 <= len(name) <= 255):
        raise ValueError(
            f"Framework name must be between 1 and 255 characters, got {len(name)}."
        )
    if not (1 <= len(description) <= 4000):
        raise ValueError(
            f"Framework description must be between 1 and 4000 characters, got {len(description)}."
        )


class FrameworkRepository:
    """Handles all database operations related to Frameworks."""

    def __init__(self, db_session: AsyncSession):
        self.db = db_session

    async def create_framework(
        self, framework_data: api_models.FrameworkCreate
    ) -> db_models.Framework:
        """Creates a new Framework in the database."""
        raw = framework_data.model_dump()
        _validate(raw.get("name", ""), raw.get("description", ""))
        payload = {k: v for k, v in raw.items() if k in _ALLOWED_FIELDS}
        db_framework = db_models.Framework(**payload)
        self.db.add(db_framework)
        try:
            await self.db.commit()
        except SQLAlchemyError as e:
            logger.error(
                "framework.created.failed",
                extra={"framework_id": None, "error_class": e.__class__.__name__},
                exc_info=True,
            )
            raise
        await self.db.refresh(db_framework)
        logger.info(
            "framework.created",
            extra={
                "framework_id": str(db_framework.id),
                "framework_name": db_framework.name,
            },
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

        raw_update = framework_data.model_dump(exclude_unset=True)
        update_data = {k: v for k, v in raw_update.items() if k in _ALLOWED_FIELDS}
        new_name = update_data.get("name", db_framework.name)
        new_description = update_data.get("description", db_framework.description)
        _validate(new_name, new_description)
        for key, value in update_data.items():
            setattr(db_framework, key, value)

        try:
            await self.db.commit()
        except SQLAlchemyError as e:
            logger.error(
                "framework.updated.failed",
                extra={
                    "framework_id": str(framework_id),
                    "error_class": e.__class__.__name__,
                },
                exc_info=True,
            )
            raise
        await self.db.refresh(db_framework)
        logger.info("framework.updated", extra={"framework_id": str(framework_id)})
        return db_framework

    async def delete_framework(self, framework_id: uuid.UUID) -> bool:
        """Deletes a framework from the database."""
        db_framework = await self.get_framework_by_id(framework_id)
        if not db_framework:
            return False

        await self.db.delete(db_framework)
        try:
            await self.db.commit()
        except SQLAlchemyError as e:
            logger.error(
                "framework.deleted.failed",
                extra={
                    "framework_id": str(framework_id),
                    "error_class": e.__class__.__name__,
                },
                exc_info=True,
            )
            raise
        logger.info("framework.deleted", extra={"framework_id": str(framework_id)})
        return True

    async def update_agent_mappings_for_framework(
        self, framework_id: uuid.UUID, agent_ids: List[uuid.UUID]
    ) -> Optional[db_models.Framework]:
        """Sets the associated agents for a given framework."""
        db_framework = await self.get_framework_by_id(framework_id)
        if not db_framework:
            logger.warning(
                "framework.agent_mapping.framework_not_found",
                extra={"framework_id": str(framework_id)},
            )
            return None

        # Fetch the agent objects to be associated
        if agent_ids:
            stmt = select(db_models.Agent).where(db_models.Agent.id.in_(agent_ids))
            result = await self.db.execute(stmt)
            agents_to_map = list(result.scalars().all())

            if len(agents_to_map) != len(agent_ids):
                missing = set(str(a) for a in agent_ids) - {
                    str(a.id) for a in agents_to_map
                }
                raise ValueError(f"Invalid agent_ids: {missing}")
        else:
            agents_to_map = []

        # Update the relationship
        db_framework.agents = agents_to_map
        self.db.add(db_framework)
        try:
            await self.db.commit()
        except SQLAlchemyError as e:
            logger.error(
                "framework.agent_mapping.failed",
                extra={
                    "framework_id": str(framework_id),
                    "error_class": e.__class__.__name__,
                },
                exc_info=True,
            )
            raise
        await self.db.refresh(db_framework)
        logger.info(
            "framework.agent_mapping.updated",
            extra={
                "framework_id": str(framework_id),
                "agent_count": len(agents_to_map),
            },
        )
        return db_framework
