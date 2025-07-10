# src/app/infrastructure/database/repositories/prompt_template_repo.py
import logging
import uuid
from typing import List, Optional

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.v1 import models as api_models
from app.infrastructure.database import models as db_models

logger = logging.getLogger(__name__)


class PromptTemplateRepository:
    """Handles all database operations related to PromptTemplates."""

    def __init__(self, db_session: AsyncSession):
        self.db = db_session

    async def create_template(
        self, template_data: api_models.PromptTemplateCreate
    ) -> db_models.PromptTemplate:
        """Creates a new PromptTemplate in the database."""
        db_template = db_models.PromptTemplate(**template_data.model_dump())
        self.db.add(db_template)
        await self.db.commit()
        await self.db.refresh(db_template)
        logger.info(f"Created prompt template '{db_template.name}' with ID {db_template.id}.")
        return db_template

    async def get_template_by_id(
        self, template_id: uuid.UUID
    ) -> Optional[db_models.PromptTemplate]:
        """Retrieves a single prompt template by its UUID."""
        stmt = select(db_models.PromptTemplate).filter(
            db_models.PromptTemplate.id == template_id
        )
        result = await self.db.execute(stmt)
        return result.scalars().first()

    async def get_template_by_name_and_type(
        self, name: str, template_type: str
    ) -> Optional[db_models.PromptTemplate]:
        """Retrieves a single prompt template by its unique name and type."""
        stmt = select(db_models.PromptTemplate).filter_by(
            name=name, template_type=template_type
        )
        result = await self.db.execute(stmt)
        return result.scalars().first()

    async def get_all_templates(self) -> List[db_models.PromptTemplate]:
        """Retrieves all prompt templates."""
        stmt = select(db_models.PromptTemplate).order_by(db_models.PromptTemplate.name)
        result = await self.db.execute(stmt)
        return list(result.scalars().all())

    async def update_template(
        self,
        template_id: uuid.UUID,
        template_data: api_models.PromptTemplateUpdate,
    ) -> Optional[db_models.PromptTemplate]:
        """Updates an existing prompt template."""
        db_template = await self.get_template_by_id(template_id)
        if not db_template:
            return None

        update_data = template_data.model_dump(exclude_unset=True)
        for key, value in update_data.items():
            setattr(db_template, key, value)

        await self.db.commit()
        await self.db.refresh(db_template)
        logger.info(f"Updated prompt template with ID {template_id}.")
        return db_template

    async def delete_template(self, template_id: uuid.UUID) -> bool:
        """Deletes a prompt template from the database."""
        db_template = await self.get_template_by_id(template_id)
        if not db_template:
            return False

        await self.db.delete(db_template)
        await self.db.commit()
        logger.info(f"Deleted prompt template with ID {template_id}.")
        return True