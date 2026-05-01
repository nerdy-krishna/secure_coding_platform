# src/app/infrastructure/database/repositories/prompt_template_repo.py
import logging
import uuid
from typing import List, Optional

from sqlalchemy import select
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.v1 import models as api_models
from app.infrastructure.database import models as db_models

logger = logging.getLogger(__name__)

# Allow-lists for template_type and variant (V02.2.1)
_ALLOWED_TYPES = {"QUICK_AUDIT", "DETAILED_REMEDIATION", "CHAT"}
_ALLOWED_VARIANTS = {"generic", "anthropic"}

# Field allow-lists for mass-assignment protection (V15.3.3)
_CREATE_FIELDS = {
    "name",
    "template_type",
    "agent_name",
    "variant",
    "template_text",
    "version",
}
_UPDATE_FIELDS = {"name", "template_text"}

# Maximum allowed template_text length (V02.2.1)
_MAX_TEMPLATE_TEXT_LEN = 200_000


class PromptTemplateRepository:
    """Handles all database operations related to PromptTemplates."""

    def __init__(self, db_session: AsyncSession):
        self.db = db_session

    async def create_template(
        self, template_data: api_models.PromptTemplateCreate
    ) -> db_models.PromptTemplate:
        """Creates a new PromptTemplate in the database."""
        raw = template_data.model_dump()

        # V02.2.1: validate allow-lists and length before touching the DB
        if raw.get("template_type") not in _ALLOWED_TYPES:
            raise ValueError(
                f"template_type must be one of {_ALLOWED_TYPES}; "
                f"got {raw.get('template_type')!r}"
            )
        if (
            raw.get("variant") is not None
            and raw.get("variant") not in _ALLOWED_VARIANTS
        ):
            raise ValueError(
                f"variant must be one of {_ALLOWED_VARIANTS}; got {raw.get('variant')!r}"
            )
        if len(raw.get("template_text", "")) > _MAX_TEMPLATE_TEXT_LEN:
            raise ValueError(
                f"template_text exceeds maximum allowed length of {_MAX_TEMPLATE_TEXT_LEN}"
            )

        # V15.3.3: only pass allow-listed fields to the ORM constructor
        payload = {k: v for k, v in raw.items() if k in _CREATE_FIELDS}
        db_template = db_models.PromptTemplate(**payload)
        self.db.add(db_template)

        # V16.3.4: wrap commit so DB errors are logged and re-raised
        try:
            await self.db.commit()
        except SQLAlchemyError:
            logger.error(
                "prompt_template.create.failed",
                extra={"template_name": raw.get("name")},
                exc_info=True,
            )
            raise

        await self.db.refresh(db_template)

        # V16.4.1 / V16.2.1: structured log — no f-string interpolation of user data
        logger.info(
            "prompt_template.created",
            extra={
                "template_id": str(db_template.id),
                "template_name": db_template.name,
            },
        )
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
        self,
        agent_name: str,
        template_type: str,
        variant: Optional[str] = None,
    ) -> Optional[db_models.PromptTemplate]:
        """Retrieves a single prompt template.

        If `variant` is provided, tries that variant first; if no row exists
        for that variant, falls back to variant="generic". This lets an admin
        ship a partial set of Anthropic-optimized prompts without blocking
        agents whose tuned variant hasn't been authored yet.
        """
        # V02.2.3: reject obviously invalid inputs early
        if (
            not (1 <= len(agent_name) <= 100)
            or template_type not in _ALLOWED_TYPES
            or (variant is not None and variant not in _ALLOWED_VARIANTS)
        ):
            return None

        if variant:
            stmt = select(db_models.PromptTemplate).filter_by(
                agent_name=agent_name,
                template_type=template_type,
                variant=variant,
            )
            result = await self.db.execute(stmt)
            row = result.scalars().first()
            if row:
                return row
            if variant != "generic":
                logger.debug(
                    "prompt_template.variant_fallback",
                    extra={
                        "variant": variant,
                        "agent_name": agent_name,
                        "template_type": template_type,
                    },
                )

        stmt = select(db_models.PromptTemplate).filter_by(
            agent_name=agent_name,
            template_type=template_type,
            variant="generic",
        )
        result = await self.db.execute(stmt)
        row = result.scalars().first()
        if row:
            return row

        # Legacy fallback: rows from before the variant column existed may
        # (in theory) have been backfilled to 'generic', so this is defensive.
        stmt = select(db_models.PromptTemplate).filter_by(
            agent_name=agent_name, template_type=template_type
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
            # V16.3.2: log missing target before returning
            logger.warning(
                "prompt_template.update.target_missing",
                extra={"template_id": str(template_id)},
            )
            return None

        raw_update = template_data.model_dump(exclude_unset=True)

        # V02.2.1: validate allow-lists and length for any supplied fields
        if (
            "template_type" in raw_update
            and raw_update["template_type"] not in _ALLOWED_TYPES
        ):
            raise ValueError(
                f"template_type must be one of {_ALLOWED_TYPES}; "
                f"got {raw_update['template_type']!r}"
            )
        if "variant" in raw_update and raw_update["variant"] not in _ALLOWED_VARIANTS:
            raise ValueError(
                f"variant must be one of {_ALLOWED_VARIANTS}; got {raw_update['variant']!r}"
            )
        if (
            "template_text" in raw_update
            and len(raw_update["template_text"]) > _MAX_TEMPLATE_TEXT_LEN
        ):
            raise ValueError(
                f"template_text exceeds maximum allowed length of {_MAX_TEMPLATE_TEXT_LEN}"
            )

        # V15.3.3: only allow-listed fields may be updated (identity-key columns are excluded)
        update_data = {k: v for k, v in raw_update.items() if k in _UPDATE_FIELDS}
        for key, value in update_data.items():
            setattr(db_template, key, value)

        # V02.3.4: bump version for optimistic-lock concurrency control
        prev_version = db_template.version
        db_template.version = prev_version + 1

        # V16.3.4: wrap commit so DB errors (including stale-lock conflicts) are logged
        try:
            await self.db.commit()
        except SQLAlchemyError:
            logger.error(
                "prompt_template.update.failed",
                extra={"template_id": str(template_id)},
                exc_info=True,
            )
            raise

        await self.db.refresh(db_template)

        # V16.4.1 / V16.2.1: structured log — no f-string interpolation
        logger.info(
            "prompt_template.updated",
            extra={"template_id": str(template_id)},
        )
        return db_template

    async def delete_template(self, template_id: uuid.UUID) -> bool:
        """Deletes a prompt template from the database."""
        db_template = await self.get_template_by_id(template_id)
        if not db_template:
            # V16.3.2: log missing target before returning
            logger.warning(
                "prompt_template.delete.target_missing",
                extra={"template_id": str(template_id)},
            )
            return False

        await self.db.delete(db_template)

        # V16.3.4: wrap commit so DB errors are logged and re-raised
        try:
            await self.db.commit()
        except SQLAlchemyError:
            logger.error(
                "prompt_template.delete.failed",
                extra={"template_id": str(template_id)},
                exc_info=True,
            )
            raise

        # V16.4.1 / V16.2.1: structured log — no f-string interpolation
        logger.info(
            "prompt_template.deleted",
            extra={"template_id": str(template_id)},
        )
        return True
