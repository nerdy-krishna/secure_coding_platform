from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from typing import Literal
import logging
from app.config.logging_config import update_logging_level
from app.config.config import settings
from app.infrastructure.auth.core import current_superuser
from app.infrastructure.database import models as db_models

from app.api.v1 import models as api_models
from app.infrastructure.database.repositories.system_config_repo import (
    SystemConfigRepository,
)
from app.infrastructure.database.database import get_db
from sqlalchemy.ext.asyncio import AsyncSession

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/logs", tags=["Admin: Logs"])


class LogLevelUpdate(BaseModel):
    level: Literal["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"] = Field(
        ..., description="The new log level to set."
    )


class LogLevelResponse(BaseModel):
    level: str
    message: str


@router.get("/level", response_model=LogLevelResponse)
async def get_log_level(
    user: db_models.User = Depends(current_superuser),
):
    """
    Get the current log level of the application.
    """
    # Get the effective level of the root logger
    level_int = logging.getLogger().getEffectiveLevel()
    level_name = logging.getLevelName(level_int)
    logger.info("admin.log_level.read", extra={"actor_id": str(user.id)})
    return {"level": level_name, "message": f"Current log level is {level_name}"}


@router.put("/level", response_model=LogLevelResponse)
async def set_log_level(
    update: LogLevelUpdate,
    user: db_models.User = Depends(current_superuser),
    db: AsyncSession = Depends(get_db),
):
    """
    Update the log level dynamically and persist it.

    DANGEROUS FUNCTIONALITY (V15.1.5): setting level=DEBUG enables verbose log output
    across the entire process tree. Sensitive fields (request bodies, downstream API
    payloads) may be captured to disk via app_debug.log and forwarded via
    Fluentd-to-Loki. Use only when actively debugging; restore to INFO/WARNING when
    done. The Langfuse mask.py only redacts secrets on the trace path, not on
    application logs.

    When level=DEBUG, callers MUST ensure the log redaction filter
    (see app.infrastructure.observability.mask) is attached to the active handler,
    and the log file rotation policy (app.config.logging_config) MUST cap retention
    at 24 hours. Failing either condition violates the documented V14.1.2 requirement.

    # NOTE (V15.4.1): only updates *this* worker's runtime logger; other uvicorn
    # workers continue at their previous level until next process restart, when they
    # read system.log_level from the DB. For cluster-wide live updates, switch to a
    # pub/sub channel (e.g. RabbitMQ fanout) that every worker subscribes to in
    # app.config.logging_config.

    REQUIRES SUPERUSER PRIVILEGES.
    """
    # Production guard: DEBUG level is not permitted in production (V13.4.2)
    if (
        getattr(settings, "ENVIRONMENT", None) == "production"
        and update.level == "DEBUG"
    ):
        raise HTTPException(
            status_code=400,
            detail="DEBUG log level is disabled in production environments.",
        )

    # Warn before enabling verbose output so SIEM can alert on level drops (V14.1.1)
    if update.level == "DEBUG":
        logger.warning(
            "LOG_LEVEL_DEBUG_ENABLED by user_id=%s — verbose logging enabled",
            user.id,
        )

    try:
        # 1. Update Runtime
        update_logging_level(update.level)

        # 2. Persist to DB
        repo = SystemConfigRepository(db)
        config_create = api_models.SystemConfigurationCreate(
            key="system.log_level",
            value={"level": update.level},
            description="System Log Level",
            is_secret=False,
            encrypted=False,
        )
        await repo.set_value(config_create)

        # Audit log: record granted authz decision and level change (V16.2.1, V16.3.2, V16.3.3)
        logger.warning(
            "admin.log_level.changed",
            extra={"actor_id": str(user.id), "new_level": update.level},
        )

        return {
            "level": update.level,
            "message": f"Log level successfully updated to {update.level} and saved to configuration.",
        }
    except ValueError:
        logger.warning("Invalid log level requested", exc_info=True)
        raise HTTPException(status_code=400, detail="Invalid log level.")
    except Exception:
        logger.exception(
            "admin.log_level.update_failed",
            extra={"actor_id": str(user.id), "requested_level": update.level},
        )
        raise HTTPException(status_code=500, detail="Failed to update log level.")
