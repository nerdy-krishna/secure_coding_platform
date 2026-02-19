from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from typing import Literal
import logging
from app.config.logging_config import update_logging_level
from app.infrastructure.auth.core import current_superuser
from app.infrastructure.database import models as db_models

from app.api.v1 import models as api_models
from app.infrastructure.database.repositories.system_config_repo import SystemConfigRepository
from app.infrastructure.database.database import get_db
from sqlalchemy.ext.asyncio import AsyncSession

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
    return {"level": level_name, "message": f"Current log level is {level_name}"}


@router.put("/level", response_model=LogLevelResponse)
async def set_log_level(
    update: LogLevelUpdate,
    user: db_models.User = Depends(current_superuser),
    db: AsyncSession = Depends(get_db),
):
    """
    Update the log level of the application dynamically and persist it.
    REQUIRES SUPERUSER PRIVILEGES.
    """
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
            encrypted=False
        )
        await repo.set_value(config_create)

        return {
            "level": update.level,
            "message": f"Log level successfully updated to {update.level} and saved to configuration.",
        }
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        raise HTTPException(
            status_code=500, detail=f"Failed to update log level: {str(e)}"
        )
