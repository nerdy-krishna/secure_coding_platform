from typing import List
import uuid
from fastapi import APIRouter, Depends, HTTPException, status
from app.api.v1 import models as api_models
from app.infrastructure.database import models as db_models
from app.infrastructure.database.repositories.llm_config_repo import LLMConfigRepository
from app.infrastructure.auth.core import current_active_user

router = APIRouter(
    prefix="/admin/llm-config",
    tags=["admin"],
    responses={404: {"description": "Not found"}},
)

async def get_admin_user(current_user: db_models.User = Depends(current_active_user)):
    if not current_user.is_superuser:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN, detail="Not enough privileges"
        )
    return current_user

@router.get("/", response_model=List[api_models.LLMConfigurationRead])
async def get_all_llm_configs(
    skip: int = 0,
    limit: int = 100,
    repo: LLMConfigRepository = Depends(LLMConfigRepository.get_instance),
    current_user: db_models.User = Depends(get_admin_user),
):
    """
    Get all LLM configurations.
    """
    return await repo.get_all(skip=skip, limit=limit)

@router.post("/", response_model=api_models.LLMConfigurationRead)
async def create_llm_config(
    config: api_models.LLMConfigurationCreate,
    repo: LLMConfigRepository = Depends(LLMConfigRepository.get_instance),
    current_user: db_models.User = Depends(get_admin_user),
):
    """
    Create a new LLM configuration.
    """
    return await repo.create(config)

@router.get("/{config_id}", response_model=api_models.LLMConfigurationRead)
async def get_llm_config(
    config_id: uuid.UUID,
    repo: LLMConfigRepository = Depends(LLMConfigRepository.get_instance),
    current_user: db_models.User = Depends(get_admin_user),
):
    """
    Get a specific LLM configuration.
    """
    config = await repo.get_by_id(config_id)
    if not config:
        raise HTTPException(status_code=404, detail="LLM Configuration not found")
    return config

@router.put("/{config_id}", response_model=api_models.LLMConfigurationRead)
async def update_llm_config(
    config_id: uuid.UUID,
    config: api_models.LLMConfigurationUpdate,
    repo: LLMConfigRepository = Depends(LLMConfigRepository.get_instance),
    current_user: db_models.User = Depends(get_admin_user),
):
    """
    Update an LLM configuration.
    """
    updated_config = await repo.update(config_id, config)
    if not updated_config:
        raise HTTPException(status_code=404, detail="LLM Configuration not found")
    return updated_config

@router.delete("/{config_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_llm_config(
    config_id: uuid.UUID,
    repo: LLMConfigRepository = Depends(LLMConfigRepository.get_instance),
    current_user: db_models.User = Depends(get_admin_user),
):
    """
    Delete an LLM configuration.
    """
    deleted_config = await repo.delete(config_id)
    if not deleted_config:
        raise HTTPException(status_code=404, detail="LLM Configuration not found")
    return None
