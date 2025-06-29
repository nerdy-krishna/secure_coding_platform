# src/app/api/v1/routers/admin.py
import uuid
from typing import List
from fastapi import APIRouter, Depends, HTTPException, Response
from app.api.v1 import models as api_models
from app.infrastructure.database import models as db_models
from app.infrastructure.auth.core import current_active_user, current_superuser
from app.core.services.admin_service import AdminService
from app.api.v1.dependencies import get_admin_service

llm_router = APIRouter(prefix="/llm-configs", tags=["Admin: LLM Configurations"])


@llm_router.post("/", response_model=api_models.LLMConfigurationRead, status_code=201)
async def create_llm_configuration(
    config: api_models.LLMConfigurationCreate,
    admin_service: AdminService = Depends(get_admin_service),
    user: db_models.User = Depends(current_superuser),
):
    return await admin_service.create_config(config)


@llm_router.get("/", response_model=List[api_models.LLMConfigurationRead])
async def read_llm_configurations(
    admin_service: AdminService = Depends(get_admin_service),
    user: db_models.User = Depends(current_active_user),
):
    return await admin_service.get_all_configs()


@llm_router.patch("/{config_id}", response_model=api_models.LLMConfigurationRead)
async def update_llm_configuration(
    config_id: uuid.UUID,
    config_update: api_models.LLMConfigurationUpdate,
    admin_service: AdminService = Depends(get_admin_service),
    user: db_models.User = Depends(current_superuser),
):
    updated_config = await admin_service.update_config(config_id, config_update)
    if updated_config is None:
        raise HTTPException(status_code=404, detail="LLM Configuration not found")
    return updated_config


@llm_router.delete("/{config_id}", status_code=204)
async def delete_llm_configuration(
    config_id: uuid.UUID,
    admin_service: AdminService = Depends(get_admin_service),
    user: db_models.User = Depends(current_superuser),
):
    deleted = await admin_service.delete_config(config_id)
    if not deleted:
        raise HTTPException(status_code=404, detail="LLM Configuration not found")
    return Response(status_code=204)
