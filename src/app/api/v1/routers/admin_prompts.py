# src/app/api/v1/routers/admin_prompts.py
import uuid
from typing import List
from fastapi import APIRouter, Depends, HTTPException, Response, status
from app.api.v1 import models as api_models
from app.infrastructure.database import models as db_models
from app.infrastructure.auth.core import current_superuser
from app.core.services.admin_service import AdminService
from app.api.v1.dependencies import get_admin_service

prompt_router = APIRouter(prefix="/prompts", tags=["Admin: Prompt Templates"])


@prompt_router.post(
    "/",
    response_model=api_models.PromptTemplateRead,
    status_code=status.HTTP_201_CREATED,
)
async def create_prompt_template(
    template: api_models.PromptTemplateCreate,
    admin_service: AdminService = Depends(get_admin_service),
    user: db_models.User = Depends(current_superuser),
):
    """Creates a new prompt template."""
    return await admin_service.create_prompt_template(template)


@prompt_router.get("/", response_model=List[api_models.PromptTemplateRead])
async def read_prompt_templates(
    admin_service: AdminService = Depends(get_admin_service),
    user: db_models.User = Depends(current_superuser),
):
    """Retrieves all prompt templates."""
    return await admin_service.get_all_prompt_templates()


@prompt_router.get("/{template_id}", response_model=api_models.PromptTemplateRead)
async def read_prompt_template(
    template_id: uuid.UUID,
    admin_service: AdminService = Depends(get_admin_service),
    user: db_models.User = Depends(current_superuser),
):
    """Retrieves a single prompt template by its ID."""
    db_template = await admin_service.get_prompt_template_by_id(template_id)
    if not db_template:
        raise HTTPException(status_code=404, detail="Prompt template not found")
    return db_template


@prompt_router.patch("/{template_id}", response_model=api_models.PromptTemplateRead)
async def update_prompt_template(
    template_id: uuid.UUID,
    template_update: api_models.PromptTemplateUpdate,
    admin_service: AdminService = Depends(get_admin_service),
    user: db_models.User = Depends(current_superuser),
):
    """Updates an existing prompt template."""
    updated_template = await admin_service.update_prompt_template(
        template_id, template_update
    )
    if not updated_template:
        raise HTTPException(status_code=404, detail="Prompt template not found")
    return updated_template


@prompt_router.delete("/{template_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_prompt_template(
    template_id: uuid.UUID,
    admin_service: AdminService = Depends(get_admin_service),
    user: db_models.User = Depends(current_superuser),
):
    """Deletes a prompt template."""
    deleted = await admin_service.delete_prompt_template(template_id)
    if not deleted:
        raise HTTPException(status_code=404, detail="Prompt template not found")
    return Response(status_code=status.HTTP_204_NO_CONTENT)