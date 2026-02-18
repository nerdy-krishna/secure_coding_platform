# src/app/api/v1/routers/admin_frameworks.py
import logging
import uuid
from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, Response, status
from app.api.v1 import models as api_models
from app.infrastructure.database import models as db_models
from app.infrastructure.auth.core import current_superuser
from app.core.services.admin_service import AdminService
from app.api.v1.dependencies import get_admin_service
from app.infrastructure.rag.rag_client import get_rag_service, RAGService

logger = logging.getLogger(__name__)

framework_router = APIRouter(prefix="/frameworks", tags=["Admin: Frameworks"])


@framework_router.post(
    "/", response_model=api_models.FrameworkRead, status_code=status.HTTP_201_CREATED
)
async def create_framework(
    framework: api_models.FrameworkCreate,
    admin_service: AdminService = Depends(get_admin_service),
    user: db_models.User = Depends(current_superuser),
):
    """Creates a new security framework."""
    return await admin_service.create_framework(framework)


@framework_router.get("/", response_model=List[api_models.FrameworkRead])
async def read_frameworks(
    admin_service: AdminService = Depends(get_admin_service),
    user: db_models.User = Depends(current_superuser),
):
    """Retrieves all security frameworks."""
    return await admin_service.get_all_frameworks()


@framework_router.get("/{framework_id}", response_model=api_models.FrameworkRead)
async def read_framework(
    framework_id: uuid.UUID,
    admin_service: AdminService = Depends(get_admin_service),
    user: db_models.User = Depends(current_superuser),
):
    """Retrieves a single security framework by its ID."""
    db_framework = await admin_service.get_framework_by_id(framework_id)
    if not db_framework:
        raise HTTPException(status_code=404, detail="Framework not found")
    return db_framework


@framework_router.patch("/{framework_id}", response_model=api_models.FrameworkRead)
async def update_framework(
    framework_id: uuid.UUID,
    framework_update: api_models.FrameworkUpdate,
    admin_service: AdminService = Depends(get_admin_service),
    user: db_models.User = Depends(current_superuser),
):
    """Updates an existing security framework."""
    updated_framework = await admin_service.update_framework(
        framework_id, framework_update
    )
    if not updated_framework:
        raise HTTPException(status_code=404, detail="Framework not found")
    return updated_framework


@framework_router.delete("/{framework_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_framework(
    framework_id: uuid.UUID,
    admin_service: AdminService = Depends(get_admin_service),
    rag_service: Optional[RAGService] = Depends(get_rag_service),
    user: db_models.User = Depends(current_superuser),
):
    """Deletes a security framework and its associated ChromaDB documents."""
    # Look up the framework name before deleting, so we can clean up ChromaDB
    db_framework = await admin_service.get_framework_by_id(framework_id)
    if not db_framework:
        raise HTTPException(status_code=404, detail="Framework not found")

    framework_name = db_framework.name

    # Clean up ChromaDB documents associated with this framework
    if rag_service:
        try:
            deleted_count = rag_service.delete_by_framework(framework_name)
            logger.info(
                f"Deleted {deleted_count} ChromaDB documents for framework '{framework_name}'."
            )
        except Exception as e:
            logger.warning(
                f"Failed to delete ChromaDB documents for framework '{framework_name}': {e}"
            )

    # Delete the database record
    deleted = await admin_service.delete_framework(framework_id)
    if not deleted:
        raise HTTPException(status_code=404, detail="Framework not found")
    return Response(status_code=status.HTTP_204_NO_CONTENT)


@framework_router.post(
    "/{framework_id}/agents", response_model=api_models.FrameworkRead
)
async def update_framework_agent_mappings(
    framework_id: uuid.UUID,
    mapping_data: api_models.FrameworkAgentMappingUpdate,
    admin_service: AdminService = Depends(get_admin_service),
    user: db_models.User = Depends(current_superuser),
):
    """Sets the specialized agents that are associated with a security framework."""
    updated_framework = await admin_service.update_framework_agent_mappings(
        framework_id, mapping_data.agent_ids
    )
    if not updated_framework:
        raise HTTPException(
            status_code=404, detail="Framework not found or agent IDs are invalid"
        )
    return updated_framework
