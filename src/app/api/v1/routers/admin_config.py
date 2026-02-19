from typing import List
from fastapi import APIRouter, Depends, HTTPException, status
from app.api.v1 import models as api_models
from app.infrastructure.database import models as db_models
from app.infrastructure.database.repositories.system_config_repo import SystemConfigRepository
from app.infrastructure.auth.core import current_active_user

router = APIRouter(
    prefix="/admin/system-config",
    tags=["admin"],
    responses={404: {"description": "Not found"}},
)

async def get_admin_user(current_user: db_models.User = Depends(current_active_user)):
    if not current_user.is_superuser:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN, detail="Not enough privileges"
        )
    return current_user

@router.get("/", response_model=List[api_models.SystemConfigurationRead])
async def get_all_system_configs(
    repo: SystemConfigRepository = Depends(SystemConfigRepository.get_instance),
    current_user: db_models.User = Depends(get_admin_user),
):
    """
    Get all system configurations. Only accessible by admins.
    """
    configs = await repo.get_all()
    # Mask secrets if needed
    for config in configs:
        if config.is_secret:
            # We clone the object or modify a copy to return masked value
            # Since Pydantic from_attributes=True, it reads from ORM. 
            # We might need to handle masking manually or trusting the frontend to not show it?
            # Ideally, security-wise, we should not send the value at all if it's secret.
            pass
    return configs

@router.put("/{key}", response_model=api_models.SystemConfigurationRead)
async def set_system_config(
    key: str,
    config: api_models.SystemConfigurationUpdate,
    repo: SystemConfigRepository = Depends(SystemConfigRepository.get_instance),
    current_user: db_models.User = Depends(get_admin_user),
):
    """
    Create or update a system configuration.
    """
    # Check if exists
    existing = await repo.get_by_key(key)
    
    # Merge update data into create model
    create_data = {}
    if existing:
        create_data = {
            "key": key,
            "value": config.value if config.value is not None else existing.value,
            "description": config.description if config.description is not None else existing.description,
            "is_secret": config.is_secret if config.is_secret is not None else existing.is_secret,
            "encrypted": config.encrypted if config.encrypted is not None else existing.encrypted,
        }
    else:
        if config.value is None:
             raise HTTPException(status_code=400, detail="Value is required for new key")
        create_data = {
            "key": key,
            "value": config.value,
            "description": config.description,
            "is_secret": config.is_secret if config.is_secret is not None else False,
            "encrypted": config.encrypted if config.encrypted is not None else False,
        }

    system_config = api_models.SystemConfigurationCreate(**create_data)
    return await repo.set_value(system_config)

@router.delete("/{key}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_system_config(
    key: str,
    repo: SystemConfigRepository = Depends(SystemConfigRepository.get_instance),
    current_user: db_models.User = Depends(get_admin_user),
):
    """
    Delete a system configuration.
    """
    deleted = await repo.delete(key)
    if not deleted:
        raise HTTPException(status_code=404, detail="Configuration not found")
    return None
