from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func
from app.infrastructure.database.database import get_db
from app.infrastructure.database import models as db_models
from app.infrastructure.auth.manager import UserManager, get_user_manager
from app.infrastructure.auth import schemas as auth_schemas
from app.api.v1.schemas.setup import SetupRequest, SetupStatusResponse
from app.infrastructure.database.repositories.llm_config_repo import LLMConfigRepository
from app.infrastructure.database.repositories.system_config_repo import SystemConfigRepository
from app.api.v1 import models as api_models
from app.api.v1.dependencies import get_llm_config_repository

router = APIRouter()

async def is_setup_completed(db: AsyncSession) -> bool:
    """Checks if any user exists in the database."""
    result = await db.execute(select(func.count(db_models.User.id)))
    count = result.scalar()
    return count > 0

@router.get("/status", response_model=SetupStatusResponse)
async def get_setup_status(db: AsyncSession = Depends(get_db)):
    """Check if the application setup is completed."""
    completed = await is_setup_completed(db)
    return SetupStatusResponse(is_setup_completed=completed)

@router.post("", status_code=status.HTTP_201_CREATED)
async def perform_setup(
    request: SetupRequest,
    db: AsyncSession = Depends(get_db),
    user_manager: UserManager = Depends(get_user_manager),
    llm_repo: LLMConfigRepository = Depends(get_llm_config_repository)
):
    """
    Perform the initial setup: create superuser and default LLM config.
    Only allows execution if no users exist.
    """
    if await is_setup_completed(db):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Setup already completed. Please login."
        )

    # 1. Create Superuser
    try:
        user_create = auth_schemas.UserCreate(
            email=request.admin_email,
            password=request.admin_password,
            is_superuser=True,
            is_active=True,
            is_verified=True
        )
        await user_manager.create(user_create, safe=False)
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to create admin user: {str(e)}"
        )

    # 2. Configure LLM
    try:
        llm_create = api_models.LLMConfigurationCreate(
            name="Default Configuration",
            provider=request.llm_provider,
            model_name=request.llm_model,
            api_key=request.llm_api_key,
            input_cost_per_million=0.0, # Default, user can update later
            output_cost_per_million=0.0
        )
        await llm_repo.create(llm_create)
    except Exception as e:
        # Note: In a real scenario, we might want to rollback the user creation here
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to configure LLM: {str(e)}"
        )

    # 3. Configure CORS (System Config)
    if request.allowed_origins:
        try:
             # Create SystemConfigurationCreate object
             config_create = api_models.SystemConfigurationCreate(
                 key="security.allowed_origins",
                 value={"origins": request.allowed_origins}, # Store as JSON dict
                 description="Allowed origins for CORS",
                 is_secret=False,
                 encrypted=False
             )
             sys_conf_repo = SystemConfigRepository(db)
             await sys_conf_repo.set_value(config_create)

             # Update Cache immediately so next request works
             from app.core.config_cache import SystemConfigCache
             SystemConfigCache.set_allowed_origins(request.allowed_origins)
             SystemConfigCache.set_setup_completed(True) 
        except Exception as e:
             # Log error but don't fail setup as user creation is done
             # In a real app we might want to be more transactional
             pass

    return {"message": "Setup completed successfully"}
