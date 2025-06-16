# src/app/api/endpoints.py

import logging
import uuid
from typing import List, Optional, Annotated

from fastapi import (
    APIRouter,
    Depends,
    HTTPException,
    UploadFile,
    File,
    Form,
    Response,
)
from sqlalchemy.ext.asyncio import AsyncSession

from app.db import crud
from app.db.database import get_db
from app.db import models as db_models
from app.api import models as api_models
from app.auth.core import current_active_user, current_superuser
from app.utils import rabbitmq_utils

# Create two routers: one for general endpoints, one for admin-level LLM configs
router = APIRouter()
llm_router = APIRouter(prefix="/llm-configs", tags=["LLM Configurations"])

logger = logging.getLogger(__name__)

# === LLM Configuration Endpoints ===


@llm_router.post("/", response_model=api_models.LLMConfigurationRead, status_code=201)
async def create_llm_configuration(
    config: api_models.LLMConfigurationCreate,
    db: AsyncSession = Depends(get_db),
    # CORRECTED DEPENDENCY
    user: db_models.User = Depends(current_superuser),
):
    """
    Creates a new LLM configuration. Requires superuser privileges.
    """
    return await crud.create_llm_config(db=db, config=config)


@llm_router.get("/", response_model=List[api_models.LLMConfigurationRead])
async def read_llm_configurations(
    db: AsyncSession = Depends(get_db),
    # CORRECTED DEPENDENCY
    user: db_models.User = Depends(current_active_user),
):
    """
    Retrieves all LLM configurations. API keys are not included.
    """
    configs = await crud.get_llm_configs(db)
    return configs


@llm_router.delete("/{config_id}", status_code=204)
async def delete_llm_configuration(
    config_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    # CORRECTED DEPENDENCY
    user: db_models.User = Depends(current_superuser),
):
    """
    Deletes an LLM configuration by its ID. Requires superuser privileges.
    """
    config = await crud.delete_llm_config(db=db, config_id=config_id)
    if config is None:
        raise HTTPException(status_code=404, detail="LLM Configuration not found")
    return Response(status_code=204)


# === Submission & Results Endpoints ===


@router.post("/submit", response_model=api_models.SubmissionResponse)
async def submit_code(
    db: Annotated[AsyncSession, Depends(get_db)],
    current_user: Annotated[db_models.User, Depends(current_active_user)],
    main_llm_config_id: Annotated[uuid.UUID, Form(...)],
    specialized_llm_config_id: Annotated[uuid.UUID, Form(...)],
    frameworks: Annotated[str, Form(...)],
    files: Optional[List[UploadFile]] = File(None),
    repo_url: Optional[str] = Form(None),
):
    """
    Accepts code submission via file upload or Git repository URL.
    """
    if not files and not repo_url:
        raise HTTPException(
            status_code=400,
            detail="Either files must be uploaded or a git repository URL must be provided.",
        )

    main_llm = await crud.get_llm_config(db, main_llm_config_id)
    specialized_llm = await crud.get_llm_config(db, specialized_llm_config_id)
    if not main_llm or not specialized_llm:
        raise HTTPException(
            status_code=404,
            detail="One or both selected LLM configurations could not be found.",
        )

    framework_list = [f.strip() for f in frameworks.split(",")]

    files_data = []
    if files:
        for file in files:
            content = await file.read()
            files_data.append(
                {
                    "path": file.filename,
                    "content": content.decode("utf-8"),
                    "language": "python",
                }
            )

    submission = await crud.create_submission(
        db=db,
        user_id=current_user.id,
        repo_url=repo_url,
        files=files_data,
        frameworks=framework_list,
        main_llm_config_id=main_llm_config_id,
        specialized_llm_config_id=specialized_llm_config_id,
    )

    rabbitmq_utils.publish_submission(str(submission.id))
    logger.info(f"Published submission {submission.id} to RabbitMQ.")

    return {
        "submission_id": submission.id,
        "message": "Submission received and queued for analysis.",
    }


@router.get("/status/{submission_id}", response_model=api_models.SubmissionStatus)
async def get_submission_status(
    submission_id: uuid.UUID, db: AsyncSession = Depends(get_db)
):
    """Retrieves the current status of a code submission."""
    submission = await crud.get_submission(db, submission_id)
    if not submission:
        raise HTTPException(status_code=404, detail="Submission not found")
    return submission


@router.get("/results/{submission_id}", response_model=api_models.SubmissionResultResponse)
async def get_submission_results(
    submission_id: uuid.UUID, db: AsyncSession = Depends(get_db)
):
    """Retrieves the full analysis results for a completed submission."""
    submission = await crud.get_submission(db, submission_id)
    if not submission:
        raise HTTPException(status_code=404, detail="Submission not found")

    if submission.status != "Completed":
        raise HTTPException(
            status_code=400,
            detail=f"Submission is still in '{submission.status}' state.",
        )

    return submission

@router.get("/history", response_model=List[api_models.SubmissionHistoryItem])
async def get_submission_history(
    db: Annotated[AsyncSession, Depends(get_db)],
    current_user: Annotated[db_models.User, Depends(current_active_user)],
):
    """
    Retrieves the submission history for the currently authenticated user.
    """
    history = await crud.get_submission_history(db, user_id=current_user.id)
    return history