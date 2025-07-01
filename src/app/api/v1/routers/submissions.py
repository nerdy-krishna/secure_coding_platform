# src/app/api/v1/routers/submissions.py

import logging
import uuid
from typing import List, Optional

from fastapi import (
    APIRouter,
    Depends,
    HTTPException,
    UploadFile,
    File,
    Form,
    status,
)

from app.infrastructure.database import models as db_models
from app.api.v1 import models as api_models
from app.infrastructure.auth.core import current_active_user, current_superuser
from app.config.logging_config import correlation_id_var
from app.core.services.submission_service import SubmissionService
from app.api.v1.dependencies import get_submission_service
from app.shared.lib.git import clone_repo_and_get_files
from app.shared.lib.archive import extract_archive_to_files, is_archive_filename

# This line defines the 'router' object that main.py is looking for.
router = APIRouter()
logger = logging.getLogger(__name__)

# Note: Preview endpoints are simple enough to not require a service layer.
@router.post("/submit/preview-archive", response_model=dict)
async def preview_archive_files(archive_file: UploadFile = File(...)):
    if not archive_file.filename or not is_archive_filename(archive_file.filename):
        raise HTTPException(status_code=400, detail="Invalid or unsupported archive file provided.")
    files_data = extract_archive_to_files(archive_file)
    return {"files": [f["path"] for f in files_data]}

@router.post("/submit/preview-git", response_model=dict)
async def preview_git_files(request: api_models.GitRepoPreviewRequest):
    files_data = clone_repo_and_get_files(request.repo_url)
    if not files_data:
        raise HTTPException(status_code=400, detail="Repository cloned, but no processable files were found.")
    return {"files": [f["path"] for f in files_data]}

@router.post("/submit", response_model=api_models.SubmissionResponse)
async def submit_code(
    service: SubmissionService = Depends(get_submission_service),
    user: db_models.User = Depends(current_active_user),
    project_name: str = Form(...),
    main_llm_config_id: uuid.UUID = Form(...),
    specialized_llm_config_id: uuid.UUID = Form(...),
    frameworks: str = Form(...),
    excluded_files: Optional[str] = Form(None),
    files: Optional[List[UploadFile]] = File(None),
    repo_url: Optional[str] = Form(None),
    archive_file: Optional[UploadFile] = File(None),
):
    """Handles code submission by delegating all logic to the SubmissionService."""
    common_args = {
        "project_name": project_name, "user_id": user.id, "correlation_id": correlation_id_var.get(),
        "frameworks": [f.strip() for f in frameworks.split(",")],
        "excluded_files": [f.strip() for f in excluded_files.split(",")] if excluded_files else [],
        "main_llm_id": main_llm_config_id, "specialized_llm_id": specialized_llm_config_id,
    }
    
    submission_methods_count = sum(1 for method in [files, repo_url, archive_file] if method)
    if submission_methods_count == 0:
        raise HTTPException(status_code=400, detail="No submission method provided.")
    if submission_methods_count > 1:
        raise HTTPException(status_code=400, detail="Multiple submission methods provided. Please use only one.")

    if files:
        submission = await service.create_from_uploads(files=files, **common_args)
    elif repo_url:
        submission = await service.create_from_git(repo_url=repo_url, **common_args)
    elif archive_file:
        submission = await service.create_from_archive(archive_file=archive_file, **common_args)
    
    return api_models.SubmissionResponse(submission_id=submission.id, message="Submission received and queued for analysis.")

@router.get("/status/{submission_id}", response_model=api_models.SubmissionStatus)
async def get_submission_status(
    submission_id: uuid.UUID, service: SubmissionService = Depends(get_submission_service)
):
    return await service.get_submission_status(submission_id)

@router.post("/submissions/{submission_id}/approve", status_code=status.HTTP_202_ACCEPTED, response_model=dict)
async def approve_submission_analysis(
    submission_id: uuid.UUID,
    user: db_models.User = Depends(current_active_user),
    service: SubmissionService = Depends(get_submission_service),
):
    await service.approve_submission(submission_id, user)
    return {"message": "Analysis approved and queued for processing."}

# ... (include other endpoints like /cancel, /remediate, etc. here)