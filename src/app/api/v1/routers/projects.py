import logging
import uuid
from typing import List, Optional

from fastapi import (
    APIRouter,
    Depends,
    HTTPException,
    Query,
    UploadFile,
    File,
    Form,
    Response,
    status,
)

from app.infrastructure.database import models as db_models
from app.api.v1 import models as api_models
from app.infrastructure.auth.core import current_active_user, current_superuser
from app.config.logging_config import correlation_id_var
from app.core.services.scan_service import SubmissionService
from app.api.v1.dependencies import get_scan_service
from app.shared.lib.git import clone_repo_and_get_files
from app.shared.lib.archive import extract_archive_to_files, is_archive_filename

router = APIRouter()
logger = logging.getLogger(__name__)

@router.get("/projects", response_model=api_models.PaginatedProjectHistoryResponse)
async def get_all_projects(
    user: db_models.User = Depends(current_active_user),
    service: SubmissionService = Depends(get_scan_service),
    skip: int = Query(0, ge=0),
    limit: int = Query(100, ge=1, le=1000),
    search: Optional[str] = Query(None, min_length=1, max_length=100)
):
    return await service.get_paginated_projects(user.id, skip, limit, search)

@router.post("/scans/preview-archive", response_model=dict)
async def preview_archive_files(archive_file: UploadFile = File(...)):
    if not archive_file.filename or not is_archive_filename(archive_file.filename):
        raise HTTPException(status_code=400, detail="Invalid or unsupported archive file provided.")
    files_data = extract_archive_to_files(archive_file)
    return {"files": [f["path"] for f in files_data]}

@router.post("/scans/preview-git", response_model=dict)
async def preview_git_files(request: api_models.GitRepoPreviewRequest):
    files_data = clone_repo_and_get_files(request.repo_url)
    if not files_data:
        raise HTTPException(status_code=400, detail="Repository cloned, but no processable files were found.")
    return {"files": [f["path"] for f in files_data]}

@router.post("/scans", response_model=api_models.ScanResponse)
async def create_scan(
    service: SubmissionService = Depends(get_scan_service),
    user: db_models.User = Depends(current_active_user),
    project_name: str = Form(...),
    scan_type: str = Form("audit"),
    main_llm_config_id: uuid.UUID = Form(...),
    specialized_llm_config_id: uuid.UUID = Form(...),
    frameworks: str = Form(...), # Received as a string, will be processed in service
    repo_url: Optional[str] = Form(None),
    files: Optional[List[UploadFile]] = File(None),
    archive_file: Optional[UploadFile] = File(None),
):
    common_args = {
        "project_name": project_name, 
        "user_id": user.id, 
        "correlation_id": correlation_id_var.get(),
        "scan_type": scan_type,
        "main_llm_config_id": main_llm_config_id,
        "specialized_llm_config_id": specialized_llm_config_id,
        "frameworks": [fw.strip() for fw in frameworks.split(',')]
    }

    submission_methods_count = sum(1 for method in [files, repo_url, archive_file] if method)
    if submission_methods_count != 1:
        raise HTTPException(status_code=400, detail="Exactly one submission method (files, repo_url, or archive_file) must be provided.")

    if files:
        scan = await service.create_scan_from_uploads(files=files, **common_args)
    elif repo_url:
        scan = await service.create_scan_from_git(repo_url=repo_url, **common_args)
    elif archive_file:
        scan = await service.create_scan_from_archive(archive_file=archive_file, **common_args)
    else:
        raise HTTPException(status_code=400, detail="No submission data provided.")

    return api_models.ScanResponse(scan_id=scan.id, message="Scan initiated and queued for analysis.")

@router.post("/scans/{scan_id}/approve", status_code=status.HTTP_202_ACCEPTED, response_model=dict)
async def approve_scan_analysis(
    scan_id: uuid.UUID, 
    user: db_models.User = Depends(current_active_user), 
    service: SubmissionService = Depends(get_scan_service)
):
    await service.approve_scan(scan_id, user)
    return {"message": "Scan approved and queued for processing."}

@router.post("/scans/{scan_id}/cancel", status_code=status.HTTP_200_OK, response_model=dict)
async def cancel_scan_analysis(
    scan_id: uuid.UUID,
    user: db_models.User = Depends(current_active_user),
    service: SubmissionService = Depends(get_scan_service),
):
    """Cancels a scan, typically one that is pending cost approval."""
    await service.cancel_scan(scan_id, user)
    return {"message": "Scan has been cancelled successfully."}

@router.get("/scans/{scan_id}/result", response_model=api_models.AnalysisResultDetailResponse)
async def get_scan_result_details(
    scan_id: uuid.UUID,
    user: db_models.User = Depends(current_active_user),
    service: SubmissionService = Depends(get_scan_service),
):
    """Retrieves the full, detailed result of a completed scan."""
    return await service.get_scan_result(scan_id, user)

@router.get("/projects/{project_id}/scans", response_model=api_models.PaginatedScanHistoryResponse)
async def get_scan_history_for_project(
    project_id: uuid.UUID,
    user: db_models.User = Depends(current_active_user),
    service: SubmissionService = Depends(get_scan_service),
    skip: int = Query(0, ge=0), 
    limit: int = Query(10, ge=1, le=100)
):
    return await service.get_paginated_scans_for_project(project_id, user.id, skip, limit)

@router.get("/scans/{scan_id}/llm-interactions", response_model=List[api_models.LLMInteractionResponse])
async def get_llm_interactions_for_scan(
    scan_id: uuid.UUID,
    user: db_models.User = Depends(current_active_user),
    service: SubmissionService = Depends(get_scan_service),
):
    """Retrieves all LLM interactions associated with a specific scan."""
    interactions_db = await service.get_llm_interactions_for_scan(scan_id, user)
    return [api_models.LLMInteractionResponse.from_orm(inter) for inter in interactions_db]