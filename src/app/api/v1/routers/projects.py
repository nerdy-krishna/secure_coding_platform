import logging
import uuid
from typing import Any, Dict, List, Optional

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
from pydantic import BaseModel

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
    search: Optional[str] = Query(None, min_length=1, max_length=100),
):
    return await service.get_paginated_projects(user.id, skip, limit, search)


class CreateProjectRequest(BaseModel):
    name: str


@router.post(
    "/projects",
    response_model=api_models.ProjectHistoryItem,
    status_code=status.HTTP_201_CREATED,
)
async def create_project(
    request: CreateProjectRequest,
    user: db_models.User = Depends(current_active_user),
    service: SubmissionService = Depends(get_scan_service),
):
    """Creates a new empty project."""
    project = await service.repo.get_or_create_project(
        name=request.name, user_id=user.id
    )
    return api_models.ProjectHistoryItem(
        id=project.id,
        name=project.name,
        repository_url=project.repository_url,
        created_at=project.created_at,
        updated_at=project.updated_at,
        scans=[],
    )


@router.get("/projects/search", response_model=List[str])
async def search_projects_for_user(
    q: str = Query(..., min_length=1, max_length=100),
    user: db_models.User = Depends(current_active_user),
    service: SubmissionService = Depends(get_scan_service),
):
    """Searches for projects by name for the current user (for autocomplete)."""
    return await service.search_projects(user_id=user.id, query=q)


@router.get("/scans/history", response_model=api_models.PaginatedScanHistoryResponse)
async def get_user_scan_history(
    user: db_models.User = Depends(current_active_user),
    service: SubmissionService = Depends(get_scan_service),
    page: int = Query(1, ge=1),
    page_size: int = Query(10, ge=1, le=100),
    search: Optional[str] = Query(None, min_length=1, max_length=100),
    sort_order: str = Query("desc", pattern="^(asc|desc)$"),
    status: Optional[str] = Query(None),
):
    """Retrieves a paginated list of all scans for the current user."""
    return await service.get_paginated_user_scans(
        user_id=user.id,
        skip=(page - 1) * page_size,
        limit=page_size,
        search=search,
        sort_order=sort_order,
        status=status,
    )


@router.post("/scans/preview-archive", response_model=dict)
async def preview_archive_files(archive_file: UploadFile = File(...)):
    if not archive_file.filename or not is_archive_filename(archive_file.filename):
        raise HTTPException(
            status_code=400, detail="Invalid or unsupported archive file provided."
        )
    files_data = extract_archive_to_files(archive_file)
    return {"files": [f["path"] for f in files_data]}


@router.post("/scans/preview-git", response_model=dict)
async def preview_git_files(request: api_models.GitRepoPreviewRequest):
    files_data = clone_repo_and_get_files(request.repo_url)
    if not files_data:
        raise HTTPException(
            status_code=400,
            detail="Repository cloned, but no processable files were found.",
        )
    return {"files": [f["path"] for f in files_data]}


@router.post("/scans", response_model=api_models.ScanResponse)
async def create_scan(
    service: SubmissionService = Depends(get_scan_service),
    user: db_models.User = Depends(current_active_user),
    project_name: str = Form(...),
    scan_type: str = Form(...),
    utility_llm_config_id: uuid.UUID = Form(...),
    fast_llm_config_id: uuid.UUID = Form(...),
    reasoning_llm_config_id: uuid.UUID = Form(...),
    frameworks: str = Form(...),  # Received as a string, will be processed in service
    repo_url: Optional[str] = Form(None),
    files: Optional[List[UploadFile]] = File(None),
    archive_file: Optional[UploadFile] = File(None),
    selected_files: Optional[str] = Form(None),
):
    selected_files_list = selected_files.split(",") if selected_files else None

    common_args = {
        "project_name": project_name,
        "user_id": user.id,
        "correlation_id": correlation_id_var.get(),
        "scan_type": scan_type,
        "utility_llm_config_id": utility_llm_config_id,
        "fast_llm_config_id": fast_llm_config_id,
        "reasoning_llm_config_id": reasoning_llm_config_id,
        "frameworks": [fw.strip() for fw in frameworks.split(",")],
        "selected_files": selected_files_list,
    }

    submission_methods_count = sum(
        1 for method in [files, repo_url, archive_file] if method
    )
    if submission_methods_count != 1:
        raise HTTPException(
            status_code=400,
            detail="Exactly one submission method (files, repo_url, or archive_file) must be provided.",
        )

    if files:
        scan = await service.create_scan_from_uploads(files=files, **common_args)
    elif repo_url:
        scan = await service.create_scan_from_git(repo_url=repo_url, **common_args)
    elif archive_file:
        scan = await service.create_scan_from_archive(
            archive_file=archive_file, **common_args
        )
    else:
        raise HTTPException(status_code=400, detail="No submission data provided.")

    return api_models.ScanResponse(
        scan_id=scan.id,
        project_id=scan.project_id,
        message="Scan initiated and queued for analysis.",
    )


@router.post(
    "/scans/{scan_id}/approve",
    status_code=status.HTTP_202_ACCEPTED,
    response_model=dict,
)
async def approve_scan_analysis(
    scan_id: uuid.UUID,
    user: db_models.User = Depends(current_active_user),
    service: SubmissionService = Depends(get_scan_service),
):
    await service.approve_scan(scan_id, user)
    return {"message": "Scan approved and queued for processing."}


@router.post(
    "/scans/{scan_id}/cancel", status_code=status.HTTP_200_OK, response_model=dict
)
async def cancel_scan_analysis(
    scan_id: uuid.UUID,
    user: db_models.User = Depends(current_active_user),
    service: SubmissionService = Depends(get_scan_service),
):
    """Cancels a scan, typically one that is pending cost approval."""
    await service.cancel_scan(scan_id, user)
    return {"message": "Scan has been cancelled successfully."}


class SelectiveRemediationRequest(BaseModel):
    finding_ids: List[int]


@router.post(
    "/scans/{scan_id}/apply-fixes",
    status_code=status.HTTP_202_ACCEPTED,
    response_model=dict,
)
async def apply_fixes(
    scan_id: uuid.UUID,
    request: SelectiveRemediationRequest,
    user: db_models.User = Depends(current_active_user),
    service: SubmissionService = Depends(get_scan_service),
):
    """Triggers the application of selected fixes for a scan."""
    await service.apply_selective_fixes(scan_id, request.finding_ids, user)
    return {
        "message": "Fix application process initiated. The scan status will be updated upon completion."
    }


@router.get("/scans/{scan_id}/executive-summary/download", response_class=Response)
async def download_executive_summary(
    scan_id: uuid.UUID,
    user: db_models.User = Depends(current_active_user),
    service: SubmissionService = Depends(get_scan_service),
):
    """Generates and downloads the executive summary as a PDF."""
    pdf_bytes = await service.generate_executive_summary_pdf(scan_id, user)
    if not pdf_bytes:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Report data not found or you do not have permission to access it.",
        )

    return Response(
        content=pdf_bytes,
        media_type="application/pdf",
        headers={
            "Content-Disposition": f"attachment; filename=executive-summary-{scan_id}.pdf"
        },
    )


@router.get(
    "/scans/{scan_id}/result", response_model=api_models.AnalysisResultDetailResponse
)
async def get_scan_result_details(
    scan_id: uuid.UUID,
    user: db_models.User = Depends(current_active_user),
    service: SubmissionService = Depends(get_scan_service),
):
    """Retrieves the full, detailed result of a completed scan."""
    result = await service.get_scan_result(scan_id, user)

    # --- ADD THIS LOGGING BLOCK ---
    if result and result.summary_report:
        files_count = len(result.summary_report.files_analyzed)
        findings_count = sum(
            len(f.findings) for f in result.summary_report.files_analyzed
        )
        logger.debug(
            f"[API ENDPOINT DEBUG] Returning result for scan {scan_id}. "
            f"Files in report: {files_count}, Total findings nested in files: {findings_count}",
            extra={"scan_id": str(scan_id)},
        )
    # --- END LOGGING BLOCK ---

    return result


@router.get(
    "/projects/{project_id}/scans",
    response_model=api_models.PaginatedScanHistoryResponse,
)
async def get_scan_history_for_project(
    project_id: uuid.UUID,
    user: db_models.User = Depends(current_active_user),
    service: SubmissionService = Depends(get_scan_service),
    skip: int = Query(0, ge=0),
    limit: int = Query(10, ge=1, le=100),
):
    return await service.get_paginated_scans_for_project(
        project_id, user.id, skip, limit
    )


@router.get("/scans/{scan_id}/sarif", response_model=Dict[str, Any])
async def download_sarif_report(
    scan_id: uuid.UUID,
    user: db_models.User = Depends(current_active_user),
    service: SubmissionService = Depends(get_scan_service),
):
    """Downloads the SARIF report for a specific scan."""
    return await service.get_sarif_for_scan(scan_id, user)


@router.get(
    "/scans/{scan_id}/llm-interactions",
    response_model=List[api_models.LLMInteractionResponse],
)
async def get_llm_interactions_for_scan(
    scan_id: uuid.UUID,
    user: db_models.User = Depends(current_active_user),
    service: SubmissionService = Depends(get_scan_service),
):
    """Retrieves all LLM interactions associated with a specific scan."""
    interactions_db = await service.get_llm_interactions_for_scan(scan_id, user)
    return [
        api_models.LLMInteractionResponse.from_orm(inter) for inter in interactions_db
    ]


@router.delete("/scans/{scan_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_scan(
    scan_id: uuid.UUID,
    user: db_models.User = Depends(current_superuser),
    service: SubmissionService = Depends(get_scan_service),
):
    """Deletes a single scan (superuser only)."""
    await service.delete_scan_by_id(scan_id, user)
    return Response(status_code=status.HTTP_204_NO_CONTENT)


@router.delete("/projects/{project_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_project(
    project_id: uuid.UUID,
    user: db_models.User = Depends(current_superuser),
    service: SubmissionService = Depends(get_scan_service),
):
    """Delets a project and all its scans (superuser only)."""
    await service.delete_project_by_id(project_id, user)
    return Response(status_code=status.HTTP_204_NO_CONTENT)
