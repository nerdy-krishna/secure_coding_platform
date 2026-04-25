import logging
import uuid
from typing import List, Optional

from fastapi import (
    APIRouter,
    Depends,
    HTTPException,
    Query,
    Request,
    UploadFile,
    File,
    Form,
    Response,
    status,
)
from fastapi.responses import StreamingResponse
from pydantic import BaseModel

from app.infrastructure.database import models as db_models
from app.api.v1 import models as api_models
from app.config.config import settings
from app.infrastructure.auth.core import (
    current_active_user,
    current_active_user_sse,
    current_superuser,
)
from app.config.logging_config import correlation_id_var
from app.core.services.scan_service import SubmissionService
from app.api.v1.dependencies import (
    get_scan_service,
    get_llm_config_repository,
    get_visible_user_ids,
)
from app.infrastructure.database.repositories.llm_config_repo import LLMConfigRepository
from app.shared.lib.git import clone_repo_and_get_files
from app.shared.lib.archive import extract_archive_to_files, is_archive_filename

router = APIRouter()
logger = logging.getLogger(__name__)


@router.get("/projects", response_model=api_models.PaginatedProjectHistoryResponse)
async def get_all_projects(
    user: db_models.User = Depends(current_active_user),
    service: SubmissionService = Depends(get_scan_service),
    visible_user_ids: Optional[List[int]] = Depends(get_visible_user_ids),
    skip: int = Query(0, ge=0),
    limit: int = Query(100, ge=1, le=1000),
    search: Optional[str] = Query(None, min_length=1, max_length=100),
):
    return await service.get_paginated_projects(
        user.id, skip, limit, search, visible_user_ids=visible_user_ids
    )


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
    visible_user_ids: Optional[List[int]] = Depends(get_visible_user_ids),
):
    """Searches for projects by name visible to the caller (for autocomplete)."""
    return await service.search_projects(
        user_id=user.id, query=q, visible_user_ids=visible_user_ids
    )


@router.get("/scans/history", response_model=api_models.PaginatedScanHistoryResponse)
async def get_user_scan_history(
    user: db_models.User = Depends(current_active_user),
    service: SubmissionService = Depends(get_scan_service),
    visible_user_ids: Optional[List[int]] = Depends(get_visible_user_ids),
    page: int = Query(1, ge=1),
    page_size: int = Query(10, ge=1, le=100),
    search: Optional[str] = Query(None, min_length=1, max_length=100),
    sort_order: str = Query("desc", pattern="^(asc|desc)$"),
    status: Optional[str] = Query(None),
):
    """Retrieves a paginated list of all scans visible to the caller."""
    return await service.get_paginated_user_scans(
        user_id=user.id,
        skip=(page - 1) * page_size,
        limit=page_size,
        search=search,
        sort_order=sort_order,
        status=status,
        visible_user_ids=visible_user_ids,
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
    llm_repo: LLMConfigRepository = Depends(get_llm_config_repository),
    user: db_models.User = Depends(current_active_user),
    project_name: str = Form(...),
    scan_type: str = Form(...),
    utility_llm_config_id: Optional[uuid.UUID] = Form(None),
    fast_llm_config_id: Optional[uuid.UUID] = Form(None),
    reasoning_llm_config_id: Optional[uuid.UUID] = Form(None),
    frameworks: str = Form(...),  # Received as a string, will be processed in service
    repo_url: Optional[str] = Form(None),
    files: Optional[List[UploadFile]] = File(None),
    archive_file: Optional[UploadFile] = File(None),
    selected_files: Optional[str] = Form(None),
):
    selected_files_list = selected_files.split(",") if selected_files else None

    # Resolve any missing llm_config_id slots to a fallback config. Supports
    # the fresh-setup case where the admin has only configured one LLM — we
    # reuse it across utility/fast/reasoning slots instead of forcing the
    # user to configure three. Once multiple configs exist the submit UI
    # can let the user pick per slot.
    missing_slots = [
        s
        for s in (utility_llm_config_id, fast_llm_config_id, reasoning_llm_config_id)
        if s is None
    ]
    if missing_slots:
        available = await llm_repo.get_all(skip=0, limit=1)
        if not available:
            raise HTTPException(
                status_code=400,
                detail=(
                    "No LLM configurations available. Ask an admin to add one "
                    "under Admin → LLM Configurations before submitting a scan."
                ),
            )
        fallback_id = available[0].id
        utility_llm_config_id = utility_llm_config_id or fallback_id
        fast_llm_config_id = fast_llm_config_id or fallback_id
        reasoning_llm_config_id = reasoning_llm_config_id or fallback_id

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


@router.get("/scans/{scan_id}/stream")
async def stream_scan_progress(
    scan_id: uuid.UUID,
    request: Request,
    user: db_models.User = Depends(current_active_user_sse),
    service: SubmissionService = Depends(get_scan_service),
):
    """Server-Sent Events stream of a scan's progress.

    Emits a `scan_state` event for status transitions, a `scan_event` for
    each new pipeline stage (ScanEvent row), and a terminal `done` event
    when the scan reaches a final state. The client reconnects via
    EventSource's native retry.

    Implementation: polls the DB at 1-second intervals — simpler than
    wiring LangGraph event streaming and sufficient for the per-stage
    granularity the UI wants. Can be upgraded later if we need per-file
    finding deltas mid-scan.
    """
    # Authz: reuse the existing service check.
    scan = await service.get_scan_status(scan_id)
    if scan.user_id != user.id and not user.is_superuser:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Not authorized to stream this scan.",
        )

    terminal_statuses = {
        "COMPLETED",
        "REMEDIATION_COMPLETED",
        "FAILED",
        "CANCELLED",
        "EXPIRED",
    }
    poll_interval_seconds = 1.0
    # Bound on the stream's lifetime as a safety net; the scan-workflow
    # timeout (default 2h) dominates in practice.
    max_stream_seconds = settings.SCAN_WORKFLOW_TIMEOUT_SECONDS

    async def event_generator():
        import asyncio as _asyncio
        import json as _json
        import time as _time

        start = _time.monotonic()
        last_event_id = 0
        last_status: Optional[str] = None

        while True:
            if await request.is_disconnected():
                logger.info(
                    "SSE: client disconnected, ending stream.",
                    extra={"scan_id": str(scan_id), "user_id": user.id},
                )
                return
            if _time.monotonic() - start > max_stream_seconds:
                yield (
                    f"event: timeout\n"
                    f"data: {_json.dumps({'scan_id': str(scan_id)})}\n\n"
                )
                return

            scan = await service.get_scan_status(scan_id)

            # Emit on status change (including the first tick).
            if scan.status != last_status:
                last_status = scan.status
                payload = {
                    "scan_id": str(scan_id),
                    "status": scan.status,
                }
                yield (f"event: scan_state\n" f"data: {_json.dumps(payload)}\n\n")

            # Emit any ScanEvents with id > last_event_id.
            events = sorted(
                (e for e in (scan.events or []) if e.id > last_event_id),
                key=lambda e: e.id,
            )
            for e in events:
                last_event_id = e.id
                payload = {
                    "scan_id": str(scan_id),
                    "event_id": e.id,
                    "stage_name": e.stage_name,
                    "status": e.status,
                    "timestamp": e.timestamp.isoformat() if e.timestamp else None,
                }
                yield (
                    f"event: scan_event\n"
                    f"id: {e.id}\n"
                    f"data: {_json.dumps(payload)}\n\n"
                )

            if scan.status in terminal_statuses:
                yield (
                    f"event: done\n"
                    f"data: {_json.dumps({'scan_id': str(scan_id), 'status': scan.status})}\n\n"
                )
                return

            await _asyncio.sleep(poll_interval_seconds)

    return StreamingResponse(
        event_generator(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "X-Accel-Buffering": "no",  # disable nginx buffering for SSE
            "Connection": "keep-alive",
        },
    )


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
