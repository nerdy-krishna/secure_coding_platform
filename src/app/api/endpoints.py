# src/app/api/endpoints.py

import logging
import uuid
from typing import List, Optional, Annotated, Dict, Any
# Removed tempfile, os, shutil, git imports as they are now in git_utils

from fastapi import (
    APIRouter,
    Depends,
    HTTPException,
    UploadFile,
    File,
    Form,
    Response,
    status,
)
from sqlalchemy.ext.asyncio import AsyncSession

from app.db import crud
from app.db.database import get_db
from app.db import models as db_models
from app.api import models as api_models
from app.auth.core import current_active_user, current_superuser
from app.utils import rabbitmq_utils
from app.core.config import settings
from app.utils.git_utils import clone_repo_and_get_files # get_language_from_filename removed
from app.utils.file_utils import get_language_from_filename # Added import from file_utils
from app.utils.archive_utils import extract_archive_to_files, is_archive_filename, ALLOWED_ARCHIVE_EXTENSIONS # Added archive_utils imports

# Create two routers: one for general endpoints, one for admin-level LLM configs
router = APIRouter()
llm_router = APIRouter(prefix="/llm-configs", tags=["LLM Configurations"])

logger = logging.getLogger(__name__)

# === LLM Configuration Endpoints ===


@llm_router.post("/", response_model=api_models.LLMConfigurationRead, status_code=201)
async def create_llm_configuration(
    config: api_models.LLMConfigurationCreate,
    db: AsyncSession = Depends(get_db),
    user: db_models.User = Depends(current_superuser),
):
    """
    Creates a new LLM configuration. Requires superuser privileges.
    """
    return await crud.create_llm_config(db=db, config=config)


@llm_router.get("/", response_model=List[api_models.LLMConfigurationRead])
async def read_llm_configurations(
    db: AsyncSession = Depends(get_db),
    user: db_models.User = Depends(current_active_user),
):
    """
    Retrieves all LLM configurations. API keys are not included.
    """
    configs = await crud.get_llm_configs(db)
    return configs


@llm_router.patch("/{config_id}", response_model=api_models.LLMConfigurationRead)
async def update_llm_configuration(
    config_id: uuid.UUID,
    config_update: api_models.LLMConfigurationUpdate,
    db: AsyncSession = Depends(get_db),
    user: db_models.User = Depends(current_superuser),
):
    """
    Updates an existing LLM configuration. Requires superuser privileges.
    Partial updates are allowed.
    """
    updated_config = await crud.update_llm_config(
        db=db, config_id=config_id, config_update=config_update
    )
    if updated_config is None:
        raise HTTPException(status_code=404, detail="LLM Configuration not found")
    return updated_config


@llm_router.delete("/{config_id}", status_code=204)
async def delete_llm_configuration(
    config_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
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

@router.post("/submit/preview-archive", response_model=Dict[str, List[str]])
async def preview_archive_files(archive_file: UploadFile = File(...)):
    """
    Accepts an archive file, extracts it in a temporary location,
    and returns a list of file paths for frontend preview.
    """
    try:
        files_data = extract_archive_to_files(archive_file)
        file_paths = [f["path"] for f in files_data]
        return {"files": file_paths}
    except HTTPException:
        raise  # Re-raise HTTP exceptions from the utility function
    except Exception as e:
        logger.error(f"Error previewing archive {archive_file.filename}: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=f"Failed to preview archive: {str(e)}")


@router.post("/submit/preview-git", response_model=Dict[str, List[str]])
async def preview_git_files(request: api_models.GitRepoPreviewRequest):
    """
    Accepts a Git repository URL, clones it to a temporary location,
    and returns a list of file paths for frontend preview.
    """
    try:
        files_data = clone_repo_and_get_files(request.repo_url)
        if not files_data:
            raise HTTPException(status_code=400, detail="Repository cloned, but no processable files were found.")
        file_paths = [f["path"] for f in files_data]
        return {"files": file_paths}
    except HTTPException:
        raise  # Re-raise HTTP exceptions from the utility function
    except Exception as e:
        logger.error(f"Error previewing git repo {request.repo_url}: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=f"Failed to preview git repository: {str(e)}")

@router.post("/submit", response_model=api_models.SubmissionResponse)
async def submit_code(
    db: Annotated[AsyncSession, Depends(get_db)],
    current_user: Annotated[db_models.User, Depends(current_active_user)],
    main_llm_config_id: Annotated[uuid.UUID, Form(...)],
    specialized_llm_config_id: Annotated[uuid.UUID, Form(...)],
    frameworks: Annotated[str, Form(...)],
    excluded_files: Optional[str] = Form(None),
    files: Optional[List[UploadFile]] = File(None), # For direct file uploads
    repo_url: Optional[str] = Form(None), # For git repository URL
    archive_file: Optional[UploadFile] = File(None), # For archive file upload
):
    """
    Accepts code submission via direct file uploads, a Git repository URL, or an archive file.
    """
    submission_methods_count = sum(
        [1 for method in [files, repo_url, archive_file] if method]
    )

    if submission_methods_count == 0:
        raise HTTPException(
            status_code=400,
            detail="No submission method provided. Please upload files, provide a git repository URL, or upload an archive.",
        )
    if submission_methods_count > 1:
        raise HTTPException(
            status_code=400,
            detail="Multiple submission methods provided. Please use only one: direct file uploads, a git repository URL, or an archive file.",
        )

    main_llm = await crud.get_llm_config(db, main_llm_config_id)
    specialized_llm = await crud.get_llm_config(db, specialized_llm_config_id)
    if not main_llm or not specialized_llm:
        raise HTTPException(
            status_code=404,
            detail="One or both selected LLM configurations could not be found.",
        )

    framework_list = [f.strip() for f in frameworks.split(",")]
    excluded_files_list = [f.strip() for f in excluded_files.split(",")] if excluded_files else []

    files_data = []
    if files: # Direct file uploads
        for file_upload in files:
            if not file_upload.filename: # Should not happen with FastAPI UploadFile
                logger.warning("Received a file upload without a filename.")
                continue
            
            # Server-side check to reject archives in the direct file upload list
            if is_archive_filename(file_upload.filename):
                raise HTTPException(
                    status_code=400,
                    detail=f"Archive file '{file_upload.filename}' submitted via direct file upload. "
                           f"Please use the 'Upload Archive' option for archive files. "
                           f"Supported archive types: {', '.join(ALLOWED_ARCHIVE_EXTENSIONS)}",
                )

            content_bytes = await file_upload.read()
            try:
                content_str = content_bytes.decode("utf-8")
            except UnicodeDecodeError:
                logger.warning(f"Could not decode file {file_upload.filename} as UTF-8, attempting latin-1.")
                try:
                    content_str = content_bytes.decode("latin-1") # Fallback encoding
                except UnicodeDecodeError:
                    logger.error(f"Failed to decode file {file_upload.filename} with UTF-8 and latin-1.")
                    # Skip file or raise error, for now skipping
                    continue
            
            # Remove null bytes
            content_str = content_str.replace("\x00", "")
            language = get_language_from_filename(file_upload.filename)
            files_data.append(
                {
                    "path": file_upload.filename,
                    "content": content_str,
                    "language": language or "unknown",
                }
            )
    elif repo_url: # Git repository URL
        try:
            files_data = clone_repo_and_get_files(repo_url) # This already handles null bytes
            if not files_data:
                raise HTTPException(
                    status_code=400,
                    detail="Repository cloned, but no processable files were found."
                )
        except HTTPException:
            raise
        except Exception as e:
            logger.error(f"Unhandled error during repository processing for {repo_url}: {e}", exc_info=True)
            raise HTTPException(status_code=500, detail="An unexpected error occurred while processing the repository.")
    elif archive_file: # Archive file upload
        try:
            if not archive_file.filename or not is_archive_filename(archive_file.filename):
                raise HTTPException(
                    status_code=400,
                    detail=f"Invalid or unsupported archive file provided. Filename: {archive_file.filename}. "
                           f"Supported archive types: {', '.join(ALLOWED_ARCHIVE_EXTENSIONS)}",
                )
            files_data = extract_archive_to_files(archive_file) # This handles null bytes
        except HTTPException:
            raise
        except Exception as e:
            logger.error(f"Error processing uploaded archive {archive_file.filename}: {e}", exc_info=True)
            raise HTTPException(status_code=500, detail=f"An unexpected error occurred while processing the archive: {str(e)}")
    
    if not files_data:
        raise HTTPException(
            status_code=400,
            detail="No files were successfully processed for analysis from the provided input."
        )

    submission = await crud.create_submission(
        db=db,
        user_id=current_user.id,
        repo_url=repo_url,
        files=files_data,
        frameworks=framework_list,
        excluded_files=excluded_files_list,
        main_llm_config_id=main_llm_config_id,
        specialized_llm_config_id=specialized_llm_config_id,
    )

    rabbitmq_utils.publish_submission(str(submission.id))
    logger.info(f"Published submission {submission.id} to RabbitMQ.")

    return {
        "submission_id": submission.id,
        "message": "Submission received and queued for analysis.",
    }


@router.post(
    "/submissions/{submission_id}/approve",
    status_code=status.HTTP_202_ACCEPTED,
    summary="Approve a pending analysis for a submission",
    response_model=Dict[str, str],
)
async def approve_submission_analysis(
    submission_id: uuid.UUID,
    user: db_models.User = Depends(current_active_user),
    db: AsyncSession = Depends(get_db),
):
    """
    Approves a submission that is in the 'Pending Cost Approval' state.
    This endpoint sends a message to the worker queue to resume the analysis.
    """
    submission = await crud.get_submission(db, submission_id)
    if not submission:
        raise HTTPException(status_code=404, detail="Submission not found")

    if submission.user_id != user.id and not user.is_superuser:
        raise HTTPException(status_code=403, detail="Not authorized to approve this submission")

    if submission.status != "PENDING_COST_APPROVAL": # Updated status check
        raise HTTPException(
            status_code=400,
            detail=f"Submission is not pending approval. Current status: {submission.status}",
        )
    
    message = {
        "submission_id": str(submission.id),
        "action": "resume_analysis" 
    }
    
    # This line will now work correctly
    queue_name = settings.RABBITMQ_APPROVAL_QUEUE
    published = rabbitmq_utils.publish_message(queue_name, message)
    
    if not published:
        raise HTTPException(
            status_code=500,
            detail="Failed to send approval message to the processing queue. Please try again later."
        )
    
    await crud.update_submission_status(db, submission_id, "Approved - Queued")

    return {"message": "Analysis approved and queued for processing."}

@router.post(
    "/submissions/{submission_id}/cancel",
    status_code=status.HTTP_200_OK,
    response_model=Dict[str, str],
    summary="Cancel a pending submission",
)
async def cancel_submission(
    submission_id: uuid.UUID,
    user: db_models.User = Depends(current_active_user),
    db: AsyncSession = Depends(get_db),
):
    """
    Cancels a submission that is in the 'PENDING_COST_APPROVAL' state.
    """
    submission = await crud.get_submission(db, submission_id)
    if not submission:
        raise HTTPException(status_code=404, detail="Submission not found")

    if submission.user_id != user.id and not user.is_superuser:
        raise HTTPException(
            status_code=403, detail="Not authorized to cancel this submission"
        )

    if submission.status != "PENDING_COST_APPROVAL":
        raise HTTPException(
            status_code=400,
            detail=f"Submission cannot be cancelled. Current status: {submission.status}",
        )

    await crud.update_submission_status(db, submission_id, "Cancelled")
    logger.info(f"User {user.id} cancelled submission {submission_id}.")
    return {"message": "Submission has been successfully cancelled."}

@router.get("/status/{submission_id}", response_model=api_models.SubmissionStatus)
async def get_submission_status(
    submission_id: uuid.UUID, db: AsyncSession = Depends(get_db)
):
    """Retrieves the current status of a code submission."""
    submission = await crud.get_submission(db, submission_id)
    if not submission:
        raise HTTPException(status_code=404, detail="Submission not found")
    return submission


@router.get("/result/{submission_id}", response_model=api_models.AnalysisResultDetailResponse)
async def get_submission_results(
    submission_id: uuid.UUID, db: AsyncSession = Depends(get_db)
):
    """
    Retrieves the full analysis results for a completed submission, including
    the new impact and SARIF reports.
    """
    # Step 1: Fetch the submission object. The 'get_submission' function should be configured
    # to eager-load related findings and files.
    submission_db = await crud.get_submission(db, submission_id)
    if not submission_db:
        raise HTTPException(status_code=404, detail="Submission not found")

    # Step 2: Ensure the analysis is actually complete. This is still crucial.
    if submission_db.status != "Completed":
        logger.warning(
            f"Attempt to access results for non-completed submission {submission_id} with status {submission_db.status}"
        )
        raise HTTPException(
            status_code=400,
            detail=f"Submission analysis is not yet completed. Current status: '{submission_db.status}'.",
        )
    
    # Step 3 (Optional but preserved): Build the detailed summary report for the UI.
    # This logic remains useful for UIs that need a granular breakdown.
    all_findings_db: List[db_models.VulnerabilityFinding] = submission_db.findings
    findings_by_file: Dict[str, List[db_models.VulnerabilityFinding]] = {}
    for finding_db_item in all_findings_db:
        findings_by_file.setdefault(finding_db_item.file_path, []).append(finding_db_item)

    files_analyzed_report_items: List[api_models.SubmittedFileReportItem] = []
    for file_db in submission_db.files:
        current_file_findings_db = findings_by_file.get(file_db.file_path, [])
        file_findings_response: List[api_models.VulnerabilityFindingResponse] = [
            api_models.VulnerabilityFindingResponse.from_orm(f) for f in current_file_findings_db
        ]
        files_analyzed_report_items.append(
            api_models.SubmittedFileReportItem(
                file_path=file_db.file_path,
                findings=file_findings_response,
                language=file_db.language,
                analysis_summary=file_db.analysis_summary,
                identified_components=file_db.identified_components,
                asvs_analysis=file_db.asvs_analysis,
            )
        )

    sev_counts_obj = api_models.SeverityCountsResponse()
    for finding_db_item in all_findings_db:
        sev = finding_db_item.severity.upper()
        if sev == "CRITICAL": sev_counts_obj.CRITICAL += 1
        elif sev == "HIGH": sev_counts_obj.HIGH += 1
        elif sev == "MEDIUM": sev_counts_obj.MEDIUM += 1
        elif sev == "LOW": sev_counts_obj.LOW += 1
        elif sev == "INFORMATIONAL": sev_counts_obj.INFORMATIONAL += 1

    summary_response_obj = api_models.SummaryResponse(
        total_findings_count=len(all_findings_db),
        files_analyzed_count=len(submission_db.files),
        severity_counts=sev_counts_obj
    )
    
    project_name = submission_db.repo_url or "N/A"
    if submission_db.repo_url:
        try:
            project_name = submission_db.repo_url.split('/')[-1].replace('.git', '')
        except Exception:
            project_name = submission_db.repo_url

    primary_language = "N/A"
    if submission_db.files and submission_db.files[0].language:
        primary_language = submission_db.files[0].language

    summary_report_response_obj = api_models.SummaryReportResponse(
        submission_id=submission_db.id,
        project_name=project_name,
        primary_language=primary_language,
        selected_frameworks=submission_db.frameworks or [],
        analysis_timestamp=submission_db.completed_at,
        summary=summary_response_obj,
        files_analyzed=files_analyzed_report_items,
    )
    
    # Step 4: Assemble the final response, now including the new direct report fields.
    return api_models.AnalysisResultDetailResponse(
        impact_report=submission_db.impact_report,
        sarif_report=submission_db.sarif_report,
        summary_report=summary_report_response_obj
    )

@router.get("/llm-interactions/", response_model=List[api_models.LLMInteractionResponse])
async def read_llm_interactions_for_user(
    db: Annotated[AsyncSession, Depends(get_db)],
    current_user: Annotated[db_models.User, Depends(current_active_user)],
):
    """
    Retrieves a history of all LLM interactions for the current user.
    """
    interactions = await crud.get_llm_interactions_for_user(db, user_id=current_user.id)
    return interactions

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
