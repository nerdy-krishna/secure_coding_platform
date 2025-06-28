# src/app/api/endpoints.py

import datetime
import io
import logging
import uuid
from typing import List, Optional, Annotated, Dict, Any

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
from fastapi.responses import StreamingResponse
from sqlalchemy.ext.asyncio import AsyncSession

from app.db import crud
from app.db.database import get_db
from app.db import models as db_models
from app.api import models as api_models
from app.auth.core import current_active_user, current_superuser
from app.utils import rabbitmq_utils
from app.core.config import settings
from app.core.logging_config import correlation_id_var
from app.utils.git_utils import clone_repo_and_get_files
from app.utils.file_utils import get_language_from_filename
from app.utils.archive_utils import extract_archive_to_files, is_archive_filename, ALLOWED_ARCHIVE_EXTENSIONS
from app.utils.reporting_utils import generate_pdf_from_html

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
    project_name: Annotated[str, Form(...)],
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
        project_name=project_name,
        repo_url=repo_url,
        files=files_data,
        frameworks=framework_list,
        excluded_files=excluded_files_list,
        main_llm_config_id=main_llm_config_id,
        specialized_llm_config_id=specialized_llm_config_id,
    )

    # Get the correlation ID from the context variable and pass it to the publisher
    corr_id = correlation_id_var.get()
    rabbitmq_utils.publish_submission(str(submission.id), correlation_id=corr_id)
    logger.info(f"Published submission {submission.id} to RabbitMQ.", extra={"correlation_id": corr_id})

    return {
        "submission_id": submission.id,
        "message": "Submission received and queued for analysis.",
    }

@router.post(
    "/submissions/{submission_id}/remediate",
    status_code=status.HTTP_202_ACCEPTED,
    summary="Trigger remediation for a completed submission",
    response_model=Dict[str, str],
)
async def trigger_remediation(
    submission_id: uuid.UUID,
    remediation_request: api_models.RemediationRequest,
    user: db_models.User = Depends(current_active_user),
    db: AsyncSession = Depends(get_db),
):
    """
    Triggers a remediation workflow for a submission that has been audited.
    This action is asynchronous and will queue the remediation task.
    """
    submission = await crud.get_submission(db, submission_id)
    if not submission:
        raise HTTPException(status_code=404, detail="Submission not found")

    if submission.user_id != user.id and not user.is_superuser:
        raise HTTPException(status_code=403, detail="Not authorized to remediate this submission")

    # Allow remediation on 'Completed' or previously failed remediation runs
    if submission.status not in ["Completed", "Remediation-Failed"]:
        raise HTTPException(
            status_code=400,
            detail=f"Remediation can only be started for submissions with status 'Completed' or 'Remediation-Failed'. Current status: {submission.status}",
        )

    message = {
        "submission_id": str(submission.id),
        "action": "trigger_remediation",
        "categories_to_fix": remediation_request.categories_to_fix,
    }
    
    corr_id = correlation_id_var.get()
    published = rabbitmq_utils.publish_message(
        queue_name=settings.RABBITMQ_REMEDIATION_QUEUE,
        message_body=message,
        correlation_id=corr_id
    )
    
    if not published:
        raise HTTPException(
            status_code=500,
            detail="Failed to send remediation request to the processing queue."
        )
    
    # Update status to show it's queued for the next phase
    await crud.update_submission_status(db, submission_id, "Queued for Remediation")

    return {"message": "Remediation request accepted and queued for processing."}


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
    
    # --- START: NEW FILTERING LOGIC ---
    # Create a set of excluded file paths for efficient lookup.
    excluded_files_set = set(submission_db.excluded_files or [])
    
    # Create new lists containing only the data from non-excluded files.
    analyzed_files_db = [
        file for file in submission_db.files if file.file_path not in excluded_files_set
    ]
    findings_from_analyzed_files = [
        finding for finding in submission_db.findings if finding.file_path not in excluded_files_set
    ]
    # --- END: NEW FILTERING LOGIC --

    # Step 3: Build the detailed summary report using the FILTERED data.
    all_findings_db: List[db_models.VulnerabilityFinding] = findings_from_analyzed_files
    
    # 1. Group findings by their file_path.
    findings_by_file: Dict[str, List[db_models.VulnerabilityFinding]] = {}
    for finding_db_item in all_findings_db:
        findings_by_file.setdefault(finding_db_item.file_path, []).append(finding_db_item)

    # 2. Create a map of file data for easy lookup, using only analyzed files.
    file_data_map: Dict[str, db_models.SubmittedFile] = {
        file_db.file_path: file_db for file_db in analyzed_files_db
    }
    
    # 3. This union will now correctly only contain paths of analyzed files.
    all_involved_paths = sorted(
        list(set(file_data_map.keys()).union(set(findings_by_file.keys())))
    )

    # 4. Build the final report list. This loop now only iterates over analyzed files.
    files_analyzed_report_items: List[api_models.SubmittedFileReportItem] = []
    for path in all_involved_paths:
        file_info = file_data_map.get(path)
        file_findings = findings_by_file.get(path, [])
        
        file_findings_response = [
            api_models.VulnerabilityFindingResponse.from_orm(f) for f in file_findings
        ]

        files_analyzed_report_items.append(
            api_models.SubmittedFileReportItem(
                file_path=path,
                findings=file_findings_response,
                language=file_info.language if file_info else "unknown",
                analysis_summary=file_info.analysis_summary if file_info else None,
                identified_components=file_info.identified_components if file_info else [],
                asvs_analysis=file_info.asvs_analysis if file_info else None,
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
        files_analyzed_count=len(files_analyzed_report_items),
        severity_counts=sev_counts_obj
    )
    
    project_name = submission_db.project_name

    primary_language = "N/A"
    if analyzed_files_db:
        primary_language = analyzed_files_db[0].language

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

@router.get("/result/{submission_id}/executive-summary/download")
async def download_executive_summary_pdf(
    submission_id: uuid.UUID, db: AsyncSession = Depends(get_db)
):
    """
    Generates and downloads a PDF version of the executive summary report.
    """
    submission_db = await crud.get_submission(db, submission_id)
    if not submission_db or not submission_db.impact_report:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Executive summary report not found for this submission.",
        )

    report_data = submission_db.impact_report

    # Basic HTML structure for the PDF report
    html_content = f"""
    <html>
        <head>
            <style>
                body {{ font-family: sans-serif; line-height: 1.6; }}
                h1 {{ color: #333; }}
                h2 {{ color: #555; border-bottom: 1px solid #eee; padding-bottom: 5px; }}
                ul {{ padding-left: 20px; }}
                li {{ margin-bottom: 8px; }}
                .summary {{ background-color: #f7f7f7; padding: 15px; border-radius: 5px; }}
            </style>
        </head>
        <body>
            <h1>Executive Security Summary</h1>
            <p><strong>Project:</strong> {submission_db.project_name}</p>
            <p><strong>Submission ID:</strong> {submission_id}</p>
            <p><strong>Date:</strong> {datetime.datetime.now().strftime("%Y-%m-%d")}</p>
            
            <h2>Executive Summary</h2>
            <div class="summary">
                <p>{report_data.get('executive_summary', 'Not available.')}</p>
            </div>

            <h2>Vulnerability Overview</h2>
            <p>{report_data.get('vulnerability_overview', 'Not available.')}</p>

            <h2>High-Risk Findings</h2>
            <ul>
                {''.join(f"<li>{item}</li>" for item in report_data.get('high_risk_findings_summary', []))}
            </ul>

            <h2>Remediation Strategy</h2>
            <p>{report_data.get('remediation_strategy', 'Not available.')}</p>

            <h2>Effort & Architectural Impact</h2>
            <p><strong>Estimated Remediation Effort:</strong> {report_data.get('estimated_remediation_effort', 'N/A')}</p>
            <p><strong>Required Architectural Changes:</strong></p>
            <ul>
                {''.join(f"<li>{item}</li>" for item in report_data.get('required_architectural_changes', ['None']))}
            </ul>
        </body>
    </html>
    """

    try:
        pdf_bytes = generate_pdf_from_html(html_content)
        return StreamingResponse(
            io.BytesIO(pdf_bytes),
            media_type='application/pdf',
            headers={
                'Content-Disposition': f'attachment; filename="executive-summary-{submission_id}.pdf"'
            }
        )
    except Exception as e:
        logger.error(f"Failed to generate PDF for submission {submission_id}: {e}", exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to generate PDF report."
        )

@router.get("/results", response_model=api_models.PaginatedResultsResponse)
async def get_all_results(
    db: Annotated[AsyncSession, Depends(get_db)],
    current_user: Annotated[db_models.User, Depends(current_active_user)],
    skip: int = Query(0, ge=0, description="Number of records to skip for pagination."),
    limit: int = Query(10, ge=1, le=100, description="Number of records to return."),
    search: Optional[str] = Query(None, min_length=1, max_length=100, description="Search term to filter results.")
):
    """
    Retrieves a paginated and searchable list of all completed analysis results for the user.
    """
    total = await crud.get_paginated_results_count(db, user_id=current_user.id, search=search)
    items = await crud.get_paginated_results(db, user_id=current_user.id, skip=skip, limit=limit, search=search)
    return {"items": items, "total": total}


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

@router.get("/history", response_model=api_models.PaginatedSubmissionHistoryResponse)
async def get_submission_history(
    db: Annotated[AsyncSession, Depends(get_db)],
    current_user: Annotated[db_models.User, Depends(current_active_user)],
    skip: int = Query(0, ge=0, description="Number of records to skip for pagination."),
    limit: int = Query(10, ge=1, le=100, description="Number of records to return."),
    search: Optional[str] = Query(None, min_length=1, max_length=100, description="Search term to filter by project name or submission ID.")
):
    """
    Retrieves a paginated list of submission history for the currently authenticated user.
    """

    total = await crud.get_submission_history_count(db, user_id=current_user.id, search=search)
    items_raw = await crud.get_submission_history(db, user_id=current_user.id, skip=skip, limit=limit, search=search)
    
    return {"items": items_raw, "total": total}


@router.delete(
    "/submissions/{submission_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    summary="Delete a submission record",
)
async def delete_submission_record(
    submission_id: uuid.UUID,
    user: db_models.User = Depends(current_superuser),
    db: AsyncSession = Depends(get_db),
):
    """
    Deletes a submission and all its associated data.
    This action is permanent and requires superuser privileges.
    """
    deleted = await crud.delete_submission(db, submission_id)
    if not deleted:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Submission not found")
    return Response(status_code=status.HTTP_204_NO_CONTENT)