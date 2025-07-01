# src/app/api/v1/routers/submissions.py

import datetime
import io
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
from fastapi.responses import StreamingResponse

from app.infrastructure.database import models as db_models
from app.api.v1 import models as api_models
from app.infrastructure.auth.core import current_active_user, current_superuser
from app.config.logging_config import correlation_id_var
from app.core.services.submission_service import SubmissionService
from app.api.v1.dependencies import get_submission_service
from app.shared.lib.git import clone_repo_and_get_files
from app.shared.lib.archive import extract_archive_to_files, is_archive_filename
from app.shared.lib.reporting import generate_pdf_from_html

router = APIRouter()
logger = logging.getLogger(__name__)

# --- Preview Endpoints ---
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

# --- Main Submission Endpoint ---
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
    common_args = {
        "project_name": project_name, "user_id": user.id, "correlation_id": correlation_id_var.get(),
        "frameworks": [f.strip() for f in frameworks.split(",")],
        "excluded_files": [f.strip() for f in excluded_files.split(",")] if excluded_files else [],
        "main_llm_id": main_llm_config_id, "specialized_llm_id": specialized_llm_config_id,
    }
    submission_methods_count = sum(1 for method in [files, repo_url, archive_file] if method)
    if submission_methods_count != 1:
        raise HTTPException(status_code=400, detail="Exactly one submission method must be provided.")
    if files:
        submission = await service.create_from_uploads(files=files, **common_args)
    elif repo_url:
        submission = await service.create_from_git(repo_url=repo_url, **common_args)
    elif archive_file:
        submission = await service.create_from_archive(archive_file=archive_file, **common_args)
    return api_models.SubmissionResponse(submission_id=submission.id, message="Submission received and queued for analysis.")

# --- Results and History Endpoints ---

@router.get("/results", response_model=api_models.PaginatedResultsResponse)
async def get_all_results(
    user: db_models.User = Depends(current_active_user),
    service: SubmissionService = Depends(get_submission_service),
    skip: int = Query(0, ge=0), limit: int = Query(10, ge=1, le=100),
    search: Optional[str] = Query(None, min_length=1, max_length=100)
):
    return await service.get_paginated_results(user.id, skip, limit, search)

@router.get("/history", response_model=api_models.PaginatedSubmissionHistoryResponse)
async def get_submission_history(
    user: db_models.User = Depends(current_active_user),
    service: SubmissionService = Depends(get_submission_service),
    skip: int = Query(0, ge=0), limit: int = Query(5, ge=1, le=50),
    search: Optional[str] = Query(None, min_length=1, max_length=100)
):
    return await service.get_paginated_history(user.id, skip, limit, search)

@router.get("/llm-interactions/", response_model=List[api_models.LLMInteractionResponse])
async def read_llm_interactions_for_user(
    user: db_models.User = Depends(current_active_user),
    service: SubmissionService = Depends(get_submission_service),
):
    return await service.get_llm_interactions(user_id=user.id)

@router.get("/result/{submission_id}", response_model=api_models.AnalysisResultDetailResponse)
async def get_submission_results(
    submission_id: uuid.UUID, service: SubmissionService = Depends(get_submission_service)
):
    """Retrieves the full analysis results for a single completed submission."""
    return await service.get_results(submission_id)

@router.get("/result/{submission_id}/executive-summary/download")
async def download_executive_summary_pdf(
    submission_id: uuid.UUID, service: SubmissionService = Depends(get_submission_service)
):
    """Generates and downloads a PDF version of the executive summary report."""
    submission_db = await service.get_submission_status(submission_id)
    if not submission_db or not submission_db.impact_report:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Executive summary report not found for this submission.",
        )

    report_data = submission_db.impact_report
    html_content = f"""
    <html><head><style>
        body {{ font-family: sans-serif; line-height: 1.5; }} h1 {{ color: #2c3e50; }}
        h2 {{ color: #34495e; border-bottom: 1px solid #eee; padding-bottom: 5px; margin-top: 20px;}}
        ul {{ padding-left: 20px; }} li {{ margin-bottom: 8px; }}
        .summary {{ background-color: #f8f9f9; border: 1px solid #d6dbdf; padding: 15px; border-radius: 5px; }}
    </style></head><body>
        <h1>Executive Security Summary</h1>
        <p><strong>Project:</strong> {submission_db.project_name}</p>
        <p><strong>Submission ID:</strong> {submission_id}</p>
        <p><strong>Date:</strong> {datetime.datetime.now().strftime("%Y-%m-%d")}</p>
        <h2>Executive Overview</h2><div class="summary"><p>{report_data.get('executive_summary', 'Not available.')}</p></div>
        <h2>Vulnerability Analysis</h2><p>{report_data.get('vulnerability_overview', 'Not available.')}</p>
        <h2>High-Risk Findings</h2><ul>{''.join(f"<li>{item}</li>" for item in report_data.get('high_risk_findings_summary', []))}</ul>
        <h2>Remediation Strategy</h2><p>{report_data.get('remediation_strategy', 'Not available.')}</p>
        <h2>Effort & Architectural Impact</h2>
        <p><strong>Estimated Remediation Effort:</strong> {report_data.get('estimated_remediation_effort', 'N/A')}</p>
        <p><strong>Required Architectural Changes:</strong></p><ul>{''.join(f"<li>{item}</li>" for item in report_data.get('required_architectural_changes', ['None']))}</ul>
    </body></html>
    """
    try:
        pdf_bytes = generate_pdf_from_html(html_content)
        return StreamingResponse(io.BytesIO(pdf_bytes), media_type='application/pdf',
            headers={'Content-Disposition': f'attachment; filename="executive-summary-{submission_id}.pdf"'})
    except Exception as e:
        logger.error(f"Failed to generate PDF for submission {submission_id}: {e}", exc_info=True)
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Failed to generate PDF report.")

# --- Submission Lifecycle Endpoints ---

@router.get("/status/{submission_id}", response_model=api_models.SubmissionStatus)
async def get_submission_status(
    submission_id: uuid.UUID, service: SubmissionService = Depends(get_submission_service)
):
    return await service.get_submission_status(submission_id)

@router.post("/submissions/{submission_id}/approve", status_code=status.HTTP_202_ACCEPTED, response_model=dict)
async def approve_submission_analysis(
    submission_id: uuid.UUID, user: db_models.User = Depends(current_active_user), service: SubmissionService = Depends(get_submission_service)
):
    await service.approve_submission(submission_id, user)
    return {"message": "Analysis approved and queued for processing."}

@router.post("/submissions/{submission_id}/cancel", status_code=status.HTTP_200_OK, response_model=dict)
async def cancel_submission(
    submission_id: uuid.UUID, user: db_models.User = Depends(current_active_user), service: SubmissionService = Depends(get_submission_service)
):
    await service.cancel_submission(submission_id, user)
    return {"message": "Submission has been successfully cancelled."}

@router.post("/submissions/{submission_id}/remediate", status_code=status.HTTP_202_ACCEPTED, response_model=dict)
async def trigger_remediation(
    submission_id: uuid.UUID, remediation_request: api_models.RemediationRequest,
    user: db_models.User = Depends(current_active_user), service: SubmissionService = Depends(get_submission_service)
):
    await service.queue_remediation(submission_id, remediation_request, user, correlation_id_var.get())
    return {"message": "Remediation request accepted and queued for processing."}

@router.delete("/submissions/{submission_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_submission_record(
    submission_id: uuid.UUID, user: db_models.User = Depends(current_superuser), service: SubmissionService = Depends(get_submission_service)
):
    await service.delete_submission(submission_id)
    return Response(status_code=status.HTTP_204_NO_CONTENT)