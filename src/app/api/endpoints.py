# src/app/api/endpoints.py

import logging
import uuid
from typing import List, Optional, Annotated, Dict, Any

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
from app.core.config import settings # <-- ADDED THIS IMPORT

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

    if submission.status != "Pending Cost Approval":
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