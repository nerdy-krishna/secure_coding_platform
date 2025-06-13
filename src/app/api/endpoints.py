# src/app/api/endpoints.py
import logging
# Add Optional to the import from typing
from typing import List, Optional 

from fastapi import APIRouter, Depends, HTTPException, BackgroundTasks, status
from sqlalchemy.ext.asyncio import AsyncSession

from src.app.db import crud
from src.app.db.database import get_db_session
from src.app.utils.rabbitmq_utils import publish_to_rabbitmq
from . import models as api_models

from src.app.auth.core import current_active_user, current_superuser
from src.app.auth.models import User

logger = logging.getLogger(__name__)
router = APIRouter()

# --- Submission Endpoints ---

@router.post("/submit", response_model=api_models.SubmissionResponse, status_code=status.HTTP_202_ACCEPTED)
async def submit_code(
    submission_request: api_models.SubmissionRequest,
    background_tasks: BackgroundTasks,
    db: AsyncSession = Depends(get_db_session),
    user: User = Depends(current_active_user),
):
    """
    Accepts code submissions for analysis. This single endpoint handles both file and repository submissions.
    """
    if not submission_request.files and not submission_request.repo_url:
        raise HTTPException(status_code=400, detail="Either files or a repo_url must be provided.")

    try:
        submission = await crud.create_submission(db, user_id=user.id, repo_url=submission_request.repo_url)
        if submission_request.files:
            # Assuming add_files_to_submission is designed to handle this structure
            await crud.add_files_to_submission(db, submission.id, submission_request.files)

        background_tasks.add_task(publish_to_rabbitmq, submission.id)
        
        return {"submission_id": submission.id, "message": "Submission accepted for analysis."}
    except Exception as e:
        logger.error(f"Error during submission: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail="Failed to process submission.")

# --- Results and Status Endpoints ---

@router.get(
    "/submissions/{submission_id}/results",
    response_model=api_models.SubmissionResultResponse,
    summary="Get Analysis Results for a Submission",
)
async def get_analysis_results(
    submission_id: int,
    db: AsyncSession = Depends(get_db_session),
    user: User = Depends(current_active_user),
):
    """
    Retrieves the analysis results for a specific submission, including all findings and fixes.
    This endpoint is updated to use the new structured finding models.
    """
    submission = await crud.get_submission(db, submission_id)
    if not submission:
        raise HTTPException(status_code=404, detail="Submission not found")
    
    # Allow admin/superuser to view any submission
    if not user.is_superuser and submission.user_id != user.id:
         raise HTTPException(status_code=403, detail="Not authorized to view this submission")

    return submission


@router.get(
    "/submissions/{submission_id}/status",
    response_model=api_models.SubmissionStatus,
    summary="Get Submission Status"
)
async def get_submission_status(
    submission_id: int,
    db: AsyncSession = Depends(get_db_session),
    user: User = Depends(current_active_user),
):
    """Retrieves the current processing status of a submission."""
    submission = await crud.get_submission(db, submission_id)
    if not submission:
        raise HTTPException(status_code=404, detail="Submission not found")

    if not user.is_superuser and submission.user_id != user.id:
        raise HTTPException(status_code=403, detail="Not authorized to view this submission")

    return submission

# --- Admin & Management Endpoints ---

@router.get(
    "/admin/queries/",
    response_model=List[api_models.SecurityQueryResponse],
    dependencies=[Depends(current_superuser)],
    summary="List all security queries"
)
async def list_security_queries(db: AsyncSession = Depends(get_db_session)):
    """(Admin) Lists all saved Tree-sitter security queries."""
    logger.info("Placeholder: Admin requested list of security queries.")
    return []


@router.post(
    "/admin/queries/",
    response_model=api_models.SecurityQueryResponse,
    status_code=status.HTTP_201_CREATED,
    dependencies=[Depends(current_superuser)],
    summary="Create a new security query"
)
async def create_security_query(
    query_data: api_models.SecurityQueryCreate,
    db: AsyncSession = Depends(get_db_session)
):
    """(Admin) Creates a new Tree-sitter security query."""
    logger.info("Placeholder: Admin attempting to create a security query.")
    raise HTTPException(status_code=501, detail="Feature not yet implemented.")


@router.get(
    "/admin/dashboard/stats",
    response_model=api_models.DashboardStats,
    dependencies=[Depends(current_superuser)],
    summary="Get Dashboard Statistics"
)
async def get_dashboard_stats(db: AsyncSession = Depends(get_db_session)):
    """(Admin) Retrieves platform-wide statistics for the dashboard."""
    logger.info("Placeholder: Admin requested dashboard stats.")
    return api_models.DashboardStats(
        total_submissions=0,
        pending_submissions=0,
        completed_submissions=0,
        total_findings=0,
        high_severity_findings=0
    )


@router.get(
    "/admin/llm-interactions/",
    response_model=List[api_models.LLMInteractionResponse],
    dependencies=[Depends(current_superuser)],
    summary="List LLM Interactions"
)
async def list_llm_interactions(submission_id: Optional[int] = None, db: AsyncSession = Depends(get_db_session)):
    """(Admin) Lists recorded LLM interactions, optionally filtered by submission ID."""
    logger.info("Placeholder: Admin requested LLM interactions.")
    return []