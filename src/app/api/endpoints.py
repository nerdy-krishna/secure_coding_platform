# src/app/api/endpoints.py
import logging
from fastapi import APIRouter, HTTPException, status, Depends
from typing import Optional  # Added Any

# SQLAlchemy Imports
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select

# Pydantic models from our local api.models
from .models import CodeInput, AnalysisResultResponse
# We might need SubmissionHistoryResponse, SubmissionHistoryItem later from .models

# DB ORM Models
from src.app.db.models import CodeSubmission, AnalysisResult
from src.app.auth.models import User  # User model from auth.models

# DB Session and Auth dependencies
from src.app.db.database import get_db_session
from src.app.auth.core import current_active_user

# API Graph import
from src.app.graphs.api_graph import api_workflow, ApiGraphState

logger = logging.getLogger(__name__)
router = APIRouter()


@router.post(
    "/analyze",
    status_code=status.HTTP_202_ACCEPTED,
    summary="Submit code for analysis",
    response_description="Submission accepted for processing, returns submission ID.",
)
async def analyze_code_submission(
    payload: CodeInput,
    user: User = Depends(current_active_user),  # Require authenticated user
):
    logger.info(
        f"Received /analyze request from user ID: {user.id}. Language hint: {payload.language}"
    )

    initial_state = ApiGraphState(
        input_code=payload.code,
        input_files=payload.files,
        language=payload.language,
        user_id=user.id,  # Pass the authenticated user's ID
        # Initialize other state fields to None or default
        submission_id=None,
        db_error=None,
        publish_error=None,
        final_message=None,
        files_to_save=None,
    )

    try:
        logger.debug(
            f"Invoking API graph workflow with initial state for user {user.id}."
        )
        final_state = await api_workflow.ainvoke(initial_state)
        logger.info(
            f"API graph workflow completed for user {user.id}. Final state message: {final_state.get('final_message')}"
        )

        if final_state.get("db_error"):
            logger.error(f"DB error from API graph: {final_state['db_error']}")
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail=final_state.get("final_message")
                or "Database operation failed during submission.",
            )

        if final_state.get("publish_error"):
            logger.error(
                f"MQ publish error from API graph: {final_state['publish_error']}"
            )
            # Note: The submission might be in DB but not queued.
            # Decide on response: Could be 500, or 207 Multi-Status with details.
            # For now, let's treat it as a server-side issue for the queueing part.
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail=final_state.get("final_message")
                or "Failed to queue submission for analysis.",
            )

        submission_id = final_state.get("submission_id")
        if submission_id is not None:
            return {
                "message": final_state.get(
                    "final_message", "Submission accepted and queued."
                ),
                "submission_id": submission_id,
            }
        else:
            # This case should ideally be covered by db_error or publish_error
            logger.error(
                f"API graph completed without submission_id and no explicit error for user {user.id}."
            )
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Submission processing failed to yield a submission ID.",
            )

    except HTTPException:  # Re-raise HTTPExceptions directly
        raise
    except Exception as e:
        logger.error(
            f"Unexpected error during /analyze endpoint for user {user.id}: {e}",
            exc_info=True,
        )
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An unexpected error occurred while processing your submission.",
        )


@router.get(
    "/results/{submission_id}",
    response_model=AnalysisResultResponse,
    summary="Get analysis results for a specific submission",
    response_description="The analysis result object or error if not found/authorized.",
)
async def get_analysis_results(
    submission_id: int,
    db: AsyncSession = Depends(get_db_session),
    user: User = Depends(current_active_user),  # Require authenticated user
):
    logger.info(f"User {user.id} requesting results for submission ID: {submission_id}")

    # First, verify the submission belongs to the user
    submission_check_stmt = select(CodeSubmission.id).where(
        CodeSubmission.id == submission_id,
        CodeSubmission.user_id == user.id,  # Ensure user owns the submission
    )
    submission_owner_check = await db.execute(submission_check_stmt)
    if submission_owner_check.scalar_one_or_none() is None:
        logger.warning(
            f"User {user.id} attempted to access unauthorized or non-existent submission {submission_id}."
        )
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,  # Or 403 Forbidden if you want to distinguish
            detail=f"Submission ID {submission_id} not found or not accessible.",
        )

    # Fetch the analysis result
    stmt = select(AnalysisResult).where(AnalysisResult.submission_id == submission_id)
    result = await db.execute(stmt)
    analysis_result: Optional[AnalysisResult] = result.scalar_one_or_none()

    if analysis_result is None:
        # If submission exists but result doesn't, it might still be processing
        logger.info(
            f"Analysis result not yet available for submission ID: {submission_id} (owned by user {user.id})."
        )
        # You could return a 202 Accepted or a specific message indicating processing.
        # For now, let's treat "not found" as strictly for the AnalysisResult object.
        # A more advanced version might check CodeSubmission status.
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Analysis result not found for submission ID {submission_id}. It may still be processing or encountered an issue.",
        )

    logger.info(
        f"Returning analysis result for submission ID: {submission_id} to user {user.id}."
    )
    # Pydantic will serialize analysis_result to AnalysisResultResponse
    # Ensure your AnalysisResult ORM model and AnalysisResultResponse Pydantic model align
    # particularly with how 'original_code_snapshot' and 'fixed_code_snapshot' are handled.
    # If they are stored as JSON strings in DB, and response model expects dict,
    # you might need a pre-serialization step or a Pydantic validator.
    # For now, assuming direct compatibility or that Pydantic handles JSON string to dict.
    return analysis_result


@router.get("/ping", tags=["Health"])
async def ping():
    """A simple ping endpoint to confirm the API router is working."""
    return {"ping": "pong!"}
