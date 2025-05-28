import logging
import datetime
from typing import Optional, Any, Dict, List  # Added Dict, List can also be useful
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.future import select

from .database import AsyncSessionLocal
from .models import (
    LLMInteraction,
    CodeSubmission,
    AnalysisResult,
    SubmittedFile,
)
from ..llm.providers import LLMResult

logger = logging.getLogger(__name__)


async def save_llm_interaction(
    submission_id: int,
    agent_name: str,
    prompt: str,
    result: LLMResult,
    estimated_cost: Optional[float],
    status: str,
    prompt_title: Optional[str] = None,
    interaction_context: Optional[Dict[str, Any]] = None,
    error_message: Optional[str] = None,
) -> Optional[LLMInteraction]:
    """
    Saves the details of an LLM interaction to the database.
    """
    interaction_data = LLMInteraction(
        submission_id=submission_id,
        agent_name=agent_name,
        prompt_title=prompt_title,
        input_prompt=prompt,
        output_response=result.content,
        input_tokens=result.input_tokens,
        output_tokens=result.output_tokens,
        total_tokens=result.total_tokens,
        model_name=result.model_name,
        latency_ms=result.latency_ms,
        estimated_cost=estimated_cost,
        status=status,
        interaction_context=interaction_context,
        error_message=error_message or result.error,
    )
    try:
        async with AsyncSessionLocal() as session:
            async with session.begin():
                session.add(interaction_data)
            # Refresh to get ID and other database-generated defaults like timestamp
            await session.refresh(interaction_data)
            logger.info(
                f"Saved LLM interaction for sub_id={submission_id}, agent={agent_name}, interaction_id={interaction_data.id}"
            )
            return interaction_data
    except SQLAlchemyError as db_exc:
        logger.error(
            f"Database error saving LLM interaction for sub_id={submission_id}, agent={agent_name}: {db_exc}",
            exc_info=True,
        )
        return None
    except Exception as e:
        logger.error(
            f"Unexpected error saving LLM interaction for sub_id={submission_id}, agent={agent_name}: {e}",
            exc_info=True,
        )
        return None


async def get_submission_by_id(submission_id: int) -> Optional[CodeSubmission]:
    """
    Retrieves a CodeSubmission by its ID along with its related files.
    """
    try:
        async with AsyncSessionLocal() as session:
            # Using selectinload to eager load related files to avoid separate queries
            # This requires defining the relationship in CodeSubmission model correctly.
            # For now, a simple select. If 'files' relationship is properly configured:
            # from sqlalchemy.orm import selectinload
            # stmt = select(CodeSubmission).options(selectinload(CodeSubmission.files)).filter(CodeSubmission.id == submission_id)

            stmt = select(CodeSubmission).filter(CodeSubmission.id == submission_id)
            result = await session.execute(stmt)
            submission = result.scalar_one_or_none()
            if submission:
                logger.debug(f"Retrieved submission {submission_id} from database.")
            else:
                logger.debug(f"Submission {submission_id} not found in database.")
            return submission
    except SQLAlchemyError as e:
        logger.error(
            f"Database error getting submission by ID {submission_id}: {e}",
            exc_info=True,
        )
        return None
    except Exception as e:  # Catch any other unexpected errors
        logger.error(
            f"Unexpected error getting submission by ID {submission_id}: {e}",
            exc_info=True,
        )
        return None


async def get_files_for_submission(submission_id: int) -> List[Dict[str, Any]]:
    """
    Retrieves all files associated with a given submission_id.
    Returns a list of dictionaries, each containing filename, content, and detected_language.
    """
    files_data: List[Dict[str, Any]] = []
    try:
        async with AsyncSessionLocal() as session:
            stmt = select(SubmittedFile).filter(
                SubmittedFile.submission_id == submission_id
            )
            result = await session.execute(stmt)
            submitted_files = result.scalars().all()

            for file_obj in submitted_files:
                files_data.append(
                    {
                        "filename": file_obj.filename,
                        "content": file_obj.content,
                        "detected_language": file_obj.detected_language,
                    }
                )
            logger.debug(
                f"Retrieved {len(files_data)} files for submission_id {submission_id}."
            )
    except SQLAlchemyError as e:
        logger.error(
            f"Database error getting files for submission {submission_id}: {e}",
            exc_info=True,
        )
        # Depending on desired behavior, you might re-raise or return empty list with error state
    except Exception as e:
        logger.error(
            f"Unexpected error getting files for submission {submission_id}: {e}",
            exc_info=True,
        )
    return files_data


async def get_analysis_result_by_submission_id(
    submission_id: int,
) -> Optional[AnalysisResult]:
    """
    Retrieves an AnalysisResult by its submission_id.
    """
    try:
        async with AsyncSessionLocal() as session:
            stmt = select(AnalysisResult).filter(
                AnalysisResult.submission_id == submission_id
            )
            result = await session.execute(stmt)
            analysis_result = result.scalar_one_or_none()
            if analysis_result:
                logger.debug(
                    f"Retrieved analysis result for submission_id {submission_id}."
                )
            else:
                logger.debug(
                    f"Analysis result for submission_id {submission_id} not found."
                )
            return analysis_result
    except SQLAlchemyError as e:
        logger.error(
            f"Database error getting analysis result for submission_id {submission_id}: {e}",
            exc_info=True,
        )
        return None
    except Exception as e:
        logger.error(
            f"Unexpected error getting analysis result for submission_id {submission_id}: {e}",
            exc_info=True,
        )
        return None


async def create_or_update_analysis_result(
    submission_id: int,
    report_content: Optional[Dict[str, Any]],
    original_code_snapshot_json: Optional[str],  # Expecting JSON string
    fixed_code_snapshot_json: Optional[str],  # Expecting JSON string
    sarif_report_json: Optional[Dict[str, Any]],  # Expecting dict for JSONB
    status: str,
    error_message: Optional[str] = None,
) -> Optional[AnalysisResult]:
    """
    Creates a new AnalysisResult or updates an existing one for a given submission_id.
    """
    try:
        async with AsyncSessionLocal() as session:
            async with session.begin():
                stmt = select(AnalysisResult).filter(
                    AnalysisResult.submission_id == submission_id
                )
                result = await session.execute(stmt)
                db_result = result.scalar_one_or_none()

                if db_result:
                    logger.info(
                        f"Updating existing AnalysisResult for submission_id {submission_id}"
                    )
                    db_result.report_content = report_content
                    db_result.original_code_snapshot = original_code_snapshot_json
                    db_result.fixed_code_snapshot = fixed_code_snapshot_json
                    db_result.sarif_report = sarif_report_json
                    db_result.status = status
                    db_result.error_message = error_message
                    db_result.completed_at = datetime.datetime.now(
                        datetime.timezone.utc
                    )
                else:
                    logger.info(
                        f"Creating new AnalysisResult for submission_id {submission_id}"
                    )
                    db_result = AnalysisResult(
                        submission_id=submission_id,
                        report_content=report_content,
                        original_code_snapshot=original_code_snapshot_json,
                        fixed_code_snapshot=fixed_code_snapshot_json,
                        sarif_report=sarif_report_json,
                        status=status,
                        error_message=error_message,
                        completed_at=datetime.datetime.now(
                            datetime.timezone.utc
                        ),  # Ensure completed_at is set
                    )
                    session.add(db_result)
            await session.refresh(db_result)
            logger.info(
                f"Successfully saved AnalysisResult for submission_id {submission_id} with status '{status}'."
            )
            return db_result
    except SQLAlchemyError as db_exc:
        logger.error(
            f"Database error saving AnalysisResult for submission_id {submission_id}: {db_exc}",
            exc_info=True,
        )
        return None
    except Exception as e:
        logger.error(
            f"Unexpected error saving AnalysisResult for submission_id {submission_id}: {e}",
            exc_info=True,
        )
        return None


# Note: The `get_submission_by_id` function had `db: AsyncSessionLocal` as a parameter.
# This is unusual for CRUD functions that manage their own sessions internally using `async with AsyncSessionLocal() as session:`.
# I've removed it from `get_submission_by_id` and made it consistent with `save_llm_interaction`.
# If you intend to pass an active session for transaction control, the pattern would be different.
# For now, all functions manage their own session from AsyncSessionLocal.
# I've also added a few more CRUD function placeholders/examples based on your models.
