# src/app/db/crud.py
import logging
from typing import Optional, Any # Added Any for broader type hinting if needed later
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.future import select # For potential future generic 'get' operations

from .database import AsyncSessionLocal
from .models import LLMInteraction, CodeSubmission, AnalysisResult # Added other models for future use
from ..llm.providers import LLMResult # For type hinting LLMResult object

logger = logging.getLogger(__name__)

async def save_llm_interaction(
    submission_id: int,
    agent_name: str,
    prompt: str, # Changed from prompt_title to reflect usage in collated_code
    result: LLMResult, # Type hint using the imported LLMResult
    estimated_cost: Optional[float],
    status: str,
    prompt_title: Optional[str] = None, # Added optional prompt_title
    interaction_context: Optional[Dict[str, Any]] = None, # Added optional context
    error_message: Optional[str] = None,
) -> Optional[LLMInteraction]: # Return the created object or None
    """
    Saves the details of an LLM interaction to the database.
    """
    interaction_data = LLMInteraction(
        submission_id=submission_id,
        agent_name=agent_name,
        prompt_title=prompt_title, # Use the new parameter
        input_prompt=prompt, # Kept as input_prompt for the main prompt text
        output_response=result.content,
        input_tokens=result.input_tokens,
        output_tokens=result.output_tokens,
        total_tokens=result.total_tokens,
        model_name=result.model_name,
        latency_ms=result.latency_ms,
        estimated_cost=estimated_cost,
        status=status,
        interaction_context=interaction_context, # Use the new parameter
        error_message=error_message or result.error, # Use the error_message param first
    )
    try:
        async with AsyncSessionLocal() as session:
            async with session.begin():
                session.add(interaction_data)
            await session.refresh(interaction_data) # Refresh to get ID and other defaults
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

# Placeholder for a generic 'get_submission_by_id' - we can implement fully when needed
async def get_submission_by_id(db: AsyncSessionLocal, submission_id: int) -> Optional[CodeSubmission]:
    """
    Retrieves a CodeSubmission by its ID.
    (This is a basic 'get' operation, can be expanded later)
    """
    try:
        async with db() as session: # Corrected: Call AsyncSessionLocal to get a session
            result = await session.execute(
                select(CodeSubmission).filter(CodeSubmission.id == submission_id)
            )
            return result.scalar_one_or_none()
    except SQLAlchemyError as e:
        logger.error(f"Database error getting submission by ID {submission_id}: {e}", exc_info=True)
        return None

# We can add more CRUD functions here as our application grows, for example:
# async def create_code_submission(...) -> CodeSubmission: ...
# async def get_analysis_result(...) -> AnalysisResult: ...
# async def update_analysis_result_status(...): ...