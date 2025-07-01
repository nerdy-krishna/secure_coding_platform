# src/app/infrastructure/workflows/api_graph.py
import logging
import uuid  # For user_id type hint
from typing import TypedDict, Literal, Dict, Any, List, Optional

from fastapi.concurrency import (
    run_in_threadpool,
)  # For blocking I/O like RabbitMQ sync client
from langgraph.graph import StateGraph, END

# Database imports
from app.infrastructure.database import AsyncSessionLocal
from app.infrastructure.database.models import CodeSubmission, SubmittedFile
from app.api.v1.models import CodeFile
from app.config.config import settings

# RabbitMQ import
from app.infrastructure.messaging.publisher import publish_submission

logger = logging.getLogger(__name__)


class ApiGraphState(TypedDict):
    """State for the API processing graph."""

    # Input from the API endpoint
    input_code: Optional[str]
    input_files: Optional[List[CodeFile]]  # List of Pydantic CodeFile models
    language: Optional[str]
    user_id: uuid.UUID  # User ID is mandatory

    # Intermediate state
    submission_id: Optional[uuid.UUID]  # Changed from int to uuid.UUID
    db_error: Optional[str]
    publish_error: Optional[str]
    final_message: Optional[str]

    # For multi-file submissions, this can hold structured data
    files_to_save: Optional[List[Dict[str, str]]]


async def prepare_and_validate_input_node(state: ApiGraphState) -> Dict[str, Any]:
    logger.info(
        f"API Graph Node: prepare_and_validate_input_node for user {state['user_id']}"
    )
    files_to_save: List[Dict[str, str]] = []

    # Get optional values from state more explicitly for type checking
    input_code_val = state.get("input_code")
    primary_language_val = state.get("language")
    input_files_list = state.get("input_files")

    if input_files_list:
        logger.info(f"Processing {len(input_files_list)} input files.")
        for file_obj in input_files_list:
            file_name = file_obj.filename
            file_content = file_obj.content
            # Basic validation (can be enhanced)
            if not file_name or not file_content:  # Check for None or empty string
                return {
                    "db_error": "Invalid file data: filename and content are required."
                }
            # At this point, file_name and file_content are known to be non-empty strings.
            files_to_save.append({"filename": file_name, "content": file_content})
        # If primary language wasn't provided alongside files, primary_language_val remains None.
        # The 'if not primary_language_val and files_to_save:' block handles this scenario.
        if not primary_language_val and files_to_save:
            # Simple heuristic: use language of first file if not provided,
            # or enhance with detection later. For now, language is user-provided or None.
            pass
    elif input_code_val and primary_language_val:
        logger.info("Processing single code snippet.")
        # Both input_code_val and primary_language_val are confirmed str here by the condition
        files_to_save.append(
            {"filename": f"snippet.{primary_language_val}", "content": input_code_val}
        )
    else:
        logger.error("No valid input (code+language or files) provided to API graph.")
        return {
            "db_error": "Invalid input: Must provide code with language or a list of files."
        }

    return {"files_to_save": files_to_save, "language": primary_language_val}


async def save_submission_to_db_node(state: ApiGraphState) -> Dict[str, Any]:
    logger.info(
        f"API Graph Node: save_submission_to_db_node for user {state['user_id']}"
    )
    user_id = state["user_id"]
    primary_language = state.get("language")
    files_to_save = state.get("files_to_save")

    if not files_to_save:
        logger.error("No files to save in DB submission node.")
        return {"db_error": "No file data prepared for saving.", "submission_id": None}

    async with AsyncSessionLocal() as session:
        async with session.begin():
            try:
                new_submission = CodeSubmission(
                    user_id=user_id,
                    primary_language=primary_language,
                    # selected_frameworks can be added later from API payload
                )
                session.add(new_submission)
                await session.flush()  # To get new_submission.id

                for file_data in files_to_save:
                    db_file = SubmittedFile(
                        submission_id=new_submission.id,
                        filename=file_data["filename"],
                        content=file_data["content"],
                        # detected_language can be added later
                    )
                    session.add(db_file)

                await session.commit()
                logger.info(
                    f"Successfully saved CodeSubmission {new_submission.id} and associated files to DB."
                )
                return {"submission_id": new_submission.id, "db_error": None}
            except Exception as e:
                await session.rollback()
                logger.error(f"Error saving submission to DB: {e}", exc_info=True)
                return {
                    "db_error": f"Database save failed: {str(e)}",
                    "submission_id": None,
                }


async def publish_to_mq_node(state: ApiGraphState) -> Dict[str, Any]:
    logger.info(
        f"API Graph Node: publish_to_mq_node for submission_id {state.get('submission_id')}"
    )
    submission_id = state.get("submission_id")
    if submission_id is None:
        logger.error("Cannot publish to MQ: submission_id is missing.")
        return {
            "publish_error": "Submission ID missing, cannot queue for analysis.",
            "final_message": "Internal error: Submission ID not available for MQ.",
        }

    try:
        # The publish_submission function now correctly uses the new setting internally.
        # We just need to update the log message here for accurate reporting.
        await run_in_threadpool(publish_submission, str(submission_id))

        # Use the new, correct setting name for the log message
        queue_name = settings.RABBITMQ_SUBMISSION_QUEUE
        logger.info(
            f"Successfully published submission_id {submission_id} to queue '{queue_name}'."
        )
        return {
            "publish_error": None,
            "final_message": f"Submission {submission_id} accepted and queued for analysis.",
        }
    except Exception as e:
        logger.error(
            f"Error publishing submission_id {submission_id} to MQ: {e}", exc_info=True
        )
        return {
            "publish_error": str(e),
            "final_message": f"Failed to queue submission: {e}",
        }


# Conditional Edges
def route_after_db_save(state: ApiGraphState) -> Literal["publish_to_mq", "__end__"]:
    if state.get("db_error") or state.get("submission_id") is None:
        logger.error(
            f"Routing to END after DB save due to error or no submission_id. DB Error: {state.get('db_error')}"
        )
        # Populate final_message if not already set by an error node
        if not state.get("final_message"):
            state["final_message"] = "Failed to save submission to database."
        return "__end__"  # Explicitly return the string literal for __end__
    logger.info("DB save successful, routing to publish_to_mq.")
    return "publish_to_mq"


def build_api_graph() -> Any:
    workflow = StateGraph(ApiGraphState)
    workflow.add_node("prepare_input", prepare_and_validate_input_node)
    workflow.add_node("save_to_db", save_submission_to_db_node)
    workflow.add_node("publish_to_mq", publish_to_mq_node)

    workflow.set_entry_point("prepare_input")
    workflow.add_edge("prepare_input", "save_to_db")

    workflow.add_conditional_edges(
        "save_to_db",
        route_after_db_save,
        {
            "publish_to_mq": "publish_to_mq",
            "__end__": END,  # Route to END if DB save fails
        },
    )
    # If MQ publish fails, it sets publish_error and final_message, then ends.
    workflow.add_edge("publish_to_mq", END)

    app_graph = workflow.compile()
    logger.info("API processing graph compiled.")
    return app_graph


api_workflow = build_api_graph()
