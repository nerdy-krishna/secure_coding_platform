# src/app/graphs/api_graph.py
import logging
import json
import uuid  # For user_id type hint
from typing import TypedDict, Literal, Dict, Any, List, Optional

from fastapi.concurrency import (
    run_in_threadpool,
)  # For blocking I/O like RabbitMQ sync client
from langgraph.graph import StateGraph, END

# Database imports
from src.app.db.database import AsyncSessionLocal
from src.app.db.models import CodeSubmission, SubmittedFile
from src.app.api.models import CodeFile  # Pydantic model for input files

# RabbitMQ import
from src.app.utils.rabbitmq_utils import publish_to_rabbitmq, CODE_QUEUE

logger = logging.getLogger(__name__)


class ApiGraphState(TypedDict):
    """State for the API processing graph."""

    # Input from the API endpoint
    input_code: Optional[str]
    input_files: Optional[List[CodeFile]]  # List of Pydantic CodeFile models
    language: Optional[str]
    user_id: uuid.UUID  # User ID is mandatory

    # Intermediate state
    submission_id: Optional[int]
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
    primary_language = state.get("language")

    if state.get("input_files"):
        logger.info(f"Processing {len(state['input_files'])} input files.")
        for file_obj in state["input_files"]:
            # Basic validation (can be enhanced)
            if not file_obj.filename or not file_obj.content:
                return {
                    "db_error": "Invalid file data: filename and content are required."
                }
            files_to_save.append(
                {"filename": file_obj.filename, "content": file_obj.content}
            )
        if not primary_language and files_to_save:
            # Simple heuristic: use language of first file if not provided,
            # or enhance with detection later. For now, language is user-provided or None.
            pass
    elif state.get("input_code") and primary_language:
        logger.info("Processing single code snippet.")
        files_to_save.append(
            {"filename": f"snippet.{primary_language}", "content": state["input_code"]}
        )
    else:
        logger.error("No valid input (code+language or files) provided to API graph.")
        return {
            "db_error": "Invalid input: Must provide code with language or a list of files."
        }

    return {"files_to_save": files_to_save, "language": primary_language}


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

    message_payload = {"submission_id": submission_id}
    try:
        json_payload_string = json.dumps(message_payload)
        # Run synchronous pika publish in a threadpool to avoid blocking asyncio loop
        await run_in_threadpool(publish_to_rabbitmq, json_payload_string)
        logger.info(
            f"Successfully published submission_id {submission_id} to queue '{CODE_QUEUE}'."
        )
        return {
            "publish_error": None,
            "final_message": f"Submission {submission_id} accepted and queued for analysis.",
        }
    except json.JSONDecodeError as json_err:
        logger.error(f"Error serializing MQ payload: {json_err}", exc_info=True)
        return {
            "publish_error": "JSON serialization error for MQ.",
            "final_message": "Internal error with MQ.",
        }
    except Exception as e:  # Catch errors from publish_to_rabbitmq
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
        return END  # Using LangGraph's predefined END node name
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
