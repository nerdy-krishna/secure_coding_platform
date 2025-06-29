# src/app/workers/consumer.py

import pika
import os
import logging
import logging.config
import asyncio
import json
import threading
import time  # For sleep in retry logic and initial loop spin-up
from typing import Callable, Optional

from langchain_core.runnables import RunnableConfig  # Added import
import uuid  # Import uuid
from dotenv import load_dotenv

# Import the worker graph and its state
from app.infrastructure.workflows.worker_graph import (
    get_workflow,
    WorkerState,
    close_workflow_resources,
)
from app.config.config import settings

# Import the new logging config and context variable
from app.config.logging_config import LOGGING_CONFIG, correlation_id_var

# Ensure necessary imports for type hints used in this file
from pika.adapters.blocking_connection import BlockingChannel  # For Pika channel type
from pika.spec import (
    BasicProperties,
    Basic,
)  # For Pika message properties and delivery info (Basic.Deliver)
from pika.exceptions import AMQPConnectionError  # For specific Pika exception handling

logging.basicConfig(
    level=logging.INFO,  # Lower to DEBUG for more verbose output from this module
    format="%(asctime)s - %(levelname)-7s - [%(threadName)s] %(name)s (%(module)s.%(funcName)s:%(lineno)d) - %(message)s",
)
logger = logging.getLogger(
    __name__
)  # Gets logger for current module __main__ if run directly

# Apply the logging configuration at the start of the worker process
logging.config.dictConfig(LOGGING_CONFIG)

logging.getLogger("pika").setLevel(logging.WARNING)
# You can add more libraries here if needed, e.g.:
# logging.getLogger("aio_pika").setLevel(logging.WARNING) # If you use aio_pika directly and it's noisy
# logging.getLogger("sqlalchemy.engine").setLevel(logging.WARNING) # To quiet SQLAlchemy engine logs

load_dotenv()

RABBITMQ_HOST = os.getenv("RABBITMQ_HOST", "rabbitmq")
RABBITMQ_PORT = os.getenv("RABBITMQ_PORT_DOCKER", "5672")
RABBITMQ_USER = os.getenv("RABBITMQ_DEFAULT_USER", "devuser_scp")
RABBITMQ_PASS = os.getenv("RABBITMQ_DEFAULT_PASS", "YourStrongRabbitPassword!")

_async_loop: Optional[asyncio.AbstractEventLoop] = None
_event_loop_thread: Optional[threading.Thread] = None
_pika_connection: Optional[pika.BlockingConnection] = None
_pika_channel: Optional[BlockingChannel] = None  # Changed to BlockingChannel

_stop_event = threading.Event()  # For signaling threads to stop

# WorkerGraphState TypedDict is removed as we will use CoordinatorState directly.

# --- Asyncio Task Execution ---


async def run_graph_task_wrapper(initial_state: WorkerState, delivery_tag: int):
    """
    Gets the compiled workflow and executes it with a checkpointer configuration.
    """
    global _pika_channel, _pika_connection
    submission_id_uuid = initial_state["submission_id"]
    submission_id_str_log = str(submission_id_uuid)
    logger.info(
        f"ASYNC WRAPPER: Starting/Resuming worker_workflow for submission_id: {submission_id_str_log}"
    )

    success = False

    try:
        # Get the compiled workflow instance asynchronously. This will now work.
        worker_workflow = await get_workflow()

        # The checkpointer uses this thread_id to save/load the state
        config: RunnableConfig = {"configurable": {"thread_id": submission_id_str_log}}

        final_graph_state = await worker_workflow.ainvoke(initial_state, config)

        logger.info(
            f"ASYNC WRAPPER: worker_workflow completed for SID: {submission_id_str_log}."
        )

        if final_graph_state and not final_graph_state.get("error_message"):
            success = True
        else:
            error_msg = (
                final_graph_state.get("error_message", "Unknown error")
                if final_graph_state
                else "Workflow returned no state"
            )
            logger.error(f"ASYNC WRAPPER: Graph processing failed. Error: {error_msg}")
            success = False

    except Exception as e:
        logger.error(
            f"ASYNC WRAPPER: Exception during worker_workflow invocation: {e}",
            exc_info=True,
        )
        success = False

    if _pika_connection and _pika_connection.is_open:

        def pika_finalize_message():
            try:
                if success:
                    if _pika_channel and _pika_channel.is_open:
                        _pika_channel.basic_ack(delivery_tag=delivery_tag)
                else:
                    if _pika_channel and _pika_channel.is_open:
                        _pika_channel.basic_nack(
                            delivery_tag=delivery_tag, requeue=False
                        )
            except Exception as e_pika_finalize:
                logger.error(
                    f"PIKA FINALIZE: Exception for SID {submission_id_str_log}: {e_pika_finalize}",
                    exc_info=True,
                )

        _pika_connection.add_callback_threadsafe(pika_finalize_message)


def schedule_task_on_async_loop(target_coroutine_func: Callable, *args, **kwargs):
    """
    Schedules a target coroutine function to be run on the asyncio event loop.
    The target_coroutine_func will be wrapped with asyncio.create_task.
    """
    global _async_loop
    if _async_loop and _async_loop.is_running():
        # Wrapper to call create_task from within the loop's thread
        def _scheduler():
            asyncio.create_task(target_coroutine_func(*args, **kwargs))
            logger.debug(
                f"ASYNC SCHEDULER (via _scheduler): Task created for {target_coroutine_func.__name__}"
            )

        _async_loop.call_soon_threadsafe(_scheduler)
        logger.info(
            f"ASYNC SCHEDULER: Task for {target_coroutine_func.__name__} scheduled via call_soon_threadsafe."
        )
    else:
        logger.error(
            f"ASYNC SCHEDULER: Asyncio loop not available/running. Task for {target_coroutine_func.__name__} not scheduled."
        )


# In src/app/workers/consumer.py
# Replace your existing pika_message_callback function with this correct version


def pika_message_callback(
    ch: BlockingChannel,
    method: Basic.Deliver,
    properties: BasicProperties,
    body: bytes,
):
    """Pika callback for received messages from all queues."""
    try:
        message_data = json.loads(body.decode("utf-8"))
        submission_id_str = message_data.get("submission_id")

        # --- START: CORRELATION ID HANDLING ---
        # Extract correlation_id from the message, or create a new one if missing
        corr_id = message_data.get("correlation_id") or str(uuid.uuid4())
        # Set it in the context variable for all subsequent logs in this task
        correlation_id_var.set(corr_id)
        # --- END: CORRELATION ID HANDLING ---

        logger.info(
            f"PIKA CB: Received message from queue '{method.routing_key}'. Delivery Tag: {method.delivery_tag}."
        )

        if not submission_id_str:
            logger.error("PIKA CB: Invalid message - no submission_id.")
            ch.basic_nack(delivery_tag=method.delivery_tag, requeue=False)
            return

        submission_uuid = uuid.UUID(submission_id_str)

        # FIX: Explicitly initialize the full state with default values to satisfy Pylance
        initial_worker_state: WorkerState = {
            "submission_id": submission_uuid,
            "llm_config_id": None,
            "files": None,
            "workflow_mode": "audit",  # This will be overridden below
            "excluded_files": None,
            "remediation_categories": None,  # Initialize new field
            "repository_map": None,
            "asvs_analysis": None,
            "findings": [],
            "impact_report": None,
            "sarif_report": None,
            "error_message": None,
            "current_submission_status": None,
        }

        # --- UPDATED ROUTING LOGIC ---
        queue_name = method.routing_key
        if queue_name == settings.RABBITMQ_REMEDIATION_QUEUE:
            logger.info(
                f"PIKA CB: Received REMEDIATION trigger for submission_id: {submission_uuid}"
            )
            initial_worker_state["workflow_mode"] = "remediate"
            # Extract categories from message, default to empty list if not present
            initial_worker_state["remediation_categories"] = message_data.get(
                "categories_to_fix", []
            )
        elif queue_name == settings.RABBITMQ_APPROVAL_QUEUE:
            logger.info(
                f"PIKA CB: Resuming ANALYSIS for submission_id: {submission_uuid}"
            )
            # This is for resuming an audit, so workflow_mode can remain 'audit'
            # Or be set explicitly depending on desired resume logic. Let's assume it resumes the audit.
            initial_worker_state["workflow_mode"] = "audit"
        else:  # RABBITMQ_SUBMISSION_QUEUE
            logger.info(
                f"PIKA CB: Starting new ANALYSIS for submission_id: {submission_uuid}"
            )
            initial_worker_state["workflow_mode"] = "audit"

        schedule_task_on_async_loop(
            run_graph_task_wrapper, initial_worker_state, method.delivery_tag
        )

    except (json.JSONDecodeError, ValueError) as e:
        logger.error(
            f"PIKA CB: Failed to parse message body or UUID: {e}", exc_info=True
        )
        ch.basic_nack(delivery_tag=method.delivery_tag, requeue=False)


def asyncio_thread_worker_target():
    """Target function for the thread that runs the asyncio event loop."""
    global _async_loop
    _async_loop = asyncio.new_event_loop()
    asyncio.set_event_loop(_async_loop)
    logger.info("ASYNCIO THREAD: Event loop created and set for this thread.")
    try:
        logger.info("ASYNCIO THREAD: Starting loop.run_forever().")
        _async_loop.run_forever()  # Loop runs until loop.stop() is called
    except KeyboardInterrupt:
        logger.info(
            "ASYNCIO THREAD: KeyboardInterrupt received in asyncio thread (should be handled by main Pika thread)."
        )
    finally:
        logger.info("ASYNCIO THREAD: loop.run_forever() exited.")
        # Gracefully shutdown any remaining tasks
        if (
            _async_loop.is_running()
        ):  # Should be false if stop() was called and processed
            logger.warning(
                "ASYNCIO THREAD: Loop still shows as running after run_forever exited; attempting to stop again."
            )
            _async_loop.call_soon_threadsafe(
                _async_loop.stop
            )  # Should have been called already

        try:
            logger.info("ASYNCIO THREAD: Cleaning up remaining tasks...")
            all_tasks = asyncio.all_tasks(loop=_async_loop)
            # Filter out the current task if it's part of all_tasks to avoid self-cancellation issues
            current_task = asyncio.current_task(loop=_async_loop)
            tasks_to_cancel = [t for t in all_tasks if t is not current_task]

            if tasks_to_cancel:
                logger.info(
                    f"ASYNCIO THREAD: Cancelling {len(tasks_to_cancel)} outstanding tasks."
                )
                for task in tasks_to_cancel:
                    task.cancel()
                # Wait for tasks to cancel
                _async_loop.run_until_complete(
                    asyncio.gather(*tasks_to_cancel, return_exceptions=True)
                )
                logger.info("ASYNCIO THREAD: Outstanding tasks cancelled.")
            else:
                logger.info("ASYNCIO THREAD: No outstanding tasks to cancel.")
        except Exception as e_shutdown:
            logger.error(
                f"ASYNCIO THREAD: Error during task cleanup on shutdown: {e_shutdown}",
                exc_info=True,
            )

        if not _async_loop.is_closed():
            _async_loop.close()
        logger.info("ASYNCIO THREAD: Event loop closed. Thread exiting.")


# In src/app/workers/consumer.py


def start_worker_consumer():
    global _event_loop_thread, _async_loop, _pika_connection, _pika_channel, _stop_event
    _stop_event.clear()

    if not (_event_loop_thread and _event_loop_thread.is_alive()):
        _event_loop_thread = threading.Thread(
            target=asyncio_thread_worker_target,
            name="AsyncioEventLoopThread",
            daemon=True,
        )
        _event_loop_thread.start()
        logger.info("WORKER: Started asyncio event loop manager thread.")
        time.sleep(1)
    else:
        logger.info("WORKER: Asyncio event loop manager thread already running.")

    retry_delay = 5
    while not _stop_event.is_set():
        try:
            logger.info("WORKER: Attempting RabbitMQ connection...")
            if not settings.RABBITMQ_URL:
                raise ValueError("RABBITMQ_URL not set in settings.")

            parameters = pika.URLParameters(settings.RABBITMQ_URL)
            _pika_connection = pika.BlockingConnection(parameters)
            _pika_channel = _pika_connection.channel()
            logger.info("WORKER: RabbitMQ connection successful.")

            submission_queue = settings.RABBITMQ_SUBMISSION_QUEUE
            approval_queue = settings.RABBITMQ_APPROVAL_QUEUE
            remediation_queue = settings.RABBITMQ_REMEDIATION_QUEUE

            _pika_channel.queue_declare(queue=submission_queue, durable=True)
            _pika_channel.queue_declare(queue=approval_queue, durable=True)
            _pika_channel.queue_declare(queue=remediation_queue, durable=True)
            _pika_channel.basic_qos(prefetch_count=1)

            _pika_channel.basic_consume(
                queue=submission_queue, on_message_callback=pika_message_callback
            )
            _pika_channel.basic_consume(
                queue=approval_queue, on_message_callback=pika_message_callback
            )
            _pika_channel.basic_consume(
                queue=remediation_queue, on_message_callback=pika_message_callback
            )

            logger.info("WORKER: Waiting for messages...")
            _pika_channel.start_consuming()

        except AMQPConnectionError as conn_err:
            logger.error(f"WORKER: RabbitMQ connection error: {conn_err}.")
        except KeyboardInterrupt:
            logger.info("WORKER: KeyboardInterrupt received. Shutting down consumer.")
            _stop_event.set()
        except Exception as e:
            logger.error(
                f"WORKER: Unexpected error in main Pika consumer loop: {e}",
                exc_info=True,
            )
        finally:
            if _pika_connection and _pika_connection.is_open:
                _pika_connection.close()
            logger.info("WORKER: Pika connection closed for this iteration.")

        if _stop_event.is_set():
            break
        time.sleep(retry_delay)

    # --- FINAL SHUTDOWN LOGIC ---
    logger.info("WORKER: Finalizing shutdown...")
    if _async_loop and _async_loop.is_running():
        logger.info("WORKER: Closing workflow resources...")
        # Schedule the resource cleanup in the async loop
        future = asyncio.run_coroutine_threadsafe(
            close_workflow_resources(), _async_loop
        )
        try:
            future.result(timeout=5)  # Wait for cleanup to finish
        except Exception as e:
            logger.error(f"WORKER: Error during workflow resource cleanup: {e}")

        logger.info("WORKER: Signaling asyncio loop to stop.")
        _async_loop.call_soon_threadsafe(_async_loop.stop)

    if _event_loop_thread and _event_loop_thread.is_alive():
        logger.info("WORKER: Waiting for asyncio event loop thread to join...")
        _event_loop_thread.join(timeout=5)
        if _event_loop_thread.is_alive():
            logger.warning("WORKER: Asyncio event loop thread did not join in time.")

    logger.info("WORKER: Consumer has fully shut down.")


if __name__ == "__main__":
    logger.info("Starting RabbitMQ worker consumer script (__main__)...")
    try:
        start_worker_consumer()
    except Exception as e:
        logger.critical(f"WORKER (__main__): Unrecoverable error: {e}", exc_info=True)
    finally:
        logger.info("WORKER (__main__): Script execution finished.")
