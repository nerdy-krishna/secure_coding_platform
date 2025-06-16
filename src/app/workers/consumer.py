# src/app/workers/consumer.py
import pika
import os
import logging
import asyncio
import json
import threading
import time  # For sleep in retry logic and initial loop spin-up
from typing import Any, Callable, Dict, Optional, TypedDict, cast

from dotenv import load_dotenv

# Import the worker graph and its state (though worker_workflow isn't called in this test version)
from app.graphs.worker_graph import worker_workflow

# Ensure necessary imports for type hints used in this file
from pika.adapters.blocking_connection import BlockingChannel # For Pika channel type
from pika.channel import Channel # Original import, BlockingChannel is more specific here
from pika.spec import BasicProperties, Basic # For Pika message properties and delivery info (Basic.Deliver)
from pika.exceptions import AMQPConnectionError # For specific Pika exception handling

logging.basicConfig(
    level=logging.INFO,  # Lower to DEBUG for more verbose output from this module
    format="%(asctime)s - %(levelname)-7s - [%(threadName)s] %(name)s (%(module)s.%(funcName)s:%(lineno)d) - %(message)s",
)
logger = logging.getLogger(
    __name__
)  # Gets logger for current module __main__ if run directly
# or app.workers.consumer if imported.
# Consider a fixed name if preferred: logging.getLogger("secure_coding_platform.worker")

logging.getLogger("pika").setLevel(logging.WARNING)
logging.getLogger("asyncio").setLevel(logging.WARNING)
# You can add more libraries here if needed, e.g.:
# logging.getLogger("aio_pika").setLevel(logging.WARNING) # If you use aio_pika directly and it's noisy
# logging.getLogger("sqlalchemy.engine").setLevel(logging.WARNING) # To quiet SQLAlchemy engine logs

load_dotenv()

RABBITMQ_HOST = os.getenv("RABBITMQ_HOST", "rabbitmq")
RABBITMQ_PORT = os.getenv("RABBITMQ_PORT_DOCKER", "5672")
RABBITMQ_USER = os.getenv("RABBITMQ_DEFAULT_USER", "devuser_scp")
RABBITMQ_PASS = os.getenv("RABBITMQ_DEFAULT_PASS", "YourStrongRabbitPassword!")
CODE_QUEUE = os.getenv("CODE_QUEUE", "code_analysis_queue")

_async_loop: Optional[asyncio.AbstractEventLoop] = None
_event_loop_thread: Optional[threading.Thread] = None
_pika_connection: Optional[pika.BlockingConnection] = None
_pika_channel: Optional[BlockingChannel] = None # Changed to BlockingChannel

_stop_event = threading.Event()  # For signaling threads to stop

class WorkerGraphState(TypedDict):
    """Overall state for the worker graph, used by the consumer."""
    submission_id: str
    result: Optional[Dict[str, Any]]
    error: Optional[str]

# --- Asyncio Task Execution ---
async def run_graph_task_wrapper(initial_state: WorkerGraphState, delivery_tag: int):
    """
    This coroutine runs in the asyncio event loop.
    It executes the worker_workflow and then schedules Pika ACK/NACK.
    """
    global _pika_channel, _pika_connection  # Ensure globals are accessible if not already
    submission_id = initial_state.get("submission_id", "N/A_IN_ASYNC_WRAPPER")
    logger.info(
        f"ASYNC WRAPPER: Starting actual worker_workflow for submission_id: {submission_id}, delivery_tag: {delivery_tag}"
    )

    success = False
    final_graph_state: Optional[WorkerGraphState] = (
        None  # To store the result from the graph
    )

    try:
        # === CALL THE ACTUAL WORKER GRAPH ===
        logger.info(
            f"ASYNC WRAPPER: Invoking worker_workflow for SID: {submission_id}..."
        )
        # Cast the result to the expected type
        invoked_state = await worker_workflow.ainvoke(initial_state)
        if isinstance(invoked_state, dict):
            final_graph_state = cast(WorkerGraphState, invoked_state)
        elif invoked_state is None:
            final_graph_state = None
        else:
            # Handle unexpected type from ainvoke if necessary, or assume it's WorkerGraphState | None
            logger.error(f"ASYNC WRAPPER: Unexpected type from worker_workflow.ainvoke: {type(invoked_state)}")
            final_graph_state = None # Or handle as an error state

        logger.info(
            f"ASYNC WRAPPER: worker_workflow completed for SID: {submission_id}."
        )

        if final_graph_state:
            # Assuming final_graph_state is WorkerGraphState
            # WorkerGraphState.error should contain any error string from the workflow.
            # WorkerGraphState.result should contain the 'results' dict from CoordinatorState.
            worker_level_error = final_graph_state.get("error")
            final_status_from_results = final_graph_state.get("result", {}).get(
                "final_status"
            )

            logger.info(
                f"ASYNC WRAPPER: Graph result for SID {submission_id} - WorkerError: {worker_level_error}, FinalStatusInResult: {final_status_from_results}"
            )

            if not worker_level_error and final_status_from_results == "Analysis complete.":
                success = True
                logger.info(f"ASYNC WRAPPER: Graph processing for SID {submission_id} successful.")
            else:
                logger.error(
                    f"ASYNC WRAPPER: Graph processing for SID {submission_id} reported issues. WorkerError: {worker_level_error}, FinalStatusInResult: {final_status_from_results}"
                )
                success = False
        else:
            logger.error(
                f"ASYNC WRAPPER: worker_workflow returned None for SID {submission_id}."
            )
            success = False
            # Create a minimal final_graph_state for error reporting to Pika finalize
            # No type re-declaration here, assign to the existing 'final_graph_state'
            final_graph_state = {
                "submission_id": submission_id, # submission_id from the current scope
                "result": None,
                "error": "Worker workflow returned None or unexpected type", # Clarified error message
            }

    except Exception as e:
        logger.error(
            f"ASYNC WRAPPER: Exception during worker_workflow invocation for SID {submission_id}: {e}",
            exc_info=True,
        )
        success = False
        # Create a minimal final_graph_state for error reporting
        if (
            final_graph_state is None
        ):  # If error happened before final_graph_state was set
            # Create a new WorkerGraphState for error reporting
            # No type re-declaration here, assign to the existing 'final_graph_state'
            final_graph_state = {
                "submission_id": submission_id, # submission_id from the current scope
                "result": None,
                "error": str(e),
            }
        else: # final_graph_state exists, just update the error
            # Ensure final_graph_state is a dict before trying to set a key
            if isinstance(final_graph_state, dict):
                final_graph_state["error"] = str(e)
            else:
                # This case should ideally not be reached if logic is correct,
                # but as a fallback, create a new error state.
                logger.warning(f"ASYNC WRAPPER: final_graph_state was not None but also not a dict in exception handler. Type: {type(final_graph_state)}. Re-creating.")
                final_graph_state = {
                    "submission_id": submission_id,
                    "result": None,
                    "error": str(e),
                }


    # Safely schedule Pika operations on Pika's I/O loop thread
    if (
        _pika_channel
        and _pika_channel.is_open
        and _pika_connection
        and _pika_connection.is_open
    ):

        def pika_finalize_message():
            try:
                if success:
                    logger.info(
                        f"PIKA FINALIZE (via threadsafe_cb): ACK delivery_tag {delivery_tag} for SID {submission_id}"
                    )
                    if _pika_channel and _pika_channel.is_open:
                        _pika_channel.basic_ack(delivery_tag=delivery_tag)
                else:
                    # Get error reason from the 'error' field of WorkerGraphState
                    error_info = (
                        final_graph_state.get("error", "Processing failed (error key missing)")
                        if final_graph_state
                        else "Processing failed (no final state)"
                    )
                    logger.error(
                        f"PIKA FINALIZE (via threadsafe_cb): NACK delivery_tag {delivery_tag} for SID {submission_id}. Reason: {error_info}"
                    )
                    if _pika_channel and _pika_channel.is_open:
                        _pika_channel.basic_nack(
                            delivery_tag=delivery_tag, requeue=False
                        )
            except Exception as e_pika_finalize:
                logger.error(
                    f"PIKA FINALIZE (via threadsafe_cb): Exception for SID {submission_id}, delivery_tag {delivery_tag}: {e_pika_finalize}",
                    exc_info=True,
                )

        _pika_connection.add_callback_threadsafe(pika_finalize_message)
    else:
        logger.error(
            f"ASYNC WRAPPER: Pika channel/connection not open. Cannot ACK/NACK SID {submission_id}, delivery_tag {delivery_tag}."
        )


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


def pika_message_callback( # pyright: ignore[reportGeneralTypeIssues]
    ch: BlockingChannel, # Changed from Channel
    method: Basic.Deliver, # Changed from Deliver to Basic.Deliver
    properties: BasicProperties, # Changed from pika.spec.BasicProperties
    body: bytes,
):
    """Pika callback for received messages."""
    submission_id_str = "N/A (before parse)"
    logger.info(
        f"PIKA CB: Received message. Delivery Tag: {method.delivery_tag}. Body (first 100): {body[:100]}"
    )

    try:
        message_data = json.loads(body.decode("utf-8"))
        submission_id = message_data.get("submission_id")
        submission_id_str = str(submission_id)

        if submission_id is None:
            logger.error(
                f"PIKA CB: Invalid message - no submission_id. Body: {body.decode('utf-8')}"
            )
            if ch.is_open:
                ch.basic_nack(delivery_tag=method.delivery_tag, requeue=False)
            return

        logger.info(
            f"PIKA CB: Processing submission_id: {submission_id}. Scheduling async task wrapper."
        )
        # Ensure initial_state conforms to WorkerGraphState TypedDict
        # 'result' and 'error' are Optional but part of the type, so they should be initialized.
        initial_state: WorkerGraphState = {
            "submission_id": submission_id,
            "result": None, # Initialize result field
            "error": None,  # Initialize error field
        }
        # The other keys (final_report, db_save_status, etc.) are not in WorkerGraphState
        # and were likely causing issues or being ignored.

        # Schedule run_graph_task_wrapper to be executed on the asyncio loop
        schedule_task_on_async_loop(
            run_graph_task_wrapper, initial_state, method.delivery_tag
        )

    except json.JSONDecodeError:
        logger.error(
            f"PIKA CB: Failed to decode JSON: {body.decode('utf-8')}", exc_info=True
        )
        if ch.is_open:
            ch.basic_nack(delivery_tag=method.delivery_tag, requeue=False)
    except Exception as e:
        logger.error(
            f"PIKA CB: Unhandled error for SID '{submission_id_str}': {e}",
            exc_info=True,
        )
        if ch.is_open:
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
        # Give the loop a moment to start and _async_loop to be assigned
        for _ in range(50):  # Wait up to 5 seconds
            if _async_loop and _async_loop.is_running():
                break
            time.sleep(0.1)
        if not (_async_loop and _async_loop.is_running()):
            logger.error(
                "WORKER: Asyncio loop did not start running in dedicated thread. Aborting worker."
            )
            if (
                _event_loop_thread.is_alive()
            ):  # Signal it to stop if it's stuck before run_forever
                if _async_loop:
                    _async_loop.call_soon_threadsafe(_async_loop.stop)
                _event_loop_thread.join(timeout=2)
            return  # Critical failure
        logger.info("WORKER: Asyncio loop confirmed running in dedicated thread.")
    else:
        logger.info("WORKER: Asyncio event loop manager thread already running.")

    retry_delay = 5
    while not _stop_event.is_set():
        try:
            logger.info(
                f"WORKER: Attempting RabbitMQ connection to {RABBITMQ_HOST}:{RABBITMQ_PORT}..."
            )
            credentials = pika.PlainCredentials(RABBITMQ_USER, RABBITMQ_PASS)
            parameters = pika.ConnectionParameters(
                host=RABBITMQ_HOST,
                port=int(RABBITMQ_PORT),
                credentials=credentials,
                heartbeat=60,  # Reduced heartbeat for quicker detection of dead connections
                blocked_connection_timeout=300,
            )
            _pika_connection = pika.BlockingConnection(parameters)
            _pika_channel = _pika_connection.channel()
            logger.info("WORKER: RabbitMQ connection successful, channel opened.")

            _pika_channel.queue_declare(queue=CODE_QUEUE, durable=True)
            logger.info(f"WORKER: Queue '{CODE_QUEUE}' declared.")
            _pika_channel.basic_qos(prefetch_count=1)  # Process one message at a time
            _pika_channel.basic_consume(
                queue=CODE_QUEUE,
                on_message_callback=pika_message_callback,
                auto_ack=False,
            )

            logger.info(
                f"WORKER: Waiting for messages in '{CODE_QUEUE}'. CTRL+C to exit."
            )
            _pika_channel.start_consuming()  # This blocks until connection closes, error, or stop_consuming

        except AMQPConnectionError as conn_err: # Changed from pika.exceptions.AMQPConnectionError
            logger.error(f"WORKER: RabbitMQ connection error: {conn_err}.")
            if _stop_event.is_set():
                break
            logger.info(f"WORKER: Retrying in {retry_delay}s...")
        except KeyboardInterrupt:
            logger.info("WORKER: KeyboardInterrupt received. Shutting down consumer.")
            _stop_event.set()  # Signal other loops to stop
            break
        except Exception as e:
            logger.error(
                f"WORKER: Unexpected error in main Pika consumer loop: {e}",
                exc_info=True,
            )
            if _stop_event.is_set():
                break
            logger.info(f"WORKER: Retrying in {retry_delay}s due to unexpected error.")
        finally:
            # Close Pika connection if it's open. stop_consuming might be needed before close.
            if _pika_channel and _pika_channel.is_open:
                try:
                    # _pika_channel.stop_consuming() # May not be needed if start_consuming exited due to error/close
                    _pika_channel.close()
                except Exception as e_ch_close:
                    logger.error(f"WORKER: Error closing Pika channel: {e_ch_close}")
            if _pika_connection and _pika_connection.is_open:
                try:
                    _pika_connection.close()
                except Exception as e_conn_close:
                    logger.error(
                        f"WORKER: Error closing Pika connection: {e_conn_close}"
                    )
            logger.info(
                "WORKER: Pika connection/channel (attempted) closed for this iteration."
            )

        if _stop_event.is_set():
            break

        if not (_event_loop_thread and _event_loop_thread.is_alive()):
            logger.error("WORKER: Asyncio event loop thread is not alive. Exiting.")
            _stop_event.set()  # Ensure we exit the while loop
            break

        logger.info(
            f"WORKER: Waiting {retry_delay}s before retrying RabbitMQ connection."
        )
        for _ in range(retry_delay):  # Sleep interruptibly
            if _stop_event.is_set():
                break
            time.sleep(1)
        if _stop_event.is_set():
            break

    # Final cleanup of asyncio loop
    logger.info("WORKER: Finalizing shutdown...")
    if (
        _async_loop and _async_loop.is_running()
    ):  # Ensure it's running before trying to stop
        logger.info("WORKER: Signaling asyncio loop to stop from main thread.")
        _async_loop.call_soon_threadsafe(_async_loop.stop)
    if _event_loop_thread and _event_loop_thread.is_alive():
        logger.info("WORKER: Waiting for asyncio event loop thread to join...")
        _event_loop_thread.join(timeout=10)
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
