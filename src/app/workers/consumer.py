"""RabbitMQ consumer — aio_pika async native.

Replaces the old pika.BlockingConnection + thread-bridge-to-asyncio pattern
with a single asyncio event loop that does everything inline: connect to
RabbitMQ, consume messages, invoke the LangGraph workflow, ack/nack. Killed:

- `_async_loop` + daemon thread running `asyncio.new_event_loop()`
- `_pika_connection.add_callback_threadsafe` + the `_finalize_delivery` dance
- `schedule_task_on_async_loop` + `call_soon_threadsafe`
- The `asyncio_thread_worker_target` with its `run_until_complete` cleanup

Preserved: exponential reconnect backoff, scan-workflow timeout, FAILED-on-
crash DB update, duplicate-delivery idempotency precheck.

aio_pika's `connect_robust` auto-reconnects on network blips, but we still
wrap the consume loop in exponential backoff for the "RabbitMQ is down for
a while" case.
"""

import asyncio
import json
import logging
import logging.config
import signal
import uuid
from typing import Any, Optional

import aio_pika
from aio_pika.abc import (
    AbstractIncomingMessage,
    AbstractRobustConnection,
)
from dotenv import load_dotenv
from langchain_core.runnables import RunnableConfig
from langgraph.types import Command

from app.config.config import settings
from app.config.logging_config import LOGGING_CONFIG, correlation_id_var
from app.infrastructure.workflows.worker_graph import (
    WorkerState,
    close_workflow_resources,
    get_workflow,
)
from app.shared.lib.scan_status import (
    STATUS_FAILED,
    STATUS_PENDING_APPROVAL,
    STATUS_QUEUED,
    STATUS_QUEUED_FOR_SCAN,
)

logging.config.dictConfig(LOGGING_CONFIG)
logging.captureWarnings(True)
logger = logging.getLogger(__name__)
logging.getLogger("aio_pika").setLevel(logging.WARNING)
logging.getLogger("aiormq").setLevel(logging.WARNING)

load_dotenv()

# Scan statuses the workflow knows how to handle. Any other status received
# by the worker means the scan is either already in-flight on another worker,
# has already completed, or was cancelled — all duplicate-delivery cases that
# we should ACK without re-invoking the graph.
_WORKFLOW_ENTRY_STATUSES = frozenset(
    {STATUS_QUEUED, STATUS_QUEUED_FOR_SCAN, STATUS_PENDING_APPROVAL}
)

# Reconnect backoff for the outer consume loop. aio_pika's robust connection
# handles per-op retries; this catches the "broker down for minutes" case
# where the connection itself can't be established.
_BACKOFF_START_SECONDS = 1.0
_BACKOFF_CAP_SECONDS = 30.0


async def _run_workflow_for_scan(
    initial_state: WorkerState,
    *,
    resume_payload: Optional[dict] = None,
) -> bool:
    """Invokes the LangGraph workflow for a given scan. Returns success flag.

    `resume_payload=None` starts (or restarts) the workflow with the
    initial state. `resume_payload={...}` drives a `Command(resume=...)`
    invocation against the same thread, which unblocks a paused
    `interrupt()` inside estimate_cost_node. The `thread_id` is derived
    from the scan id, so the checkpointer finds the paused state.

    Handles the idempotency precheck, the timeout-wrapped invocation, and the
    FAILED-on-crash DB update. Does NOT ack/nack — the caller owns that.
    """
    scan_id_uuid = initial_state["scan_id"]
    scan_id_str_log = str(scan_id_uuid)
    action = "Resuming" if resume_payload is not None else "Starting"
    logger.info(f"WORKFLOW: {action} worker_workflow for scan_id: {scan_id_str_log}")

    # Idempotency precheck: only meaningful for fresh-start messages. For a
    # resume, the scan is in STATUS_PENDING_APPROVAL and would fail the
    # entry-status check — but that's exactly the case we want to resume.
    if resume_payload is None:
        try:
            from app.infrastructure.database import AsyncSessionLocal
            from app.infrastructure.database.repositories.scan_repo import (
                ScanRepository,
            )

            async with AsyncSessionLocal() as db:
                repo = ScanRepository(db)
                existing = await repo.get_scan(scan_id_uuid)
            if existing is None:
                logger.warning(
                    f"WORKFLOW: Scan {scan_id_str_log} not found in DB; "
                    f"ACKing as noop."
                )
                return True
            if existing.status not in _WORKFLOW_ENTRY_STATUSES:
                logger.info(
                    f"WORKFLOW: Scan {scan_id_str_log} already in status "
                    f"'{existing.status}' — treating as duplicate delivery."
                )
                return True
        except Exception as e:
            logger.warning(
                f"WORKFLOW: Idempotency precheck failed for {scan_id_str_log}: {e}. "
                f"Proceeding with workflow invocation.",
                exc_info=True,
            )

    success = False
    timed_out = False

    try:
        worker_workflow = await get_workflow()
        config: RunnableConfig = {"configurable": {"thread_id": scan_id_str_log}}
        workflow_input: Any
        if resume_payload is not None:
            workflow_input = Command(resume=resume_payload)
        else:
            workflow_input = initial_state
        final_graph_state = await asyncio.wait_for(
            worker_workflow.ainvoke(workflow_input, config),
            timeout=settings.SCAN_WORKFLOW_TIMEOUT_SECONDS,
        )

        logger.info(f"WORKFLOW: worker_workflow completed for SID: {scan_id_str_log}.")

        if final_graph_state and not final_graph_state.get("error_message"):
            success = True
        else:
            error_msg = (
                final_graph_state.get("error_message", "Unknown error")
                if final_graph_state
                else "Workflow returned no state"
            )
            logger.error(f"WORKFLOW: Graph processing failed. Error: {error_msg}")

    except asyncio.TimeoutError:
        timed_out = True
        logger.error(
            f"WORKFLOW: Scan {scan_id_str_log} exceeded "
            f"{settings.SCAN_WORKFLOW_TIMEOUT_SECONDS}s timeout; cancelling workflow."
        )
    except Exception as e:
        logger.error(
            f"WORKFLOW: Exception during worker_workflow invocation: {e}",
            exc_info=True,
        )

    # On any failure, mark the scan FAILED so the UI doesn't show it stuck.
    if not success:
        try:
            from app.infrastructure.database import AsyncSessionLocal
            from app.infrastructure.database.repositories.scan_repo import (
                ScanRepository,
            )

            async with AsyncSessionLocal() as db:
                repo = ScanRepository(db)
                await repo.update_status(scan_id_uuid, STATUS_FAILED)
            logger.info(
                f"WORKFLOW: Set scan status to FAILED in DB for SID: {scan_id_str_log}"
                + (" (timeout)" if timed_out else "")
            )
        except Exception as db_err:
            logger.error(
                f"WORKFLOW: FAILED TO UPDATE STATUS IN DB for SID: {scan_id_str_log}. "
                f"Error: {db_err}"
            )

    return success


async def _build_initial_state(
    message: AbstractIncomingMessage,
) -> Optional[WorkerState]:
    """Parses the message body into a WorkerState. Returns None on parse error."""
    try:
        body = json.loads(message.body.decode("utf-8"))
    except (json.JSONDecodeError, UnicodeDecodeError) as e:
        logger.error(f"MSG: Failed to decode message body: {e}", exc_info=True)
        return None

    scan_id_str = body.get("scan_id")
    if not scan_id_str:
        logger.error("MSG: Invalid message — no scan_id.")
        return None

    try:
        scan_uuid = uuid.UUID(scan_id_str)
    except ValueError:
        logger.error(f"MSG: Invalid scan_id UUID: {scan_id_str}")
        return None

    corr_id = message.correlation_id or body.get("correlation_id") or str(uuid.uuid4())
    correlation_id_var.set(corr_id)

    initial_state: WorkerState = {
        "scan_id": scan_uuid,
        "scan_type": "AUDIT",  # overwritten by the DB value in retrieve_and_prepare_data
        "current_scan_status": None,
        "utility_llm_config_id": None,
        "fast_llm_config_id": None,
        "reasoning_llm_config_id": None,
        "files": None,
        "initial_file_map": None,
        "final_file_map": None,
        "repository_map": None,
        "dependency_graph": None,
        "all_relevant_agents": {},
        "live_codebase": None,
        "findings": [],
        "proposed_fixes": None,
        "agent_results": None,
        "error_message": None,
    }

    # Queue-type routing hints (scan_type gets overwritten by the DB value
    # regardless; this is mostly for logging).
    queue_name = message.routing_key or ""
    if queue_name == settings.RABBITMQ_REMEDIATION_QUEUE:
        logger.info(f"MSG: REMEDIATION trigger for scan_id: {scan_uuid}")
        initial_state["scan_type"] = "AUDIT_AND_REMEDIATE"
    elif queue_name == settings.RABBITMQ_APPROVAL_QUEUE:
        logger.info(f"MSG: Resuming ANALYSIS for scan_id: {scan_uuid}")
    else:
        logger.info(f"MSG: Starting new ANALYSIS for scan_id: {scan_uuid}")

    return initial_state


async def _handle_message(message: AbstractIncomingMessage) -> None:
    """Top-level message handler. ACK on success, reject (no requeue) on failure.

    The `async with message.process(...)` context manager ACKs the message on
    clean exit and NACKs on exception. We use `requeue=False` so poison
    messages don't loop; FAILED scan status is already persisted by
    `_run_workflow_for_scan` for UI visibility.
    """
    logger.info(
        f"MSG: Received from queue '{message.routing_key}' "
        f"(delivery_tag={message.delivery_tag})."
    )

    async with message.process(requeue=False, ignore_processed=True):
        initial_state = await _build_initial_state(message)
        if initial_state is None:
            # Parse failures: reject explicitly so the message isn't requeued.
            await message.reject(requeue=False)
            return

        resume_payload: Optional[dict] = None
        if (message.routing_key or "") == settings.RABBITMQ_APPROVAL_QUEUE:
            try:
                body = json.loads(message.body.decode("utf-8"))
            except Exception:
                body = {}
            resume_payload = {
                "scan_id": str(initial_state["scan_id"]),
                "approved": True,
                "approver_user_id": body.get("user_id"),
            }

        success = await _run_workflow_for_scan(
            initial_state, resume_payload=resume_payload
        )
        if not success:
            # Explicit reject so `message.process`'s implicit ack doesn't
            # win. `reject(requeue=False)` is idempotent with
            # `ignore_processed=True`.
            await message.reject(requeue=False)


class WorkerRunner:
    """Manages the connection + consumer lifecycle."""

    def __init__(self) -> None:
        self._connection: Optional[AbstractRobustConnection] = None
        self._stop_event = asyncio.Event()
        self._backoff = _BACKOFF_START_SECONDS

    def request_stop(self) -> None:
        logger.info("WORKER: Stop requested.")
        self._stop_event.set()

    async def run(self) -> None:
        while not self._stop_event.is_set():
            try:
                await self._consume_forever()
                # If _consume_forever returns cleanly (not via exception),
                # it's because stop was requested. Break out.
                break
            except asyncio.CancelledError:
                logger.info("WORKER: Run cancelled.")
                raise
            except Exception as e:
                logger.error(
                    f"WORKER: Consume loop error: {e}. "
                    f"Retrying in {self._backoff:.0f}s.",
                    exc_info=True,
                )

            if self._stop_event.is_set():
                break
            try:
                await asyncio.wait_for(self._stop_event.wait(), timeout=self._backoff)
            except asyncio.TimeoutError:
                pass
            self._backoff = min(self._backoff * 2, _BACKOFF_CAP_SECONDS)

        logger.info("WORKER: Run loop exited.")

    async def _consume_forever(self) -> None:
        if not settings.RABBITMQ_URL:
            raise ValueError("RABBITMQ_URL is not configured.")

        logger.info("WORKER: Connecting to RabbitMQ...")
        self._connection = await aio_pika.connect_robust(settings.RABBITMQ_URL)
        logger.info("WORKER: RabbitMQ connection established.")
        self._backoff = _BACKOFF_START_SECONDS  # reset after successful connect

        try:
            channel = await self._connection.channel()
            # prefetch=1 keeps us aligned with the old blocking behavior —
            # one scan at a time per worker. Increase if you want per-worker
            # parallelism across scans (analyze_files_parallel already gives
            # us intra-scan parallelism via the CONCURRENT_LLM_LIMIT semaphore).
            await channel.set_qos(prefetch_count=1)

            queues = []
            for queue_name in (
                settings.RABBITMQ_SUBMISSION_QUEUE,
                settings.RABBITMQ_APPROVAL_QUEUE,
                settings.RABBITMQ_REMEDIATION_QUEUE,
            ):
                queue = await channel.declare_queue(queue_name, durable=True)
                await queue.consume(_handle_message)
                queues.append(queue_name)

            logger.info(
                f"WORKER: Consuming from queues: {queues}. Waiting for messages…"
            )
            await self._stop_event.wait()
        finally:
            if self._connection is not None and not self._connection.is_closed:
                await self._connection.close()
                self._connection = None
            logger.info("WORKER: Connection closed.")


async def _async_main() -> None:
    runner = WorkerRunner()

    loop = asyncio.get_running_loop()
    for sig in (signal.SIGINT, signal.SIGTERM):
        try:
            loop.add_signal_handler(sig, runner.request_stop)
        except NotImplementedError:
            # add_signal_handler is not supported on Windows; fall through.
            pass

    try:
        await runner.run()
    finally:
        logger.info("WORKER: Closing workflow resources…")
        try:
            await close_workflow_resources()
        except Exception as e:
            logger.error(f"WORKER: Error during workflow resource cleanup: {e}")
        logger.info("WORKER: Consumer has fully shut down.")


def start_worker_consumer() -> None:
    """Entry point wrapper. Runs the async main loop to completion."""
    try:
        asyncio.run(_async_main())
    except KeyboardInterrupt:
        logger.info("WORKER: KeyboardInterrupt at top level; exiting.")


if __name__ == "__main__":
    logger.info("Starting RabbitMQ worker consumer script (__main__)…")
    try:
        start_worker_consumer()
    except Exception as e:
        logger.critical(f"WORKER (__main__): Unrecoverable error: {e}", exc_info=True)
    finally:
        logger.info("WORKER (__main__): Script execution finished.")
