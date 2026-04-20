"""Background task that re-publishes unpublished scan_outbox rows.

Started from the FastAPI lifespan. Runs forever on a fixed interval until the
app shuts down. Each tick:
  1. Selects up to `BATCH_SIZE` unpublished rows older than `MIN_AGE_SECONDS`
     (giving the primary publisher a head start on fresh rows).
  2. For each, calls publish_message; on success marks published_at, on
     failure increments attempts and leaves the row for the next tick.
"""

import asyncio
import logging

from app.infrastructure.database.database import AsyncSessionLocal
from app.infrastructure.database.repositories.scan_outbox_repo import (
    ScanOutboxRepository,
)
from app.infrastructure.messaging.publisher import publish_message

logger = logging.getLogger(__name__)

SWEEP_INTERVAL_SECONDS = 10
MIN_AGE_SECONDS = 30
BATCH_SIZE = 50


async def _tick() -> None:
    async with AsyncSessionLocal() as db:
        repo = ScanOutboxRepository(db)
        rows = await repo.list_unpublished(
            older_than_seconds=MIN_AGE_SECONDS, limit=BATCH_SIZE
        )
        if not rows:
            return
        logger.info(f"Outbox sweep: {len(rows)} unpublished row(s) to retry.")
        for row in rows:
            try:
                published = await publish_message(
                    queue_name=row.queue_name,
                    message_body=dict(row.payload),
                )
                if published:
                    await repo.mark_published(row.id)
                    logger.info(
                        f"Outbox sweep: re-published scan_id={row.scan_id} "
                        f"(attempt={row.attempts + 1})."
                    )
                else:
                    await repo.record_failed_attempt(row.id)
            except Exception as e:
                logger.error(
                    f"Outbox sweep: error re-publishing scan_id={row.scan_id}: {e}",
                    exc_info=True,
                )
                try:
                    await repo.record_failed_attempt(row.id)
                except Exception:
                    pass


async def run_outbox_sweeper(stop_event: asyncio.Event) -> None:
    """Main loop. Exits cleanly when stop_event is set."""
    logger.info(
        "Outbox sweeper started "
        f"(interval={SWEEP_INTERVAL_SECONDS}s, min_age={MIN_AGE_SECONDS}s)."
    )
    while not stop_event.is_set():
        try:
            await _tick()
        except Exception as e:
            logger.error(f"Outbox sweeper tick failed: {e}", exc_info=True)

        try:
            await asyncio.wait_for(stop_event.wait(), timeout=SWEEP_INTERVAL_SECONDS)
        except asyncio.TimeoutError:
            continue

    logger.info("Outbox sweeper stopped.")
