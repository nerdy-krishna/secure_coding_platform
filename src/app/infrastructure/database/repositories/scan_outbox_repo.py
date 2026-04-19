"""Repository for the scan_outbox table.

The outbox is a transactional guarantee that every scan row has a
corresponding publish attempt. Writes to `scan_outbox` happen in the same
HTTP request that creates the Scan; a sweep task re-publishes any row with
`published_at IS NULL` older than a few seconds.
"""

import logging
import uuid
from datetime import datetime, timezone
from typing import Dict, List

from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.infrastructure.database import models as db_models

logger = logging.getLogger(__name__)


class ScanOutboxRepository:
    def __init__(self, db_session: AsyncSession):
        self.db = db_session

    async def enqueue(
        self, scan_id: uuid.UUID, queue_name: str, payload: Dict
    ) -> db_models.ScanOutbox:
        """Inserts an unpublished outbox row. Commits."""
        row = db_models.ScanOutbox(
            scan_id=scan_id,
            queue_name=queue_name,
            payload=payload,
        )
        self.db.add(row)
        await self.db.commit()
        await self.db.refresh(row)
        return row

    async def mark_published(self, outbox_id: uuid.UUID) -> None:
        """Marks an outbox row published_at=now. Commits."""
        await self.db.execute(
            update(db_models.ScanOutbox)
            .where(db_models.ScanOutbox.id == outbox_id)
            .values(published_at=datetime.now(timezone.utc))
        )
        await self.db.commit()

    async def record_failed_attempt(self, outbox_id: uuid.UUID) -> None:
        """Increments attempts on a publish failure. Commits."""
        await self.db.execute(
            update(db_models.ScanOutbox)
            .where(db_models.ScanOutbox.id == outbox_id)
            .values(attempts=db_models.ScanOutbox.attempts + 1)
        )
        await self.db.commit()

    async def list_unpublished(
        self, older_than_seconds: int = 30, limit: int = 50
    ) -> List[db_models.ScanOutbox]:
        """Returns unpublished rows that were created more than N seconds ago.

        The age filter prevents the sweeper from racing the primary publish:
        we let the request handler try first and only fall back for rows that
        have been sitting around unpublished.
        """
        cutoff = datetime.now(timezone.utc).timestamp() - older_than_seconds
        stmt = (
            select(db_models.ScanOutbox)
            .where(db_models.ScanOutbox.published_at.is_(None))
            .where(
                db_models.ScanOutbox.created_at
                < datetime.fromtimestamp(cutoff, tz=timezone.utc)
            )
            .order_by(db_models.ScanOutbox.created_at.asc())
            .limit(limit)
        )
        result = await self.db.execute(stmt)
        return list(result.scalars().all())
