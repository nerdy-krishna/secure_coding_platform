"""Per-app-process bus for scan-progress notifications (§3.10a).

Replaces the per-SSE-client 1 Hz Postgres poll with a single LISTEN
task that subscribes to the `scan_progress` channel and fans out
notifications to in-process `asyncio.Queue`s keyed by `scan_id`.

Design:

- Worker / API code calls `notify_scan_progress(session, scan_id, kind)`
  AFTER its own DDL commit. The helper issues `SELECT pg_notify(
  'scan_progress', '<json>')` on the same SQLAlchemy session, so the
  notification fires only if the caller's transaction succeeds.
- `ScanProgressBus` owns a dedicated `psycopg.AsyncConnection` (NOT a
  pooled SQLAlchemy connection — LISTEN holds the connection idle
  forever and pool drainers would close it). One LISTEN connection
  per app process.
- SSE handlers call `bus.subscribe(scan_id, owner_user_id=...,
  visible_user_ids=...)` to get an `asyncio.Queue`, `await queue.get()`
  for the next event, and `bus.unsubscribe()` on disconnect. The bus
  drops notifications for scan_ids with no subscribers (cheap in-memory
  check).

Tenant-scope invariant (V08.2.2 / V08.4.1):
  `subscribe` enforces tenant scope as defense-in-depth even when
  callers are already authorized. It validates that the scan belongs
  to `owner_user_id` or is visible via `visible_user_ids` by loading
  the scan from the DB inside the bus, raising `PermissionError` if
  the check fails. This ensures cross-tenant isolation is enforced at
  the bus layer and does not rely solely on upstream callers.

Failure mode: if the bus connection drops, `_listen_loop` reconnects
with exponential backoff. SSE handlers fall back to a slower poll
when the bus signals "no recent notifications" via a TimeoutError on
`queue.get()` — see `stream_scan_progress` in `routers/projects.py`.
"""

from __future__ import annotations

import asyncio
import json
import logging
import uuid
from typing import Dict, List, Optional, Set

import psycopg
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import text

from app.config.config import settings
from app.infrastructure.database import AsyncSessionLocal
from app.infrastructure.database.repositories.scan_repo import ScanRepository

logger = logging.getLogger(__name__)

# Single channel for all scan-progress events. Filtering by scan_id
# happens in `_dispatch_notification` — the channel itself is shared
# so a single LISTEN connection covers every scan in the system.
_CHANNEL = "scan_progress"

# Notification kinds. The receiver doesn't need to know what changed
# in the DB; it re-reads the scan to get the current state. The kind
# is a hint for telemetry / logging.
KIND_STATUS = "status"
KIND_EVENT = "event"


async def notify_scan_progress(
    session: AsyncSession,
    *,
    scan_id: str,
    kind: str,
) -> None:
    """Emit a `pg_notify` on the `scan_progress` channel.

    Runs in the caller's transaction so the notification fires iff the
    DDL commits. Failures are swallowed (logged at WARN) — a missed
    notification just means the SSE handler falls back to its slower
    poll path on next iteration.
    """
    try:
        payload = json.dumps({"scan_id": scan_id, "kind": kind})
        await session.execute(
            text("SELECT pg_notify(:channel, :payload)"),
            {"channel": _CHANNEL, "payload": payload},
        )
    except Exception as e:
        logger.warning(
            "scan_progress: failed to enqueue NOTIFY for scan %s (kind=%s): %s",
            scan_id,
            kind,
            e,
        )


class ScanProgressBus:
    """Per-app-process LISTEN/fan-out for `scan_progress` notifications.

    Owns its own psycopg async connection because LISTEN holds the
    connection open indefinitely; a pooled SQLAlchemy connection would
    be reclaimed and the LISTEN dropped. Reconnects with exponential
    backoff on connection loss.
    """

    def __init__(self) -> None:
        self._subscribers: Dict[str, Set[asyncio.Queue]] = {}
        self._lock = asyncio.Lock()
        self._task: Optional[asyncio.Task] = None
        self._stop = asyncio.Event()
        self._conn: Optional[psycopg.AsyncConnection] = None

    async def subscribe(
        self,
        scan_id: str,
        *,
        owner_user_id: int,
        visible_user_ids: Optional[List[int]],
    ) -> asyncio.Queue:
        """Register an `asyncio.Queue` for notifications about a scan.

        Enforces tenant-scope ownership (V08.2.2 / V08.4.1) before
        registering the subscriber. Raises `PermissionError` if the
        scan does not belong to `owner_user_id` and is not within
        `visible_user_ids` (pass ``None`` for admins who bypass the
        filter).

        The queue receives the bus's notification kind ("status" /
        "event") whenever a NOTIFY arrives for `scan_id`. The caller
        is responsible for re-reading the DB to get current state.
        """
        # Defense-in-depth tenant check: verify the scan is owned by
        # the requester or is within their visibility scope before
        # registering the subscriber queue.
        async with AsyncSessionLocal() as session:
            repo = ScanRepository(session)
            scan = await repo.get_scan(uuid.UUID(scan_id))
        if scan is None:
            raise PermissionError(
                f"subscribe: scan {scan_id!r} not found or not accessible."
            )
        if visible_user_ids is not None:
            # Regular user: scan must be owned by a user in the visible set.
            if scan.user_id not in visible_user_ids:
                logger.warning(
                    "scan_progress.subscribe.access_denied: "
                    "requester %s not in visible_user_ids for scan %s (owner=%s)",
                    owner_user_id,
                    scan_id,
                    scan.user_id,
                )
                raise PermissionError(
                    f"subscribe: requester {owner_user_id} is not authorised "
                    f"to subscribe to scan {scan_id!r}."
                )
        # visible_user_ids is None → admin; no restriction.

        async with self._lock:
            queues = self._subscribers.setdefault(scan_id, set())
            q: asyncio.Queue = asyncio.Queue(maxsize=64)
            queues.add(q)
            return q

    async def unsubscribe(self, scan_id: str, queue: asyncio.Queue) -> None:
        async with self._lock:
            queues = self._subscribers.get(scan_id)
            if queues is None:
                return
            queues.discard(queue)
            if not queues:
                self._subscribers.pop(scan_id, None)

    async def _dispatch_notification(self, raw_payload: str) -> None:
        try:
            payload = json.loads(raw_payload)
        except json.JSONDecodeError:
            logger.warning(
                "scan_progress: dropped malformed NOTIFY payload (raw=%r)",
                raw_payload[:200],
            )
            return
        scan_id = payload.get("scan_id")
        kind = payload.get("kind") or "unknown"
        if not scan_id:
            return
        async with self._lock:
            queues = list(self._subscribers.get(scan_id, ()))
        for q in queues:
            try:
                q.put_nowait(kind)
            except asyncio.QueueFull:
                # Subscriber has fallen behind; drop the notification.
                # The SSE handler will re-read on its next poll-fallback
                # tick so we don't lose the underlying state, just the
                # signal that it changed.
                logger.warning(
                    "scan_progress: dropped notify for scan %s (queue full)",
                    scan_id,
                )

    async def _listen_loop(self) -> None:
        """Main loop: maintain a LISTEN connection and dispatch
        notifications. Reconnects on failure with exponential backoff
        capped at 30s."""
        backoff = 1.0
        while not self._stop.is_set():
            try:
                if not settings.ASYNC_DATABASE_URL:
                    raise RuntimeError("ASYNC_DATABASE_URL not configured.")
                conn_url = settings.ASYNC_DATABASE_URL.replace(
                    "postgresql+asyncpg://", "postgresql://"
                )
                self._conn = await psycopg.AsyncConnection.connect(
                    conn_url, autocommit=True
                )
                async with self._conn.cursor() as cur:
                    await cur.execute(f"LISTEN {_CHANNEL}")
                logger.info("scan_progress: LISTEN connected on %s", _CHANNEL)
                backoff = 1.0  # reset on successful connect
                async for notify in self._conn.notifies():
                    if self._stop.is_set():
                        break
                    await self._dispatch_notification(notify.payload)
            except asyncio.CancelledError:
                raise
            except Exception as e:
                logger.warning(
                    "scan_progress: LISTEN loop error: %s; reconnecting in %.1fs",
                    e,
                    backoff,
                )
                try:
                    if self._conn is not None and not self._conn.closed:
                        await self._conn.close()
                except Exception:
                    pass
                self._conn = None
                try:
                    await asyncio.wait_for(self._stop.wait(), timeout=backoff)
                except asyncio.TimeoutError:
                    pass
                backoff = min(backoff * 2, 30.0)
        # Clean exit
        if self._conn is not None and not self._conn.closed:
            try:
                await self._conn.close()
            except Exception:
                pass
        self._conn = None

    async def start(self) -> None:
        """Wire into the API lifespan. Called once at startup."""
        if self._task is not None and not self._task.done():
            return
        self._stop.clear()
        self._task = asyncio.create_task(self._listen_loop(), name="scan_progress_bus")
        logger.info("scan_progress: bus started")

    async def stop(self) -> None:
        """Wire into the API lifespan. Called once at shutdown."""
        self._stop.set()
        if self._task is not None:
            try:
                await asyncio.wait_for(self._task, timeout=5.0)
            except asyncio.TimeoutError:
                self._task.cancel()
                try:
                    await self._task
                except (asyncio.CancelledError, Exception):
                    pass
        self._task = None
        logger.info("scan_progress: bus stopped")


# Module-level singleton wired by `main.py` lifespan. SSE handlers
# import and use this directly. None when the bus hasn't been started
# (e.g. in tests that don't go through lifespan).
_bus: Optional[ScanProgressBus] = None


def get_scan_progress_bus() -> Optional[ScanProgressBus]:
    """Return the process-wide bus, or None if not initialised."""
    return _bus


def set_scan_progress_bus(bus: Optional[ScanProgressBus]) -> None:
    """Set the process-wide bus singleton. Called from the API
    lifespan; tests can clear it by passing None."""
    global _bus
    _bus = bus
