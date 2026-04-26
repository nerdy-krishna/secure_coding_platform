"""Unit tests for the scan-progress LISTEN/NOTIFY bus (§3.10a).

Covers the in-memory fan-out logic without a real Postgres LISTEN —
the dispatcher is the part most likely to regress; the LISTEN socket
+ reconnect handling is exercised by integration smoke.
"""

from __future__ import annotations

import asyncio
import json
from unittest.mock import AsyncMock, MagicMock

import pytest

from app.infrastructure.messaging.scan_progress_notifier import (
    KIND_EVENT,
    KIND_STATUS,
    ScanProgressBus,
    notify_scan_progress,
)

pytestmark = pytest.mark.asyncio


async def test_subscribe_and_dispatch_routes_only_to_matching_subscriber() -> None:
    bus = ScanProgressBus()
    q_a = await bus.subscribe("scan-a")
    q_b = await bus.subscribe("scan-b")

    await bus._dispatch_notification(json.dumps({"scan_id": "scan-a", "kind": KIND_STATUS}))

    # Subscriber A got the notification; B's queue stays empty.
    assert q_a.qsize() == 1
    assert (await q_a.get()) == KIND_STATUS
    assert q_b.empty()


async def test_dispatch_to_multiple_subscribers_for_same_scan() -> None:
    bus = ScanProgressBus()
    q1 = await bus.subscribe("scan-a")
    q2 = await bus.subscribe("scan-a")

    await bus._dispatch_notification(json.dumps({"scan_id": "scan-a", "kind": KIND_EVENT}))

    assert (await q1.get()) == KIND_EVENT
    assert (await q2.get()) == KIND_EVENT


async def test_unsubscribe_drops_subscriber_set_when_last_leaves() -> None:
    bus = ScanProgressBus()
    q = await bus.subscribe("scan-a")
    assert "scan-a" in bus._subscribers

    await bus.unsubscribe("scan-a", q)
    assert "scan-a" not in bus._subscribers


async def test_dispatch_drops_when_subscriber_queue_full() -> None:
    bus = ScanProgressBus()
    q = await bus.subscribe("scan-a")
    # Saturate the subscriber queue (maxsize=64).
    for _ in range(64):
        q.put_nowait("filler")
    assert q.qsize() == 64

    # Should not raise — drops the notification + logs WARN.
    await bus._dispatch_notification(json.dumps({"scan_id": "scan-a", "kind": KIND_STATUS}))
    assert q.qsize() == 64  # still full; new notification discarded


async def test_dispatch_swallows_malformed_payload() -> None:
    bus = ScanProgressBus()
    q = await bus.subscribe("scan-a")

    await bus._dispatch_notification("not-json")
    await bus._dispatch_notification(json.dumps({"missing": "scan_id"}))

    assert q.empty()


async def test_notify_scan_progress_emits_pg_notify() -> None:
    """`notify_scan_progress` must call `SELECT pg_notify(...)` on the
    caller's session. We don't need a real DB — a MagicMock that
    captures the .execute() call is sufficient to pin the contract."""
    fake_session = MagicMock()
    fake_session.execute = AsyncMock()

    await notify_scan_progress(
        fake_session, scan_id="abc", kind=KIND_STATUS
    )

    fake_session.execute.assert_awaited_once()
    call = fake_session.execute.await_args
    # First positional arg is a sqlalchemy `text(...)` clause; we
    # verify the params dict round-trips the channel + JSON payload.
    params = call.args[1]
    assert params["channel"] == "scan_progress"
    decoded = json.loads(params["payload"])
    assert decoded == {"scan_id": "abc", "kind": KIND_STATUS}


async def test_notify_swallows_session_exceptions() -> None:
    """A session.execute crash must NOT propagate — the caller's DDL
    has already committed and we don't want to roll back over a
    failed NOTIFY."""
    fake_session = MagicMock()
    fake_session.execute = AsyncMock(side_effect=RuntimeError("conn drop"))

    # Must not raise.
    await notify_scan_progress(fake_session, scan_id="x", kind=KIND_EVENT)
