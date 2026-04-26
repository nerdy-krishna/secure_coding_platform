"""Unit tests for the findings.source backfill sweeper (Feature-7 B3).

Defensive backfill of `findings.source IS NULL` rows. With the LLM
agent now stamping `source="agent"` at write time (B1), this should
be a no-op in steady state — bounded UPDATE per pass, single COUNT
when the table is clean.
"""

from __future__ import annotations

import asyncio
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

pytestmark = pytest.mark.asyncio


def _fake_session(null_count: int = 0, rowcount: int = 0):
    """A MagicMock standing in for an AsyncSessionLocal context manager.

    `null_count` is what the COUNT(*) precheck returns; `rowcount` is
    what the bounded UPDATE reports. The execute() call sequence is
    SELECT then (optionally) UPDATE — `side_effect` returns them in
    order.
    """
    fake = MagicMock()
    fake.__aenter__ = AsyncMock(return_value=fake)
    fake.__aexit__ = AsyncMock(return_value=False)
    fake.commit = AsyncMock()

    select_result = MagicMock()
    select_result.scalar_one = MagicMock(return_value=null_count)

    update_result = MagicMock()
    update_result.rowcount = rowcount

    fake.execute = AsyncMock(side_effect=[select_result, update_result])
    return fake


async def test_sweep_is_no_op_when_no_null_rows() -> None:
    """Steady state: COUNT returns 0 → no UPDATE issued, no commit."""
    from app.infrastructure.messaging import findings_source_sweeper as mod

    fake = _fake_session(null_count=0)
    with patch.object(mod, "AsyncSessionLocal", lambda: fake):
        result = await mod._sweep_once()

    assert result == 0
    # Only the COUNT was executed.
    assert fake.execute.await_count == 1
    fake.commit.assert_not_called()


async def test_sweep_backfills_null_rows() -> None:
    """COUNT returns 5 → UPDATE issued, returns rowcount."""
    from app.infrastructure.messaging import findings_source_sweeper as mod

    fake = _fake_session(null_count=5, rowcount=5)
    with patch.object(mod, "AsyncSessionLocal", lambda: fake):
        result = await mod._sweep_once()

    assert result == 5
    assert fake.execute.await_count == 2  # SELECT + UPDATE
    fake.commit.assert_awaited_once()


async def test_run_sweeper_stops_on_event() -> None:
    """The outer loop exits cleanly when `stop_event` is set."""
    from app.infrastructure.messaging import findings_source_sweeper as mod

    stop_event = asyncio.Event()

    async def _stop_after_first_pass() -> int:
        stop_event.set()
        return 0

    with patch.object(mod, "_sweep_once", side_effect=_stop_after_first_pass):
        with patch.object(mod, "SWEEPER_INTERVAL_SECONDS", 0.05):
            await asyncio.wait_for(
                mod.run_findings_source_sweeper(stop_event), timeout=2.0
            )
