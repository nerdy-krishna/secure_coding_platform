# tests/test_default_seed_service.py
#
# Covers the idempotency contract of default_seed_service.seed_defaults.
# The seed lives at the edge of two lifecycles — app startup + admin
# "restore defaults" button — so regressions here would re-break the
# advisor every time a fresh env boots.

from __future__ import annotations

import pytest
from sqlalchemy import func, select

from app.core.services.default_seed_service import (
    FRAMEWORKS_DATA,
    seed_defaults,
    seed_if_empty,
)
from app.infrastructure.database import models as db_models


@pytest.mark.asyncio
async def test_seed_defaults_produces_baseline_rows(db_session):
    """After seed_defaults, the 3 baseline frameworks always exist (regardless
    of whether the DB already had them from a previous seed — the "empty DB"
    case is covered by idempotency below)."""
    await seed_defaults(db_session, force_reset=False)

    count = await db_session.scalar(
        select(func.count()).select_from(db_models.Framework)
    )
    assert count >= len(FRAMEWORKS_DATA)


@pytest.mark.asyncio
async def test_seed_defaults_is_idempotent(db_session):
    """Running twice in a row inserts zero the second time."""
    first = await seed_defaults(db_session, force_reset=False)
    second = await seed_defaults(db_session, force_reset=False)
    assert second.frameworks_added == 0
    assert second.agents_added == 0
    assert second.templates_added == 0
    # Mappings are always refreshed (cheap upsert), so assert the count
    # is stable rather than zero.
    assert second.mappings_refreshed == first.mappings_refreshed


@pytest.mark.asyncio
async def test_seed_if_empty_no_ops_on_populated_db(db_session):
    # Ensure something exists so the "empty DB" branch doesn't fire.
    await seed_defaults(db_session, force_reset=False)

    result = await seed_if_empty(db_session)
    assert result.frameworks_added == 0
    assert result.agents_added == 0
    assert result.templates_added == 0
    assert result.reset is False
