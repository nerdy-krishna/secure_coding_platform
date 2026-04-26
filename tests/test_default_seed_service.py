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
async def test_seed_attaches_llm_agents_only_to_ai_frameworks(db_session):
    """§3.11 selective mapping: `LLMSecurityAgent` must attach ONLY to
    `llm_top10`, `AgenticSecurityAgent` must attach ONLY to
    `agentic_top10`, and they must NOT pollute the legacy AppSec
    frameworks (asvs / proactive_controls / cheatsheets). Legacy
    agents must still attach to all three AppSec frameworks."""
    from sqlalchemy.orm import selectinload

    await seed_defaults(db_session, force_reset=True)

    # Re-fetch with eager-loaded agents per framework.
    rows = await db_session.execute(
        select(db_models.Framework).options(
            selectinload(db_models.Framework.agents)
        )
    )
    fws_by_name = {fw.name: fw for fw in rows.scalars().all()}

    asvs_agent_names = {a.name for a in fws_by_name["asvs"].agents}
    llm_agent_names = {a.name for a in fws_by_name["llm_top10"].agents}
    agentic_agent_names = {a.name for a in fws_by_name["agentic_top10"].agents}

    # AI agents are NOT attached to ASVS.
    assert "LLMSecurityAgent" not in asvs_agent_names
    assert "AgenticSecurityAgent" not in asvs_agent_names

    # LLMSecurityAgent attached only to llm_top10.
    assert "LLMSecurityAgent" in llm_agent_names
    assert "AgenticSecurityAgent" not in llm_agent_names

    # AgenticSecurityAgent attached only to agentic_top10.
    assert "AgenticSecurityAgent" in agentic_agent_names
    assert "LLMSecurityAgent" not in agentic_agent_names

    # Legacy AppSec agents still attached to ASVS.
    assert "AccessControlAgent" in asvs_agent_names
    assert "AuthenticationAgent" in asvs_agent_names
    # Legacy agents NOT attached to the AI frameworks.
    assert "AccessControlAgent" not in llm_agent_names
    assert "AccessControlAgent" not in agentic_agent_names


@pytest.mark.asyncio
async def test_seed_if_empty_no_ops_on_populated_db(db_session):
    # Ensure something exists so the "empty DB" branch doesn't fire.
    await seed_defaults(db_session, force_reset=False)

    result = await seed_if_empty(db_session)
    assert result.frameworks_added == 0
    assert result.agents_added == 0
    assert result.templates_added == 0
    assert result.reset is False
