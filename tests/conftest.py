# tests/conftest.py
#
# Minimal pytest scaffolding for the SCCAP backend. Each test runs
# inside a SAVEPOINT rollback transaction against the real Postgres
# from docker-compose (same DB the dev stack uses) — the point is
# behavioural fidelity, not isolation via a mock. Nothing persists
# across tests.
#
# Fixtures:
#   - `db_session`: async SQLAlchemy session bound to a transaction that
#     rolls back on teardown.
#   - `seeded_user` / `seeded_admin`: creates a User row inside the test
#     transaction. Rolled back with it.
#   - `mock_llm_client`: monkeypatches `get_llm_client` to return a stub
#     that emits a caller-supplied Pydantic response, so service layer
#     tests don't need network / real API keys.
#
# Usage:
#     docker compose exec app poetry install --with test
#     docker compose exec app poetry run pytest

from __future__ import annotations

import uuid
from typing import AsyncIterator, Callable, Optional, Type
from unittest.mock import AsyncMock

import pytest
import pytest_asyncio
from pydantic import BaseModel
from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)

from app.config.config import settings
from app.infrastructure.database import models as db_models
from app.infrastructure.llm_client import AgentLLMResult


# ----------------------------------------------------------------------
# Database engine — one per test session. docker-compose's postgres is
# the target; tests expect `alembic upgrade head` to have been run.
# ----------------------------------------------------------------------


@pytest.fixture(autouse=True)
def _propagate_app_logger():
    """Ensure `logging.getLogger("app")` propagates so pytest's caplog
    can capture records from submodules. `logging_config.setup` (loaded
    on first FastAPI app import inside the test session) sets
    `propagate=False` for the "app" logger; that silences caplog for
    every subsequent test that depends on it. Flip it for the test,
    restore after.
    """
    import logging

    logger = logging.getLogger("app")
    original = logger.propagate
    logger.propagate = True
    try:
        yield
    finally:
        logger.propagate = original


@pytest_asyncio.fixture
async def db_engine() -> AsyncIterator[AsyncEngine]:
    """Per-test async engine.

    pytest-asyncio spins up a fresh event loop per test by default, so
    a session-scoped engine would have its asyncpg pool tied to an
    already-closed loop. Keeping the engine function-scoped is slightly
    slower but avoids the cross-loop asyncpg errors.
    """
    engine = create_async_engine(
        settings.ASYNC_DATABASE_URL, future=True, poolclass=None
    )
    try:
        yield engine
    finally:
        await engine.dispose()


@pytest_asyncio.fixture
async def db_session(db_engine: AsyncEngine) -> AsyncIterator[AsyncSession]:
    """Per-test session wrapped in a transaction + SAVEPOINT.

    The outer transaction is rolled back on teardown so every test runs
    on a clean slate even when repository code commits.

    `join_transaction_mode="create_savepoint"` is load-bearing: it tells
    the session to wrap its work in a SAVEPOINT inside the outer
    transaction, so a `session.commit()` from production code (e.g.
    `framework_repo.create_framework`) releases the SAVEPOINT instead
    of committing — and crucially, the outer transaction stays open so
    subsequent operations like `session.refresh()` don't blow up with
    `InvalidRequestError: Can't operate on closed transaction`. Without
    this, any repo method that does the standard
    `add → commit → refresh` SQLAlchemy 2.x pattern fails the moment
    it's exercised under the `db_session` fixture.
    """
    async with db_engine.connect() as connection:
        trans = await connection.begin()
        Session = async_sessionmaker(
            bind=connection,
            expire_on_commit=False,
            class_=AsyncSession,
            join_transaction_mode="create_savepoint",
        )
        session = Session()
        try:
            yield session
        finally:
            await session.close()
            if trans.is_active:
                await trans.rollback()


# ----------------------------------------------------------------------
# User fixtures
# ----------------------------------------------------------------------


@pytest_asyncio.fixture
async def seeded_user(db_session: AsyncSession) -> db_models.User:
    """Regular active user, rolled back at end of test."""
    user = db_models.User(
        email=f"user-{uuid.uuid4().hex[:8]}@sccap.test",
        hashed_password="x" * 64,  # never used — auth is mocked elsewhere
        is_active=True,
        is_superuser=False,
        is_verified=True,
    )
    db_session.add(user)
    await db_session.flush()
    return user


@pytest_asyncio.fixture
async def seeded_admin(db_session: AsyncSession) -> db_models.User:
    """Superuser, rolled back at end of test."""
    user = db_models.User(
        email=f"admin-{uuid.uuid4().hex[:8]}@sccap.test",
        hashed_password="x" * 64,
        is_active=True,
        is_superuser=True,
        is_verified=True,
    )
    db_session.add(user)
    await db_session.flush()
    return user


# ----------------------------------------------------------------------
# LLM client mock — avoids real API calls in service-layer tests.
# ----------------------------------------------------------------------


@pytest.fixture
def mock_llm_client(
    monkeypatch: pytest.MonkeyPatch,
) -> Callable[[BaseModel], AsyncMock]:
    """Returns a factory: `mock_llm_client(ChatResponse(response="hi"))`.

    The factory installs a module-level monkeypatch so
    `get_llm_client(uuid)` awaits to a stub whose
    `generate_structured_output` returns the supplied Pydantic instance
    wrapped in an `AgentLLMResult`. Token counts are synthetic
    (100/50) and cost is 0.0 — tests that care about cost should
    exercise the real `cost_estimation` module against a real model.
    """

    def _factory(
        parsed_output: BaseModel,
        *,
        error: Optional[str] = None,
    ) -> AsyncMock:
        stub = AsyncMock(name="LLMClient")

        async def _gen(
            prompt: str,
            response_model: Type[BaseModel],
            system_prompt: Optional[str] = None,
        ) -> AgentLLMResult:
            return AgentLLMResult(
                raw_output="[mock]",
                parsed_output=parsed_output if error is None else None,
                error=error,
                cost=0.0,
                prompt_tokens=100,
                completion_tokens=50,
                total_tokens=150,
                latency_ms=5,
            )

        stub.generate_structured_output = _gen
        stub.provider_name = "mock"

        async def _get_client(_llm_config_id: uuid.UUID):
            return stub

        monkeypatch.setattr("app.infrastructure.llm_client.get_llm_client", _get_client)
        return stub

    return _factory
