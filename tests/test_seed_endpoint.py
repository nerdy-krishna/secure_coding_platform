# tests/test_seed_endpoint.py
#
# Covers POST /api/v1/admin/seed/defaults. Uses httpx's AsyncClient
# against the live FastAPI app with a stubbed auth dependency so we can
# assert the admin-only gate + the SeedResult response shape without a
# real login round-trip.

from __future__ import annotations

import pytest
from httpx import ASGITransport, AsyncClient

from app.infrastructure.auth.core import current_superuser


@pytest.fixture
def make_app():
    """Import main lazily so the test session's DB fixtures get set up
    first. Returns the real FastAPI app."""
    from app.main import app

    return app


@pytest.mark.asyncio
async def test_seed_endpoint_rejects_non_admin(make_app):
    app = make_app

    async def _fake_non_admin():
        from fastapi import HTTPException

        raise HTTPException(status_code=403, detail="not admin")

    app.dependency_overrides[current_superuser] = _fake_non_admin
    try:
        async with AsyncClient(
            transport=ASGITransport(app=app), base_url="http://test"
        ) as client:
            res = await client.post("/api/v1/admin/seed/defaults")
            assert res.status_code == 403
    finally:
        app.dependency_overrides.pop(current_superuser, None)


@pytest.mark.asyncio
async def test_seed_endpoint_admin_returns_seed_result(make_app, seeded_admin):
    app = make_app

    async def _fake_admin():
        return seeded_admin

    app.dependency_overrides[current_superuser] = _fake_admin
    try:
        async with AsyncClient(
            transport=ASGITransport(app=app), base_url="http://test"
        ) as client:
            res = await client.post("/api/v1/admin/seed/defaults")
            assert res.status_code == 200
            body = res.json()
            # SeedResult.as_dict() shape.
            assert set(body.keys()) >= {
                "frameworks_added",
                "agents_added",
                "templates_added",
                "mappings_refreshed",
                "reset",
            }
            assert body["reset"] is False
            assert isinstance(body["frameworks_added"], int)
    finally:
        app.dependency_overrides.pop(current_superuser, None)
