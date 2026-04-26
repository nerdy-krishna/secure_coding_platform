# tests/test_admin_findings_router.py
#
# Covers GET /api/v1/admin/findings (Group D1). Asserts:
# - Non-superuser gets 403
# - Superuser sees cross-tenant findings
# - source filter applies at SQL layer (not Python post-filter)
# - Cursor pagination returns disjoint pages

from __future__ import annotations

import uuid

import pytest
from httpx import ASGITransport, AsyncClient

from app.api.v1.dependencies import get_visible_user_ids
from app.infrastructure.auth.core import current_superuser
from app.infrastructure.database import models as db_models


@pytest.fixture
def make_app():
    from app.main import app

    return app


async def _seed_finding(
    db_session,
    *,
    user: db_models.User,
    project_name: str,
    file_path: str,
    severity: str = "High",
    source: str | None = None,
    title: str = "test finding",
) -> db_models.Finding:
    project = db_models.Project(user_id=user.id, name=project_name)
    db_session.add(project)
    await db_session.flush()
    scan = db_models.Scan(
        id=uuid.uuid4(),
        project_id=project.id,
        user_id=user.id,
        scan_type="AUDIT",
        status="COMPLETED",
        frameworks=["asvs"],
    )
    db_session.add(scan)
    await db_session.flush()
    finding = db_models.Finding(
        scan_id=scan.id,
        file_path=file_path,
        title=title,
        severity=severity,
        source=source,
    )
    db_session.add(finding)
    await db_session.flush()
    return finding


@pytest.mark.asyncio
async def test_admin_findings_rejects_non_superuser(make_app):
    app = make_app

    async def _not_admin():
        from fastapi import HTTPException

        raise HTTPException(status_code=403, detail="not admin")

    app.dependency_overrides[current_superuser] = _not_admin
    try:
        async with AsyncClient(
            transport=ASGITransport(app=app), base_url="http://test"
        ) as client:
            res = await client.get("/api/v1/admin/findings")
            assert res.status_code == 403
    finally:
        app.dependency_overrides.pop(current_superuser, None)


@pytest.mark.asyncio
async def test_admin_findings_lists_cross_tenant_for_superuser(
    make_app, db_session, seeded_user, seeded_admin
):
    app = make_app
    # User-tenant finding.
    await _seed_finding(
        db_session,
        user=seeded_user,
        project_name="user-proj",
        file_path="user.py",
        severity="High",
        source="bandit",
    )
    # Admin's own tenant finding too.
    await _seed_finding(
        db_session,
        user=seeded_admin,
        project_name="admin-proj",
        file_path="admin.py",
        severity="Critical",
        source="gitleaks",
    )

    async def _fake_admin():
        return seeded_admin

    async def _fake_visible_none():
        # Superuser → no scope filter at the SQL layer.
        return None

    async def _override_db():
        # Make the FastAPI app see the same in-flight test transaction
        # so the seeded findings are visible to the route. Without
        # this, get_db() opens a fresh session that misses the
        # SAVEPOINT-scoped fixture data.
        yield db_session

    from app.infrastructure.database.database import get_db

    app.dependency_overrides[current_superuser] = _fake_admin
    app.dependency_overrides[get_visible_user_ids] = _fake_visible_none
    app.dependency_overrides[get_db] = _override_db
    try:
        async with AsyncClient(
            transport=ASGITransport(app=app), base_url="http://test"
        ) as client:
            res = await client.get("/api/v1/admin/findings")
            assert res.status_code == 200
            body = res.json()
            file_paths = {item["file_path"] for item in body["items"]}
            assert {"user.py", "admin.py"}.issubset(file_paths)
    finally:
        app.dependency_overrides.pop(current_superuser, None)
        app.dependency_overrides.pop(get_visible_user_ids, None)
        app.dependency_overrides.pop(get_db, None)


@pytest.mark.asyncio
async def test_admin_findings_source_filter_applies(make_app, db_session, seeded_admin):
    app = make_app
    await _seed_finding(
        db_session,
        user=seeded_admin,
        project_name="bandit-proj",
        file_path="b.py",
        source="bandit",
    )
    await _seed_finding(
        db_session,
        user=seeded_admin,
        project_name="semgrep-proj",
        file_path="s.js",
        source="semgrep",
    )
    await _seed_finding(
        db_session,
        user=seeded_admin,
        project_name="agent-proj",
        file_path="a.py",
        source=None,  # legacy LLM-emitted, source is NULL
    )

    async def _fake_admin():
        return seeded_admin

    async def _fake_visible_none():
        return None

    async def _override_db():
        # Make the FastAPI app see the same in-flight test transaction
        # so the seeded findings are visible to the route. Without
        # this, get_db() opens a fresh session that misses the
        # SAVEPOINT-scoped fixture data.
        yield db_session

    from app.infrastructure.database.database import get_db

    app.dependency_overrides[current_superuser] = _fake_admin
    app.dependency_overrides[get_visible_user_ids] = _fake_visible_none
    app.dependency_overrides[get_db] = _override_db
    try:
        async with AsyncClient(
            transport=ASGITransport(app=app), base_url="http://test"
        ) as client:
            res = await client.get("/api/v1/admin/findings?source=bandit")
            assert res.status_code == 200
            body = res.json()
            sources = {item["source"] for item in body["items"]}
            assert sources == {"bandit"}, f"expected only bandit, got {sources}"
    finally:
        app.dependency_overrides.pop(current_superuser, None)
        app.dependency_overrides.pop(get_visible_user_ids, None)
        app.dependency_overrides.pop(get_db, None)


@pytest.mark.asyncio
async def test_admin_findings_cursor_pagination_is_disjoint(
    make_app, db_session, seeded_admin
):
    app = make_app
    # Seed 5 findings at the same severity so we control ordering.
    for i in range(5):
        await _seed_finding(
            db_session,
            user=seeded_admin,
            project_name=f"proj-{i}",
            file_path=f"f{i}.py",
            severity="Medium",
            source="bandit",
            title=f"finding {i}",
        )

    async def _fake_admin():
        return seeded_admin

    async def _fake_visible_none():
        return None

    async def _override_db():
        # Make the FastAPI app see the same in-flight test transaction
        # so the seeded findings are visible to the route. Without
        # this, get_db() opens a fresh session that misses the
        # SAVEPOINT-scoped fixture data.
        yield db_session

    from app.infrastructure.database.database import get_db

    app.dependency_overrides[current_superuser] = _fake_admin
    app.dependency_overrides[get_visible_user_ids] = _fake_visible_none
    app.dependency_overrides[get_db] = _override_db
    try:
        async with AsyncClient(
            transport=ASGITransport(app=app), base_url="http://test"
        ) as client:
            page1 = await client.get("/api/v1/admin/findings?limit=2")
            assert page1.status_code == 200
            body1 = page1.json()
            assert len(body1["items"]) == 2
            assert body1["next_cursor"] is not None

            page2 = await client.get(
                f"/api/v1/admin/findings?limit=2&cursor={body1['next_cursor']}"
            )
            assert page2.status_code == 200
            body2 = page2.json()
            ids_page1 = {item["id"] for item in body1["items"]}
            ids_page2 = {item["id"] for item in body2["items"]}
            assert ids_page1.isdisjoint(ids_page2), "pages must be disjoint"
    finally:
        app.dependency_overrides.pop(current_superuser, None)
        app.dependency_overrides.pop(get_visible_user_ids, None)
        app.dependency_overrides.pop(get_db, None)
