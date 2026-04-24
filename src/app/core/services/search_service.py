# src/app/core/services/search_service.py
"""Global search service.

Powers `GET /api/v1/search?q=...`. Three parallel ILIKE queries against
projects, scans, and findings, each scoped by `visible_user_ids`
(None → admin sees everything). No Postgres full-text index yet — the
tables are small and ILIKE on trigram-friendly columns is snappy enough
until we hit a scale wall.

The payload is intentionally thin: the TopNav combobox needs just
enough to render a result row (title + id + breadcrumb). Result
pages load their own details.
"""

from __future__ import annotations

import logging
import uuid
from dataclasses import dataclass
from typing import List, Optional

import sqlalchemy as sa
from sqlalchemy import String, cast, or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.infrastructure.database import models as db_models

logger = logging.getLogger(__name__)


@dataclass
class ProjectHit:
    id: uuid.UUID
    name: str
    matched_on: str = "name"


@dataclass
class ScanHit:
    id: uuid.UUID
    project_name: str
    status: str
    matched_on: str = "scan_id_prefix"


@dataclass
class FindingHit:
    id: int
    scan_id: uuid.UUID
    title: str
    file_path: str
    severity: Optional[str]
    matched_on: str = "title"


@dataclass
class SearchResults:
    projects: List[ProjectHit]
    scans: List[ScanHit]
    findings: List[FindingHit]

    def to_dict(self) -> dict:
        return {
            "projects": [p.__dict__ for p in self.projects],
            "scans": [{**s.__dict__, "id": str(s.id)} for s in self.scans],
            "findings": [
                {**f.__dict__, "scan_id": str(f.scan_id)} for f in self.findings
            ],
        }


class SearchService:
    def __init__(self, db: AsyncSession):
        self.db = db

    async def search(
        self,
        query: str,
        visible_user_ids: Optional[List[int]],
        limit: int,
    ) -> SearchResults:
        query = query.strip()
        if not query:
            return SearchResults(projects=[], scans=[], findings=[])

        scope_scan_col = self._scope(db_models.Scan.user_id, visible_user_ids)
        scope_project_col = self._scope(db_models.Project.user_id, visible_user_ids)
        pattern = f"%{query}%"

        projects = await self._search_projects(pattern, scope_project_col, limit)
        scans = await self._search_scans(pattern, scope_scan_col, limit)
        findings = await self._search_findings(pattern, scope_scan_col, limit)
        return SearchResults(projects=projects, scans=scans, findings=findings)

    # --- internals ------------------------------------------------------

    @staticmethod
    def _scope(
        column: sa.ColumnElement[int], visible_user_ids: Optional[List[int]]
    ) -> sa.ColumnElement[bool]:
        if visible_user_ids is None:
            return sa.true()
        if not visible_user_ids:
            return sa.false()
        return column.in_(visible_user_ids)

    async def _search_projects(
        self, pattern: str, scope: sa.ColumnElement[bool], limit: int
    ) -> List[ProjectHit]:
        stmt = (
            select(db_models.Project.id, db_models.Project.name)
            .where(scope)
            .where(db_models.Project.name.ilike(pattern))
            .order_by(db_models.Project.updated_at.desc())
            .limit(limit)
        )
        rows = (await self.db.execute(stmt)).all()
        return [ProjectHit(id=r[0], name=r[1]) for r in rows]

    async def _search_scans(
        self, pattern: str, scope: sa.ColumnElement[bool], limit: int
    ) -> List[ScanHit]:
        # Scan IDs are UUIDs; users usually paste a prefix. Cast to text and
        # ILIKE so both full and prefix matches work.
        stmt = (
            select(
                db_models.Scan.id,
                db_models.Scan.status,
                db_models.Project.name,
            )
            .join(db_models.Project, db_models.Project.id == db_models.Scan.project_id)
            .where(scope)
            .where(cast(db_models.Scan.id, String).ilike(pattern))
            .order_by(db_models.Scan.created_at.desc())
            .limit(limit)
        )
        rows = (await self.db.execute(stmt)).all()
        return [ScanHit(id=r[0], status=r[1], project_name=r[2]) for r in rows]

    async def _search_findings(
        self, pattern: str, scope: sa.ColumnElement[bool], limit: int
    ) -> List[FindingHit]:
        # Match on title OR file_path; annotate `matched_on` so the UI can
        # show users why a row came back even when the match is in the path.
        title_match = db_models.Finding.title.ilike(pattern)
        path_match = db_models.Finding.file_path.ilike(pattern)
        stmt = (
            select(
                db_models.Finding.id,
                db_models.Finding.scan_id,
                db_models.Finding.title,
                db_models.Finding.file_path,
                db_models.Finding.severity,
                title_match.label("title_matched"),
            )
            .join(db_models.Scan, db_models.Scan.id == db_models.Finding.scan_id)
            .where(scope)
            .where(or_(title_match, path_match))
            .order_by(db_models.Finding.id.desc())
            .limit(limit)
        )
        rows = (await self.db.execute(stmt)).all()
        return [
            FindingHit(
                id=r[0],
                scan_id=r[1],
                title=r[2],
                file_path=r[3],
                severity=r[4],
                matched_on="title" if r[5] else "file_path",
            )
            for r in rows
        ]
