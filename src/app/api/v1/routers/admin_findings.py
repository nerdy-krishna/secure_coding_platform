# src/app/api/v1/routers/admin_findings.py
"""Admin-only cross-tenant findings list with source filter.

Path prefix `/admin/findings`. Doubly scoped per N7
(sast-prescan-followups threat model):
1. ``current_superuser`` dependency — only superusers reach the
   route at all (HTTP 403 otherwise).
2. ``visible_user_ids = Depends(get_visible_user_ids)`` — admins
   receive ``None`` (no filter); the helper is forwarded through
   the service layer to the repo, which applies the SQL-layer
   ``Scan.user_id IN (...)`` filter when non-None. Defense-in-depth.

The frontend's `AdminSubNav` shows a "Findings" entry only when
``user.is_superuser`` is true; this router rejects the same call
server-side regardless.
"""

from __future__ import annotations

import logging
import uuid
from datetime import datetime
from typing import List, Literal, Optional

from fastapi import APIRouter, Depends, Query
from pydantic import BaseModel
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.v1.dependencies import get_visible_user_ids
from app.infrastructure.auth.core import current_superuser
from app.infrastructure.database.database import get_db
from app.infrastructure.database.repositories.scan_repo import ScanRepository


logger = logging.getLogger(__name__)

router = APIRouter(prefix="/admin/findings", tags=["Admin: Findings"])


SourceFilter = Literal["bandit", "semgrep", "gitleaks", "osv", "agent"]


class AdminFindingItem(BaseModel):
    """Narrow projection of `Finding` for the admin list view.

    Description / remediation / cvss_vector are intentionally omitted
    here: those are user-tenant data the admin shouldn't be reading
    casually. The list view shows enough to investigate (severity,
    source, file, CWE, scan); details are fetched per-scan via the
    existing scan-result endpoint when needed.
    """

    id: int
    scan_id: uuid.UUID
    file_path: str
    line_number: Optional[int] = None
    title: str
    severity: Optional[str] = None
    cwe: Optional[str] = None
    confidence: Optional[str] = None
    source: Optional[str] = None


class AdminFindingsResponse(BaseModel):
    items: List[AdminFindingItem]
    next_cursor: Optional[int] = None
    requested_at: datetime


@router.get("", response_model=AdminFindingsResponse)
async def list_admin_findings(
    source: Optional[SourceFilter] = Query(
        default=None,
        description="Filter by scanner provenance (bandit/semgrep/gitleaks/agent).",
    ),
    limit: int = Query(default=50, ge=1, le=200),
    cursor: Optional[int] = Query(
        default=None,
        description="Last finding id from the previous page; results returned have id < cursor.",
    ),
    db: AsyncSession = Depends(get_db),
    _user=Depends(current_superuser),
    visible_user_ids: Optional[List[int]] = Depends(get_visible_user_ids),
) -> AdminFindingsResponse:
    repo = ScanRepository(db)
    rows = await repo.query_findings(
        visible_user_ids=visible_user_ids,
        source_filter=source,
        limit=limit,
        cursor=cursor,
    )
    items = [
        AdminFindingItem(
            id=row.id,
            scan_id=row.scan_id,
            file_path=row.file_path,
            line_number=row.line_number,
            title=row.title,
            severity=row.severity,
            cwe=row.cwe,
            confidence=row.confidence,
            source=row.source,
        )
        for row in rows
    ]
    next_cursor = items[-1].id if len(items) == limit else None
    return AdminFindingsResponse(
        items=items,
        next_cursor=next_cursor,
        requested_at=datetime.utcnow(),
    )
