# src/app/api/v1/routers/compliance.py
"""Public compliance endpoints consumed by the Compliance page.

Scope: per-framework rollup for the current user. `visible_user_ids` is
computed from the authenticated user (None → admin, [user.id] → regular
user). User Groups (H.2) will extend that list with peer user_ids; this
file does not need to know — it just passes the list through to the
service.
"""

from typing import List, Optional

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.services.compliance_service import (
    ComplianceService,
    get_compliance_service,
)
from app.infrastructure.auth.core import current_active_user
from app.infrastructure.database import models as db_models
from app.infrastructure.database.database import get_db
from app.infrastructure.rag.rag_client import RAGService, get_rag_service

router = APIRouter(prefix="/compliance", tags=["Compliance"])


def _visible_user_ids(user: db_models.User) -> Optional[List[int]]:
    """Superusers see everything; regular users see their own scans only.

    H.2 will replace this with a helper that expands the list using
    user_group_memberships. Keeping the stub here makes the swap a
    one-line edit per consumer.
    """
    if user.is_superuser:
        return None
    return [user.id]


def _service(
    db: AsyncSession = Depends(get_db),
    rag: Optional[RAGService] = Depends(get_rag_service),
) -> ComplianceService:
    return get_compliance_service(db, rag)


@router.get("/stats")
async def list_framework_stats(
    user: db_models.User = Depends(current_active_user),
    service: ComplianceService = Depends(_service),
):
    """Per-framework doc/findings/score rollup.

    Always returns the 3 default frameworks (asvs, proactive_controls,
    cheatsheets) even when no documents are ingested. Custom frameworks
    from the `frameworks` table follow.
    """
    return await service.get_stats(_visible_user_ids(user))


@router.get("/frameworks/{framework_name}/controls")
async def list_framework_controls(
    framework_name: str,
    user: db_models.User = Depends(current_active_user),
    service: ComplianceService = Depends(_service),
):
    """RAG-backed control list for the drill-in section.

    Groups documents by `control_id` / `section` / `title` metadata;
    falls back to a single "overview" bucket when none of those exist.
    """
    try:
        return await service.get_controls(framework_name)
    except ConnectionError as exc:
        raise HTTPException(status_code=503, detail=str(exc))
