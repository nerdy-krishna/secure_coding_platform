# src/app/api/v1/routers/search.py
"""Global search endpoint.

Consumed by the TopNav combobox; returns grouped hits across projects,
scans, and findings, scoped by H.2 `visible_user_ids`.
"""

from __future__ import annotations

from typing import List, Optional

from fastapi import APIRouter, Depends, Query
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.v1.dependencies import get_visible_user_ids
from app.core.services.search_service import SearchService
from app.infrastructure.auth.core import current_active_user
from app.infrastructure.database import models as db_models
from app.infrastructure.database.database import get_db

router = APIRouter(prefix="/search", tags=["Search"])


def _service(db: AsyncSession = Depends(get_db)) -> SearchService:
    return SearchService(db)


@router.get("")
async def global_search(
    q: str = Query(..., min_length=1, max_length=100),
    limit: int = Query(10, ge=1, le=50),
    _user: db_models.User = Depends(current_active_user),
    visible_user_ids: Optional[List[int]] = Depends(get_visible_user_ids),
    service: SearchService = Depends(_service),
):
    results = await service.search(q, visible_user_ids, limit=limit)
    return results.to_dict()
