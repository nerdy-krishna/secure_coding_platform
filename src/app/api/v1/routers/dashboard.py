# src/app/api/v1/routers/dashboard.py
"""Dashboard rollup endpoint.

Returns one blob the UI can consume without client-side aggregation.
Scope is H.2 `visible_user_ids`: admins see platform-wide, regular
users see themselves plus their group peers.
"""

from __future__ import annotations

from typing import List, Optional

from fastapi import APIRouter, Depends
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.v1.dependencies import get_visible_user_ids
from app.core.services.dashboard_service import DashboardService
from app.infrastructure.auth.core import current_active_user
from app.infrastructure.database import models as db_models
from app.infrastructure.database.database import get_db

router = APIRouter(prefix="/dashboard", tags=["Dashboard"])


def _service(db: AsyncSession = Depends(get_db)) -> DashboardService:
    return DashboardService(db)


@router.get("/stats")
async def get_dashboard_stats(
    _user: db_models.User = Depends(current_active_user),
    visible_user_ids: Optional[List[int]] = Depends(get_visible_user_ids),
    service: DashboardService = Depends(_service),
):
    stats = await service.get_stats(visible_user_ids)
    return stats.to_dict()
