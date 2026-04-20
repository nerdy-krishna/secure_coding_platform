# src/app/api/v1/routers/admin_seed.py
"""Admin-only endpoint to re-seed the platform's default frameworks,
agents, and prompt templates. Used by the "Restore defaults" button
on the Agents / Prompts admin surfaces.

When `reset=true` the existing default rows are dropped first (matches
the historic CLI behaviour). When false, only missing rows are
inserted — safe to spam without destroying admin customisations.
"""

from fastapi import APIRouter, Depends, Query
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.services.default_seed_service import seed_defaults
from app.infrastructure.auth.core import current_superuser
from app.infrastructure.database import models as db_models
from app.infrastructure.database.database import get_db

router = APIRouter(prefix="/admin/seed", tags=["Admin: Seed"])


@router.post("/defaults")
async def seed_platform_defaults(
    reset: bool = Query(
        False,
        description=(
            "If true, delete existing default frameworks / agents / prompt "
            "templates before re-inserting. If false (default), only insert "
            "missing rows."
        ),
    ),
    db: AsyncSession = Depends(get_db),
    _user: db_models.User = Depends(current_superuser),
):
    result = await seed_defaults(db, force_reset=reset)
    return result.as_dict()
