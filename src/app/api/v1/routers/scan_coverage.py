# src/app/api/v1/routers/scan_coverage.py
import logging
from typing import List

from fastapi import APIRouter, Depends, Query
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.v1 import models as api_models
from app.infrastructure.auth.core import current_active_user
from app.infrastructure.database import models as db_models
from app.infrastructure.database.database import get_db
from app.core.services.semgrep_ingestion.selector import get_coverage_summary

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/scan-coverage")


@router.get("/check", response_model=api_models.ScanCoverageResponse)
async def check_coverage(
    languages: List[str] = Query(..., alias="languages[]", min_length=1),
    db: AsyncSession = Depends(get_db),
    _user: db_models.User = Depends(current_active_user),
):
    """
    Return per-language coverage status. Used by the pre-scan wizard on the
    submission page to decide whether to prompt the user to enable Semgrep rules.
    """
    summary = await get_coverage_summary(languages, db=db)
    entries = {
        lang: api_models.ScanCoverageEntry(
            covered=data["covered"],
            enabled_rule_count=data["enabled_rule_count"],
            recommended_sources=[
                api_models.RuleSourceRead.model_validate(s)
                for s in data["recommended_sources"]
            ],
        )
        for lang, data in summary.items()
    }
    return api_models.ScanCoverageResponse(coverage=entries)
