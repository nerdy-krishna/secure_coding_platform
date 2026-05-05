# src/app/core/services/semgrep_ingestion/selector.py
import logging
from typing import Any

from sqlalchemy.ext.asyncio import AsyncSession

from app.infrastructure.database import models as db_models
from app.infrastructure.database.repositories.semgrep_rule_repo import (
    SemgrepRuleRepository,
)

logger = logging.getLogger(__name__)

# Default allowed licenses — stored / overridden via system_configurations
DEFAULT_ALLOWED_LICENSES = [
    "MIT",
    "Apache-2.0",
    "BSD-2-Clause",
    "BSD-3-Clause",
    "MPL-2.0",
    "LGPL-2.0",
    "LGPL-2.1",
    "LGPL-3.0",
    "Semgrep-Rules-License-1.0",
]

DEFAULT_MAX_RULES_PER_SCAN = 5000


async def _load_ingestion_settings(db: AsyncSession) -> dict[str, Any]:
    """Read semgrep_ingestion.* keys from system_configurations. Returns defaults if not set."""
    from sqlalchemy import select

    result = await db.execute(
        select(db_models.SystemConfiguration).where(
            db_models.SystemConfiguration.key.like("semgrep_ingestion.%")
        )
    )
    rows = {r.key: r.value for r in result.scalars().all()}

    allowed = rows.get("semgrep_ingestion.allowed_licenses", {}).get(
        "licenses", DEFAULT_ALLOWED_LICENSES
    )
    max_rules = rows.get("semgrep_ingestion.max_rules_per_scan", {}).get(
        "value", DEFAULT_MAX_RULES_PER_SCAN
    )
    global_enabled = rows.get("semgrep_ingestion.global_enabled", {}).get("value", True)
    workdir = rows.get("semgrep_ingestion.workdir", {}).get(
        "value",
        "/tmp/sccap-semgrep-rules",  # nosec B108 — configurable default, not a tmpfile call
    )
    sweep_interval = rows.get("semgrep_ingestion.sweep_interval_seconds", {}).get(
        "value", 900
    )
    return {
        "allowed_licenses": (
            allowed if isinstance(allowed, list) else DEFAULT_ALLOWED_LICENSES
        ),
        "max_rules_per_scan": (
            int(max_rules) if max_rules else DEFAULT_MAX_RULES_PER_SCAN
        ),
        "global_enabled": bool(global_enabled),
        "workdir": str(workdir),
        "sweep_interval_seconds": int(sweep_interval) if sweep_interval else 900,
    }


async def select_rules_for_scan(
    languages: list[str],
    technologies: list[str],
    *,
    db: AsyncSession,
) -> list[db_models.SemgrepRule]:
    """Return DB-ingested rules matching the scan's language and technology profile."""
    settings = await _load_ingestion_settings(db)
    if not settings["global_enabled"]:
        logger.info("semgrep.selector.disabled_globally")
        return []
    if not languages:
        return []

    repo = SemgrepRuleRepository(db)
    rules = await repo.select_rules_for_scan(
        languages=languages,
        technologies=technologies,
        allowed_licenses=settings["allowed_licenses"],
        max_rules=settings["max_rules_per_scan"],
    )
    logger.info(
        "semgrep.selector.selected",
        extra={
            "languages": languages,
            "technologies": technologies,
            "rule_count": len(rules),
        },
    )
    return rules


async def get_coverage_summary(
    languages: list[str],
    *,
    db: AsyncSession,
) -> dict:
    """Return coverage summary per language for the pre-scan wizard / readiness panel."""
    settings = await _load_ingestion_settings(db)
    repo = SemgrepRuleRepository(db)
    return await repo.get_coverage_summary(
        languages=languages,
        allowed_licenses=settings["allowed_licenses"],
    )
