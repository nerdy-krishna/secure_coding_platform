# src/app/api/v1/routers/admin_seed.py
"""Admin-only endpoint to re-seed the platform's default frameworks,
agents, and prompt templates. Used by the "Restore defaults" button
on the Agents / Prompts admin surfaces.

When `reset=true` the existing default rows are dropped first (matches
the historic CLI behaviour). When false, only missing rows are
inserted — safe to spam without destroying admin customisations.

Rate-limiting contract (V02.1.3 / V02.4.1):
- The endpoint accepts at most 3 POST requests per 300 seconds
  (per-process, in-memory sliding window) to guard against
  anti-automation abuse.

Reset cool-down contract (V02.3.2):
- When reset=True a per-platform cool-down of 3600 seconds (1 hour) is
  enforced. The timestamp of the last successful reset is persisted in
  system_config under key "seed.last_reset_at" so the limit survives
  restarts and is global across all admin sessions. A second request
  within the window is rejected with HTTP 429.
"""

import logging
import time
from collections import deque
from typing import Deque

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.v1 import models as api_models
from app.core.services.default_seed_service import seed_defaults
from app.infrastructure.auth.core import current_superuser
from app.infrastructure.database import models as db_models
from app.infrastructure.database.database import get_db
from app.infrastructure.database.repositories.system_config_repo import (
    SystemConfigRepository,
)

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/admin/seed", tags=["Admin: Seed"])

# ---------------------------------------------------------------------------
# Anti-automation rate limiter (V02.4.1)
# Sliding-window: at most _RL_MAX_CALLS within _RL_WINDOW_SECONDS.
# ---------------------------------------------------------------------------
_RL_MAX_CALLS: int = 3
_RL_WINDOW_SECONDS: int = 300
_rl_call_times: Deque[float] = deque()


def _check_endpoint_rate_limit() -> None:
    """Raise HTTP 429 if the sliding-window call count has been exceeded."""
    now = time.monotonic()
    # Evict timestamps outside the current window.
    while _rl_call_times and _rl_call_times[0] <= now - _RL_WINDOW_SECONDS:
        _rl_call_times.popleft()
    if len(_rl_call_times) >= _RL_MAX_CALLS:
        logger.warning("admin.seed.rate_limit_exceeded")
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail=(
                f"Too many requests. At most {_RL_MAX_CALLS} calls are allowed "
                f"every {_RL_WINDOW_SECONDS} seconds."
            ),
        )
    _rl_call_times.append(now)


# ---------------------------------------------------------------------------
# Reset cool-down constant (V02.3.2)
# ---------------------------------------------------------------------------
_RESET_COOLDOWN_SECONDS: int = 3600  # 1 hour
_SEED_RESET_TS_KEY: str = "seed.last_reset_at"


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
    # V02.4.1 — anti-automation: sliding-window rate limit on every call.
    _check_endpoint_rate_limit()

    if reset:
        # V02.3.2 — enforce a 1-hour cool-down between destructive resets.
        config_repo = SystemConfigRepository(db)
        last_reset_row = await config_repo.get_by_key(_SEED_RESET_TS_KEY)
        if last_reset_row is not None:
            last_ts_value = last_reset_row.value.get("ts")
            if last_ts_value is not None:
                elapsed = time.time() - float(last_ts_value)
                if elapsed < _RESET_COOLDOWN_SECONDS:
                    remaining = int(_RESET_COOLDOWN_SECONDS - elapsed)
                    logger.warning(
                        "admin.seed.reset_cooldown_active",
                        extra={"remaining_seconds": remaining},
                    )
                    raise HTTPException(
                        status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                        detail=(
                            f"A destructive seed reset was performed recently. "
                            f"Please wait {remaining} seconds before retrying "
                            f"(cool-down: {_RESET_COOLDOWN_SECONDS}s, V02.3.2)."
                        ),
                    )

    result = await seed_defaults(db, force_reset=reset)

    if reset:
        # Persist the reset timestamp so the cool-down is globally enforced.
        config_repo = SystemConfigRepository(db)
        await config_repo.set_value(
            api_models.SystemConfigurationCreate(
                key=_SEED_RESET_TS_KEY,
                value={"ts": str(time.time())},
                description=(
                    "Timestamp (Unix epoch float) of the last successful "
                    "seed reset. Used to enforce the V02.3.2 reset cool-down."
                ),
                is_secret=False,
                encrypted=False,
            )
        )
        logger.info("admin.seed.reset_timestamp_persisted")

    return result.as_dict()
