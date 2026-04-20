# src/app/scripts/populate_agents_and_frameworks.py
"""CLI wrapper around `default_seed_service.seed_defaults`.

The data lives in app.core.services.default_seed_service so the same
source of truth backs:
- this script (for bootstrapping from shell),
- the startup auto-seed hook in main.py, and
- the admin endpoint `POST /api/v1/admin/seed/defaults`.

Run with: `docker compose exec app python -m app.scripts.populate_agents_and_frameworks [--reset]`
"""

import argparse
import asyncio
import logging

from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from app.config.config import settings
from app.core.services.default_seed_service import seed_defaults

logging.basicConfig(
    level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger(__name__)


async def main(reset: bool) -> None:
    logger.info(
        "Running default-seed (reset=%s) against %s",
        reset,
        settings.ASYNC_DATABASE_URL,
    )
    if not settings.ASYNC_DATABASE_URL:
        raise ValueError("ASYNC_DATABASE_URL not set!")

    engine = create_async_engine(settings.ASYNC_DATABASE_URL)
    session_factory = async_sessionmaker(engine, expire_on_commit=False)
    async with session_factory() as session:
        result = await seed_defaults(session, force_reset=reset)

    logger.info("Seed complete: %s", result.as_dict())


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Seed platform defaults.")
    parser.add_argument(
        "--reset",
        action="store_true",
        help=(
            "Delete managed frameworks / agents / prompt templates before "
            "re-inserting (matches the original populate behaviour). Omit "
            "to only insert missing rows."
        ),
    )
    args = parser.parse_args()
    asyncio.run(main(args.reset))
