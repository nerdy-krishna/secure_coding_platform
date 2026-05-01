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
import getpass
import logging
import socket
import sys
import time
from urllib.parse import urlparse

from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from app.config.config import settings
from app.core.services.default_seed_service import seed_defaults

logging.basicConfig(
    level=logging.INFO, format="%(asctime)sZ - %(levelname)s - %(message)s"
)
logging.Formatter.converter = time.gmtime
logger = logging.getLogger(__name__)


async def main(reset: bool) -> None:
    if not settings.ASYNC_DATABASE_URL:
        raise ValueError("ASYNC_DATABASE_URL not set!")

    parsed_url = urlparse(str(settings.ASYNC_DATABASE_URL))
    safe_url = (
        f"{parsed_url.scheme}://{parsed_url.username or ''}@"
        f"{parsed_url.hostname}:{parsed_url.port or ''}/{parsed_url.path.lstrip('/')}"
    )
    logger.warning(
        "audit.seed.start operator=%s host=%s reset=%s",
        getpass.getuser(),
        socket.gethostname(),
        reset,
    )
    logger.info(
        "Running default-seed (reset=%s) against %s",
        reset,
        safe_url,
    )

    engine = create_async_engine(settings.ASYNC_DATABASE_URL)
    session_factory = async_sessionmaker(engine, expire_on_commit=False)
    try:
        async with session_factory() as session:
            result = await seed_defaults(session, force_reset=reset)
    except Exception as exc:
        logger.error(
            "audit.seed.failed operator=%s host=%s reset=%s err=%s",
            getpass.getuser(),
            socket.gethostname(),
            reset,
            exc,
            exc_info=True,
        )
        raise

    logger.info("Seed complete: %s", result.as_dict())
    logger.warning(
        "audit.seed.complete operator=%s host=%s reset=%s frameworks_added=%s agents_added=%s templates_added=%s",
        getpass.getuser(),
        socket.gethostname(),
        reset,
        result.frameworks_added,
        result.agents_added,
        result.templates_added,
    )


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
    if args.reset:
        confirm = input("Type RESET to confirm destructive seed wipe: ")
        if confirm.strip() != "RESET":
            sys.exit("Aborted: confirmation phrase did not match.")
    asyncio.run(main(args.reset))
