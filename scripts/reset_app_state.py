import asyncio
import sys
import os
import logging
import getpass
import socket

# Add project root
sys.path.append(os.getcwd())
sys.path.append(os.path.join(os.getcwd(), "src"))

from sqlalchemy import text
from app.infrastructure.database.database import AsyncSessionLocal

logger = logging.getLogger(__name__)


async def reset_app():
    # Confirmation prompt before destructive reset (V13.3.2 / V02.2.3)
    confirm = input("This will DESTROY ALL DATA. Type 'RESET' to confirm: ")
    if confirm.strip() != "RESET":
        logger.info("Reset aborted by user.")
        print("Aborted.")
        sys.exit(0)

    # Audit log of reset initiation with actor identity (V16.3.2 / V16.3.3 / V16.3.1)
    logger.warning(
        "AUDIT: app state reset initiated: actor=%s host=%s",
        getpass.getuser(),
        socket.gethostname(),
    )

    async with AsyncSessionLocal() as session:
        logger.info("Resetting database...")
        # Truncate core tables with CASCADE to wipe all related data (projects, scans, etc.)
        tables = ["system_configurations", "llm_configurations", '"user"']

        for table in tables:
            try:
                await session.execute(text(f"TRUNCATE TABLE {table} CASCADE;"))
                logger.info("Truncated %s with CASCADE", table)
            except Exception:
                # Log full exception details internally; surface only a sanitized message (V16.4.1)
                logger.exception("Error truncating table %s", table)
                print("Error truncating table. Check logs for details.")

        await session.commit()
        logger.info("Database reset successfully.")


if __name__ == "__main__":
    asyncio.run(reset_app())
