# alembic/env.py
import asyncio
import logging
from logging.config import fileConfig
import sys
from pathlib import Path

from sqlalchemy.ext.asyncio import create_async_engine
from sqlalchemy.engine import Connection
from alembic import context

# This is the Alembic Config object
config = context.config

# Interpret the config file for Python logging.
if config.config_file_name is not None:
    fileConfig(config.config_file_name)

log = logging.getLogger(__name__)

# --- Model Imports & URL Configuration ---
target_metadata = None
try:
    # Add the project's 'src' directory to the Python path
    # This ensures 'from app...' works when running from the project root
    sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

    from app.db.database import Base
    from app.core.config import settings

    log.info("Successfully imported Base and settings.")
    # Ensure all models are imported so Base.metadata is populated
    import app.db.models

    alembic_db_url = settings.ALEMBIC_DATABASE_URL
    if not alembic_db_url:
        raise ValueError("ALEMBIC_DATABASE_URL could not be constructed from settings.")

    # Set the sqlalchemy.url in the config for Alembic to use
    config.set_main_option("sqlalchemy.url", alembic_db_url)
    log.info(
        f"Alembic configured with database URL for host: {settings.POSTGRES_HOST_ALEMBIC}"
    )

    target_metadata = Base.metadata

except (ImportError, ValueError) as e:
    log.error(f"Failed to configure Alembic: {e}")
# --- End Model Imports ---


# ADDED: This function tells Alembic to ignore the langgraph tables
def include_object(object, name, type_, reflected, compare_to):
    """
    Function to tell Alembic which tables to ignore during autogeneration.
    """
    if type_ == "table" and name in [
        "checkpoints",
        "checkpoint_writes",
        "checkpoint_blobs",
        "checkpoint_migrations",
    ]:
        return False
    else:
        return True

def run_migrations_offline() -> None:
    """Run migrations in 'offline' mode."""
    url = config.get_main_option("sqlalchemy.url")
    context.configure(
        url=url,
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
        # Add these two lines to ensure correct detection
        include_object=include_object,
        compare_type=True,
    )
    with context.begin_transaction():
        context.run_migrations()


def do_run_migrations(connection: Connection):
    """Helper function for `run_migrations_online`."""
    context.configure(
        connection=connection, 
        target_metadata=target_metadata,
        # Add these two lines to ensure correct detection
        include_object=include_object,
        compare_type=True,
    )
    with context.begin_transaction():
        context.run_migrations()


async def run_async_migrations() -> None:
    """Connect asynchronously and run migrations."""
    # We use the URL from settings directly, as it's configured for host access
    db_url = settings.ALEMBIC_DATABASE_URL
    if not db_url:
        raise ValueError("ALEMBIC_DATABASE_URL is not set in settings.")

    connectable = create_async_engine(db_url)

    async with connectable.connect() as connection:
        await connection.run_sync(do_run_migrations)

    await connectable.dispose()


if context.is_offline_mode():
    run_migrations_offline()
else:
    try:
        asyncio.run(run_async_migrations())
    except KeyboardInterrupt:
        sys.exit(1)