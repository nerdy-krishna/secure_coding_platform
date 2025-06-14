# alembic/env.py
import asyncio
import logging
from logging.config import fileConfig
import sys

from sqlalchemy.ext.asyncio import async_engine_from_config
from alembic import context

# This is the Alembic Config object
config = context.config

# Interpret the config file for Python logging.
if config.config_file_name is not None:
    fileConfig(config.config_file_name)

log = logging.getLogger(__name__)

# --- Model Imports & URL Configuration ---
try:
    # Use 'from app...' style, which works with `prepend_sys_path = src`
    from app.db.database import Base
    from app.core.config import settings

    log.info("Successfully imported Base and settings.")

    log.info("Successfully loaded all models from app.db.models.")

    alembic_db_url = str(settings.ALEMBIC_DATABASE_URL)
    if not alembic_db_url:
        raise ValueError("ALEMBIC_DATABASE_URL could not be constructed from settings.")

    config.set_main_option("sqlalchemy.url", alembic_db_url)
    log.info(
        f"Alembic configured with database URL for host: {settings.POSTGRES_HOST_ALEMBIC}"
    )

    target_metadata = Base.metadata
    log.info(
        f"Tables discovered in Base.metadata: {list(target_metadata.tables.keys())}"
    )

except (ImportError, ValueError) as e:
    log.error(f"Failed to configure Alembic: {e}")
    target_metadata = None
# --- End Model Imports ---


def run_migrations_offline() -> None:
    """Run migrations in 'offline' mode."""
    url = config.get_main_option("sqlalchemy.url")
    context.configure(
        url=url,
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
    )
    with context.begin_transaction():
        context.run_migrations()


def do_run_migrations(connection):
    """Helper function for `run_migrations_online`."""
    context.configure(connection=connection, target_metadata=target_metadata)
    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online() -> None:
    """Run migrations in 'online' mode."""
    connectable = async_engine_from_config(
        config.get_section(config.config_ini_section, {}),
        prefix="sqlalchemy.",
    )

    async def run_async_migrations():
        """Connect asynchronously and run migrations."""
        async with connectable.connect() as connection:
            await connection.run_sync(do_run_migrations)

    try:
        asyncio.run(run_async_migrations())
    except KeyboardInterrupt:
        sys.exit(1)


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
