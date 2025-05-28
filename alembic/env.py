# alembic/env.py
import os
import sys
from logging.config import fileConfig
import logging

from sqlalchemy import engine_from_config
from sqlalchemy import pool

from alembic import context

from dotenv import load_dotenv
import pathlib

# This logger should be configured by alembic.ini via fileConfig()
log = logging.getLogger("alembic.env")

log.info("[ENV.PY] Script execution started.")

# --- Add project root to sys.path ---
PROJECT_ROOT = pathlib.Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))
    log.info(f"[ENV.PY] Project root '{PROJECT_ROOT}' added to sys.path.")
else:
    log.info(f"[ENV.PY] Project root '{PROJECT_ROOT}' already in sys.path.")


# --- Alembic Config (the Config object, not fileConfig) ---
# This is the Alembic Config object, which provides
# access to the values within the .ini file in use.
config = context.config

# Interpret the config file for Python logging.
# This line sets up loggers based on the settings in alembic.ini.
if config.config_file_name:
    fileConfig(config.config_file_name)
    log.info(f"[ENV.PY] Logging configured from: {config.config_file_name}")
else:
    log.warning("[ENV.PY] No config file name found in Alembic context for logging.")


# --- Target Metadata Setup ---
# Import Base from your application.
# This import should trigger src/app/db/__init__.py, which in turn
# should import src.app.db.models, populating Base.metadata.
target_metadata = None
try:
    from src.app.db.database import Base

    log.info("[ENV.PY] Imported Base from src.app.db.database.")

    # The following explicit import is to be absolutely sure models are loaded.
    # If your src/app/db/__init__.py is correctly importing .models, this might be redundant
    # but doesn't hurt for ensuring Alembic sees the models.
    import src.app.db.models  # noqa: F401 # Add noqa to ignore F401 for this line

    log.info("[ENV.PY] Ensured src.app.db.models is imported.")

    # For future use when auth_models.py is created:
    # try:
    #     import src.app.auth.models
    #     log.info("[ENV.PY] Ensured src.app.auth.models is imported (if it exists).")
    # except ImportError:
    #     log.info("[ENV.PY] src.app.auth.models not found (expected if not yet created).")

    target_metadata = Base.metadata
    log.info(
        f"[ENV.PY] Target metadata set. Tables discovered: {list(target_metadata.tables.keys())}"
    )
    if not list(target_metadata.tables.keys()):
        log.warning(
            "[ENV.PY] WARNING: No tables found in Base.metadata. Check model definitions and imports."
        )

except ImportError as e:
    log.error(
        f"[ENV.PY] CRITICAL IMPORT ERROR: {e}. Autogenerate will likely fail or be empty.",
        exc_info=True,
    )
    # Fallback to prevent Alembic from crashing if Base/models cannot be imported.
    from sqlalchemy import MetaData

    target_metadata = MetaData()
except Exception as e:
    log.error(f"[ENV.PY] UNEXPECTED ERROR during metadata setup: {e}", exc_info=True)
    from sqlalchemy import MetaData

    target_metadata = MetaData()


def get_db_url_from_env():
    dotenv_path = PROJECT_ROOT / ".env"
    if os.path.exists(dotenv_path):
        load_dotenv(dotenv_path=dotenv_path)

    # Use POSTGRES_HOST_ALEMBIC if set (for local CLI), else POSTGRES_HOST, else 'localhost'
    db_host = os.getenv(
        "POSTGRES_HOST_ALEMBIC", os.getenv("POSTGRES_HOST", "localhost")
    )

    # Ensure all required components are present
    user, password, db_name, port = (
        os.getenv("POSTGRES_USER"),
        os.getenv("POSTGRES_PASSWORD"),
        os.getenv("POSTGRES_DB"),
        os.getenv("POSTGRES_PORT", "5432"),
    )
    if not all([user, password, db_name]):
        msg = "[ENV.PY] Database connection details (USER, PASSWORD, DB) not found in .env"
        log.error(msg)
        raise ValueError(msg)

    url = f"postgresql://{user}:{password}@{db_host}:{port}/{db_name}"
    log.info(f"[ENV.PY] Constructed database URL: {url.replace(password, '******')}")
    return url


def run_migrations_offline() -> None:
    """Run migrations in 'offline' mode."""
    log.info("[ENV.PY] Running migrations offline.")
    url = get_db_url_from_env()  # Get URL from .env
    context.configure(
        url=url,
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
    )
    with context.begin_transaction():
        context.run_migrations()
    log.info("[ENV.PY] Offline migrations complete.")


def run_migrations_online() -> None:
    """Run migrations in 'online' mode."""
    log.info("[ENV.PY] Running migrations online.")

    # Get the database URL from .env and set it in Alembic's config object
    # This ensures engine_from_config uses the correct URL from .env
    db_url = get_db_url_from_env()
    # config is the Alembic Config object, already available globally in env.py
    config.set_main_option("sqlalchemy.url", db_url)

    connectable = engine_from_config(
        config.get_section(
            config.config_ini_section, {}
        ),  # Pass the entire config section
        prefix="sqlalchemy.",
        poolclass=pool.NullPool,
        future=True,
    )

    with connectable.connect() as connection:
        log.info("[ENV.PY] Online: Database connection established.")
        context.configure(connection=connection, target_metadata=target_metadata)
        log.info("[ENV.PY] Online: Alembic context configured.")
        with context.begin_transaction():
            log.info("[ENV.PY] Online: Beginning transaction.")
            context.run_migrations()  # This performs the comparison for autogenerate
        log.info("[ENV.PY] Online: Transaction complete, migrations run.")
    log.info("[ENV.PY] Online migrations complete.")


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()

log.info("[ENV.PY] Script execution finished.")
