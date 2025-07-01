# src/app/infrastructure/database/database.py

import logging
from typing import AsyncGenerator

from sqlalchemy.ext.asyncio import (
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)
from sqlalchemy.orm import declarative_base

# It's best practice to use a centralized settings management system
# from `app.config.config` instead of loading environment variables in multiple files.
# This aligns with the overall project structure.
from app.config.config import settings

logger = logging.getLogger(__name__)

# Check if the database URL is configured in the central settings.
if not settings.ASYNC_DATABASE_URL:
    critical_error_msg = (
        "ASYNC_DATABASE_URL is not set in the environment variables or .env file."
    )
    logger.critical(critical_error_msg)
    raise ValueError(critical_error_msg)

# Create an asynchronous SQLAlchemy engine.
# settings.DB_ECHO can be used to toggle SQL query logging for debugging.
engine = create_async_engine(settings.ASYNC_DATABASE_URL, echo=settings.DB_ECHO)

# Create an asynchronous session factory.
# expire_on_commit=False is a good default for FastAPI to prevent issues
# with accessing ORM objects from a session after a commit.
AsyncSessionLocal = async_sessionmaker(
    bind=engine,
    class_=AsyncSession,
    autocommit=False,
    autoflush=False,
    expire_on_commit=False,
)

# Define the declarative base for our ORM models.
# All models in src/app/db/models.py will inherit from this Base.
Base = declarative_base()


async def get_db() -> AsyncGenerator[AsyncSession, None]:
    """
    FastAPI dependency that provides an asynchronous database session.

    The function name 'get_db' is used across the application (e.g., in auth, api endpoints)
    and is required to resolve the ImportError we previously encountered.

    The 'async with' statement correctly handles the session's lifecycle,
    including rollback on exceptions and closing the session, so a try/finally
    block is not needed for this basic dependency.
    """
    async with AsyncSessionLocal() as session:
        yield session


# Note: The 'init_db' function using Base.metadata.create_all() has been omitted.
# This project uses Alembic for database migrations, which is the standard
# for managing database schema changes. Relying on `alembic upgrade head`
# is the correct and safe approach.
