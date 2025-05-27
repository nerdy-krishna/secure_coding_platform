# src/app/db/database.py
import os
import logging
from sqlalchemy.ext.asyncio import create_async_engine, async_sessionmaker, AsyncSession
from sqlalchemy.orm import declarative_base
from dotenv import load_dotenv

logger = logging.getLogger(__name__)
load_dotenv() # Load environment variables from .env file

DB_USER = os.getenv("POSTGRES_USER")
DB_PASSWORD = os.getenv("POSTGRES_PASSWORD")
DB_HOST = os.getenv("POSTGRES_HOST", "db") # Default to 'db' for Docker Compose service name
DB_PORT = os.getenv("POSTGRES_PORT", "5432")
DB_NAME = os.getenv("POSTGRES_DB")

if not all([DB_USER, DB_PASSWORD, DB_HOST, DB_PORT, DB_NAME]):
    # This error will be raised when the module is imported if env vars are missing.
    # It's a good practice to ensure critical configurations are present.
    critical_error_msg = "One or more PostgreSQL environment variables are not set (POSTGRES_USER, POSTGRES_PASSWORD, POSTGRES_HOST, POSTGRES_PORT, POSTGRES_DB)"
    logger.critical(critical_error_msg)
    raise ValueError(critical_error_msg)

DATABASE_URL = (
    f"postgresql+asyncpg://{DB_USER}:{DB_PASSWORD}@{DB_HOST}:{DB_PORT}/{DB_NAME}"
)

# Create an asynchronous SQLAlchemy engine
# echo=False is suitable for production. Set to True for debugging SQL queries.
engine = create_async_engine(DATABASE_URL, echo=False)

# Create an asynchronous session factory
AsyncSessionLocal = async_sessionmaker(
    bind=engine,
    class_=AsyncSession,
    expire_on_commit=False # Good default for FastAPI to prevent issues with background tasks
)

# Define the declarative base for ORM models
# All models in models.py will inherit from this Base.
Base = declarative_base()

async def get_db_session() -> AsyncSession:
    """
    Dependency function that provides a database session for FastAPI routes.
    """
    async with AsyncSessionLocal() as session:
        try:
            yield session
        except Exception:
            await session.rollback()
            raise
        finally:
            await session.close()

async def init_db():
    """
    Initializes the database by creating all tables defined by models
    that inherit from Base. This is typically called once at application startup.
    """
    async with engine.begin() as conn:
        # In a production environment with Alembic, you might not run create_all
        # and rely on migrations instead. But for initial setup and development,
        # create_all is convenient.
        # await conn.run_sync(Base.metadata.drop_all) # Optional: for clean slate during dev
        await conn.run_sync(Base.metadata.create_all)
    logger.info("Database tables initialized (if they didn't exist).")