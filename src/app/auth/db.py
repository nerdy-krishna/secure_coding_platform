# src/app/auth/db.py
from typing import AsyncGenerator
from fastapi import Depends
from fastapi_users_db_sqlalchemy import SQLAlchemyUserDatabase
from sqlalchemy.ext.asyncio import AsyncSession

# Import your User model and the AsyncSessionLocal from your main database setup
from .models import User
from src.app.db.database import AsyncSessionLocal # Corrected import path from ..db.database

async def get_async_session() -> AsyncGenerator[AsyncSession, None]:
    """
    Dependency to get an SQLAlchemy async database session.
    Uses the global AsyncSessionLocal factory.
    """
    async with AsyncSessionLocal() as session:
        yield session

async def get_user_db(session: AsyncSession = Depends(get_async_session)):
    """
    Dependency to get the SQLAlchemyUserDatabase adapter.
    This adapter is used by FastAPI Users to interact with the User model.
    """
    yield SQLAlchemyUserDatabase(session, User)