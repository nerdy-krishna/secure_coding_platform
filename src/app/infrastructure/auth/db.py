# src/app/infrastructure/auth/db.py
from fastapi import Depends
from fastapi_users.db import SQLAlchemyUserDatabase
from sqlalchemy.ext.asyncio import AsyncSession

from app.infrastructure.database.models import User

# --- START: THE FINAL FIX ---
# Import the correctly named dependency from the central database module.
from app.infrastructure.database.database import get_db
# --- END: THE FINAL FIX ---


# --- START: CORRECTED DEPENDENCY USAGE ---
# The dependency passed to Depends() must match the name of the imported function.
async def get_user_db(session: AsyncSession = Depends(get_db)):
    # --- END: CORRECTED DEPENDENCY USAGE ---
    """
    Dependency to get the SQLAlchemyUserDatabase adapter.
    This adapter is used by FastAPI Users to interact with the User model.
    """
    yield SQLAlchemyUserDatabase(session, User)
