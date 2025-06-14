# src/app/auth/manager.py
import logging
from typing import Optional

from fastapi import Depends, Request

# --- START: CORRECTED IMPORTS ---
# Import IntegerIDMixin
from fastapi_users import BaseUserManager, IntegerIDMixin
# --- END: CORRECTED IMPORTS ---

from app.db.models import User
from app.auth.db import get_user_db
from app.core.config import settings

logger = logging.getLogger(__name__)


# --- START: CORRECTED CLASS DEFINITION ---
# Add the IntegerIDMixin to handle integer-based user IDs.
class UserManager(IntegerIDMixin, BaseUserManager[User, int]):
    # --- END: CORRECTED CLASS DEFINITION ---
    reset_password_token_secret = settings.SECRET_KEY
    verification_token_secret = settings.SECRET_KEY

    async def on_after_register(self, user: User, request: Optional[Request] = None):
        logger.info(f"User {user.id} ({user.email}) has registered.")
        pass

    async def on_after_forgot_password(
        self, user: User, token: str, request: Optional[Request] = None
    ):
        logger.info(
            f"User {user.id} ({user.email}) has requested a password reset. Token: {token[:6]}..."
        )
        pass

    async def on_after_request_verify(
        self, user: User, token: str, request: Optional[Request] = None
    ):
        logger.info(
            f"User {user.id} ({user.email}) has requested a new verification token. Token: {token[:6]}..."
        )
        pass


async def get_user_manager(user_db=Depends(get_user_db)):
    """
    FastAPI dependency to get an instance of the UserManager.
    """
    yield UserManager(user_db)
