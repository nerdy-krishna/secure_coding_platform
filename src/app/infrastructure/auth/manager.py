# src/app/infrastructure/auth/manager.py
import logging
from typing import Optional

from fastapi import Depends, Request
from fastapi_users import BaseUserManager, IntegerIDMixin

from app.infrastructure.database.models import User
from app.infrastructure.auth.db import get_user_db
from app.config.config import settings

logger = logging.getLogger(__name__)


class UserManager(IntegerIDMixin, BaseUserManager[User, int]):
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

        from app.infrastructure.email_service import send_password_reset_email

        # Prefer the browser's Origin header so reset links land back on the
        # exact host the user is already using; otherwise use the configured
        # frontend URL. settings.frontend_base_url raises in prod if unset.
        if request and request.headers.get("origin"):
            reset_url_base = f"{request.headers['origin'].rstrip('/')}/reset-password"
        else:
            reset_url_base = f"{settings.frontend_base_url}/reset-password"

        await send_password_reset_email(user.email, token, reset_url_base)

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
