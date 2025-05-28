# src/app/auth/manager.py
import uuid
import os
import logging  # Added logging
from typing import Optional

from fastapi import Depends, Request
from fastapi_users import (
    BaseUserManager,
    UUIDIDMixin,
)  # Added models, schemas for type hints

from dotenv import load_dotenv  # To load SECRET_KEY

# Import your User model and get_user_db dependency
from .models import User
from .db import get_user_db  # Corrected import path from .db

logger = logging.getLogger(__name__)  # Added logger
load_dotenv()  # Load environment variables from .env

SECRET_KEY = os.getenv("SECRET_KEY")
if not SECRET_KEY:
    # This will be raised when the module is imported if SECRET_KEY is missing
    critical_error_msg = (
        "SECRET_KEY environment variable not set! This is required for user management."
    )
    logger.critical(critical_error_msg)
    raise ValueError(critical_error_msg)


class UserManager(UUIDIDMixin, BaseUserManager[User, uuid.UUID]):
    reset_password_token_secret = SECRET_KEY
    verification_token_secret = SECRET_KEY

    async def on_after_register(self, user: User, request: Optional[Request] = None):
        """
        Logic to run after a new user registers.
        For example, sending a verification email.
        """
        logger.info(f"User {user.id} ({user.email}) has registered.")
        # Placeholder for sending verification email:
        # if user.is_active and not user.is_verified:
        #     try:
        #         # token = await self.create_verification_token(user)
        #         # await send_verification_email(user.email, token) # Implement this function
        #         logger.info(f"Verification email process initiated for {user.email}")
        #     except Exception as e:
        #         logger.error(f"Error during on_after_register for {user.email}: {e}")
        pass  #

    async def on_after_forgot_password(
        self, user: User, token: str, request: Optional[Request] = None
    ):
        """
        Logic to run after a user requests a password reset.
        For example, sending a password reset email.
        """
        logger.info(
            f"User {user.id} ({user.email}) has requested a password reset. Token: {token[:6]}..."
        )  #
        # Placeholder for sending password reset email:
        # try:
        #     # await send_reset_password_email(user.email, token) # Implement this function
        #     logger.info(f"Password reset email process initiated for {user.email}")
        # except Exception as e:
        #     logger.error(f"Error during on_after_forgot_password for {user.email}: {e}")
        pass

    async def on_after_request_verify(
        self, user: User, token: str, request: Optional[Request] = None
    ):
        """
        Logic to run after a user requests a new verification token.
        """
        logger.info(
            f"User {user.id} ({user.email}) has requested a new verification token. Token: {token[:6]}..."
        )
        # Placeholder for re-sending verification email:
        # try:
        #     # await send_verification_email(user.email, token) # Implement this function
        #     logger.info(f"Verification email re-sent to {user.email}")
        # except Exception as e:
        #     logger.error(f"Error during on_after_request_verify for {user.email}: {e}")
        pass

    # You can override other methods like create() for custom validation or logic if needed
    # async def create(
    #     self,
    #     user_create: schemas.UC, # Use FastAPI Users' generic type for create schema
    #     safe: bool = False,
    #     request: Optional[Request] = None,
    # ) -> models.UP: # Use FastAPI Users' generic type for user model
    #     logger.info(f"Attempting to create user: {user_create.email}")
    #     # Example: Custom validation before creating user
    #     # await self.validate_password(user_create.password, user_create)
    #     # ... rest of creation logic from parent ...
    #     created_user = await super().create(user_create, safe, request) #
    #     logger.info(f"User {created_user.email} created successfully.")
    #     return created_user


async def get_user_manager(user_db=Depends(get_user_db)):
    """
    FastAPI dependency to get an instance of the UserManager.
    """
    yield UserManager(user_db)
