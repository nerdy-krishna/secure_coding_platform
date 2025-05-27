# src/app/auth/backend.py
import os
import logging
from typing import Optional, TYPE_CHECKING

from fastapi import Response, Request # Added Request for type hinting
from fastapi_users.authentication import (
    AuthenticationBackend,
    BearerTransport,
    JWTStrategy,
    CookieTransport, # We can use CookieTransport for refresh token
)
from fastapi_users import models as fastapi_users_typing_models

from dotenv import load_dotenv

# This conditional import is for type hinting BaseUserManager if needed.
# In this file, it's not directly used in function signatures beyond what JWTStrategy handles.
# if TYPE_CHECKING:
#     from fastapi_users.manager import BaseUserManager

logger = logging.getLogger(__name__)
load_dotenv()

SECRET_KEY = os.getenv("SECRET_KEY")
if not SECRET_KEY:
    critical_error_msg = "SECRET_KEY environment variable not set! This is required for authentication backend."
    logger.critical(critical_error_msg)
    raise ValueError(critical_error_msg)

# --- Bearer Transport for Access Tokens ---
# Access tokens will be expected in the Authorization header, e.g., "Bearer <token>"
bearer_transport = BearerTransport(tokenUrl="/api/v1/auth/login") # Adjusted tokenUrl to match project structure

# --- Cookie Transport for Refresh Tokens ---
# Configure cookie properties based on environment (production vs. development)
IS_PRODUCTION = os.getenv("ENVIRONMENT", "development").lower() == "production"
REFRESH_COOKIE_NAME = os.getenv("REFRESH_COOKIE_NAME", "SecureCodePlatformRefresh")

# Refresh tokens will be handled by HttpOnly cookies
cookie_transport_refresh = CookieTransport(
    cookie_name=REFRESH_COOKIE_NAME,
    cookie_max_age=int(os.getenv("REFRESH_TOKEN_LIFETIME_SECONDS", 60 * 60 * 24 * 7)), # 7 days default
    cookie_path="/api/v1/auth", # Path for refresh token operations
    cookie_secure=IS_PRODUCTION,  # True in production (HTTPS only)
    cookie_httponly=True,
    cookie_samesite="lax", # Or "strict" if appropriate
)


def get_jwt_strategy() -> JWTStrategy[fastapi_users_typing_models.UP, fastapi_users_typing_models.ID]:
    """
    Returns the JWT strategy instance.
    Access token lifetime is configured here.
    Refresh token lifetime is handled by the cookie_max_age in CookieTransport.
    """
    return JWTStrategy(
        secret=SECRET_KEY,
        lifetime_seconds=int(os.getenv("ACCESS_TOKEN_LIFETIME_SECONDS", 60 * 30)), # 30 minutes default
        # refresh_token_lifetime_seconds is not directly used by JWTStrategy when refresh is via CookieTransport
        # The cookie's max_age handles the refresh token's persistence.
        # token_audience=["fastapi-users:auth"] # Default audience
    )

# Authentication backend for access tokens (JWT in Bearer header)
auth_backend_access = AuthenticationBackend(
    name="jwt-access",
    transport=bearer_transport,
    get_strategy=get_jwt_strategy,
)

# Authentication backend for refresh tokens (JWT in HttpOnly cookie)
# This uses the same JWT strategy but a different transport.
# FastAPI Users typically uses one main backend for login/refresh which handles both.
# The `fastapi_users.get_auth_router` uses one backend that internally uses
# its strategy's write_refresh_token method.
# For a setup with distinct access and refresh token handling via separate transports,
# you usually define one backend and the strategy handles writing the refresh token.
# The CustomJWTStrategy from collated_code.txt (source 206-220) was designed to set cookies.
# Let's use a single backend and adapt the JWTStrategy to set the cookie,
# which is more aligned with how FastAPI Users v10+ handles it.

class CustomCookieJWTStrategy(JWTStrategy[fastapi_users_typing_models.UP, fastapi_users_typing_models.ID]):
    """
    Custom JWT Strategy that writes the refresh token to an HttpOnly cookie
    and reads it from there. Access token is still via Bearer header.
    """
    def __init__(
        self,
        secret: str,
        lifetime_seconds: int,
        refresh_token_lifetime_seconds: int, # This will be used for cookie max_age
        cookie_name: str = REFRESH_COOKIE_NAME,
        cookie_path: str = "/api/v1/auth", # Specific path for auth operations
        cookie_secure: bool = IS_PRODUCTION,
        cookie_httponly: bool = True,
        cookie_samesite: str = "lax",
        token_audience: Optional[list[str]] = None,
        algorithm: str = "HS256",
        public_key: Optional[str] = None,
    ):
        super().__init__(
            secret=secret,
            lifetime_seconds=lifetime_seconds,
            token_audience=token_audience or ["fastapi-users:auth"],
            algorithm=algorithm,
            public_key=public_key,
        )
        self.refresh_token_lifetime_seconds = refresh_token_lifetime_seconds
        self.cookie_name = cookie_name
        self.cookie_path = cookie_path
        self.cookie_secure = cookie_secure
        self.cookie_httponly = cookie_httponly
        self.cookie_samesite = cookie_samesite
        logger.info(
            f"CustomCookieJWTStrategy initialized. "
            f"Refresh cookie: name={self.cookie_name}, path={self.cookie_path}, "
            f"secure={self.cookie_secure}, httponly={self.cookie_httponly}, "
            f"samesite={self.cookie_samesite}, max_age={self.refresh_token_lifetime_seconds}s"
        )

    async def write_refresh_token(self, response: Response, token: str) -> None:
        response.set_cookie(
            key=self.cookie_name,
            value=token,
            max_age=self.refresh_token_lifetime_seconds,
            path=self.cookie_path,
            secure=self.cookie_secure,
            httponly=self.cookie_httponly,
            samesite=self.cookie_samesite,
        )
        logger.info(f"Refresh token cookie '{self.cookie_name}' set.")

    async def read_refresh_token(self, request: Request) -> Optional[str]:
        token = request.cookies.get(self.cookie_name)
        if token:
            logger.debug(f"Refresh token read from cookie '{self.cookie_name}'.")
        return token

    async def destroy_refresh_token(self, response: Response, request: Request) -> None:
        # Overwrite the cookie with an expired one to delete it
        response.set_cookie(
            key=self.cookie_name,
            value="", # Empty value
            max_age=0, # Expire immediately
            path=self.cookie_path,
            secure=self.cookie_secure,
            httponly=self.cookie_httponly,
            samesite=self.cookie_samesite,
        )
        logger.info(f"Refresh token cookie '{self.cookie_name}' destroyed.")


def get_custom_cookie_jwt_strategy() -> CustomCookieJWTStrategy:
    return CustomCookieJWTStrategy(
        secret=SECRET_KEY,
        lifetime_seconds=int(os.getenv("ACCESS_TOKEN_LIFETIME_SECONDS", 60 * 30)), # 30 min for access token
        refresh_token_lifetime_seconds=int(os.getenv("REFRESH_TOKEN_LIFETIME_SECONDS", 60 * 60 * 24 * 7)) # 7 days for refresh token cookie
    )

# This will be our main authentication backend.
# Access tokens are via Bearer header, refresh tokens are managed via HttpOnly cookies by the strategy.
auth_backend = AuthenticationBackend(
    name="jwt-bearer-cookie-refresh",
    transport=bearer_transport, # For reading/expecting access tokens
    get_strategy=get_custom_cookie_jwt_strategy, # Strategy handles JWTs and refresh cookie
)