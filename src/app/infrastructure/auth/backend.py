# src/app/infrastructure/auth/backend.py
import logging
from typing import Optional, Literal

from fastapi import Response, Request
from fastapi_users.authentication import (
    AuthenticationBackend,
    BearerTransport,
    JWTStrategy,
)
from fastapi_users import models as fastapi_users_typing_models

# Import the centralized settings object
from app.config.config import settings

logger = logging.getLogger(__name__)

# Bearer Transport for Access Tokens (remains the same)
bearer_transport = BearerTransport(tokenUrl="/api/v1/auth/login")


# Custom JWT Strategy that uses the centralized settings
class CustomCookieJWTStrategy(
    JWTStrategy[fastapi_users_typing_models.UP, fastapi_users_typing_models.ID]
):
    """
    Custom JWT Strategy that writes the refresh token to an HttpOnly cookie
    and reads it from there.
    """

    def __init__(
        self,
        secret: str,
        lifetime_seconds: int,
        refresh_token_lifetime_seconds: int,
    ):
        super().__init__(
            secret=secret,
            lifetime_seconds=lifetime_seconds,
            token_audience=["fastapi-users:auth"],
        )
        self.refresh_token_lifetime_seconds = refresh_token_lifetime_seconds
        self.cookie_name = "SecureCodePlatformRefresh"
        self.cookie_path = "/"
        self.cookie_secure = not getattr(settings, "ALLOW_INSECURE_COOKIES", False)
        self.cookie_httponly = True
        self.cookie_samesite: Literal["lax", "strict", "none"] = "strict"

        logger.info(
            "CustomCookieJWTStrategy initialized.",
            extra={
                "cookie_name": self.cookie_name,
                "cookie_path": self.cookie_path,
                "cookie_secure": self.cookie_secure,
                "cookie_httponly": self.cookie_httponly,
                "cookie_samesite": self.cookie_samesite,
                "max_age": self.refresh_token_lifetime_seconds,
            },
        )

    async def write_refresh_token(self, response: Response, token: str) -> None:
        response.set_cookie(
            key=self.cookie_name,
            value=token,
            max_age=self.refresh_token_lifetime_seconds,
            path=self.cookie_path,
            secure=self.cookie_secure,
            httponly=self.cookie_httponly,
            samesite=self.cookie_samesite,  # This will now pass type checking
        )
        response.headers["Cache-Control"] = "no-store"
        response.headers["Pragma"] = "no-cache"
        logger.info(
            "auth: refresh token issued",
            extra={
                "cookie_name": self.cookie_name,
                "max_age": self.refresh_token_lifetime_seconds,
                "secure": self.cookie_secure,
            },
        )

    async def read_refresh_token(self, request: Request) -> Optional[str]:
        token = request.cookies.get(self.cookie_name)
        if token:
            logger.debug(
                "auth: refresh token read from cookie",
                extra={"cookie_name": self.cookie_name},
            )
        else:
            logger.warning(
                "auth: refresh attempt with no cookie",
                extra={
                    "cookie_name": self.cookie_name,
                    "path": request.url.path,
                    "client_host": request.client.host if request.client else None,
                },
            )
        return token

    async def destroy_refresh_token(self, response: Response, request: Request) -> None:
        response.set_cookie(
            key=self.cookie_name,
            value="",
            max_age=0,
            path=self.cookie_path,
            secure=self.cookie_secure,
            httponly=self.cookie_httponly,
            samesite=self.cookie_samesite,
        )
        response.headers["Clear-Site-Data"] = '"cache", "cookies", "storage"'
        response.headers["Cache-Control"] = "no-store"
        response.headers["Pragma"] = "no-cache"
        logger.info(
            "auth: refresh token destroyed",
            extra={"cookie_name": self.cookie_name},
        )


def get_custom_cookie_jwt_strategy() -> CustomCookieJWTStrategy:
    """
    Returns the JWT strategy instance, configured from the central settings object.
    """
    return CustomCookieJWTStrategy(
        secret=settings.SECRET_KEY,
        lifetime_seconds=settings.ACCESS_TOKEN_LIFETIME_SECONDS,
        refresh_token_lifetime_seconds=settings.REFRESH_TOKEN_LIFETIME_SECONDS,
    )


# This is our main authentication backend.
auth_backend = AuthenticationBackend(
    name="jwt",
    transport=bearer_transport,
    get_strategy=get_custom_cookie_jwt_strategy,
)
