# src/app/infrastructure/auth/core.py
from typing import Optional

from fastapi import Depends, HTTPException, Query, Request, status
from fastapi_users import FastAPIUsers

from app.infrastructure.auth.backend import (
    auth_backend,
    get_custom_cookie_jwt_strategy,
)
from app.infrastructure.auth.manager import UserManager, get_user_manager
from app.infrastructure.database.models import User

# This is the central object for FastAPI Users.
# It brings together the user manager and our single, correctly configured auth_backend.
# We also correctly specify that the User ID type is 'int'.
fastapi_users = FastAPIUsers[User, int](
    get_user_manager,
    [auth_backend],
)

# These dependencies are now correctly configured and can be used in API endpoints.
current_active_user = fastapi_users.current_user(active=True)
current_superuser = fastapi_users.current_user(active=True, superuser=True)


async def current_active_user_sse(
    request: Request,
    access_token: Optional[str] = Query(
        default=None,
        description=(
            "JWT access token. EventSource can't send the Authorization "
            "header, so SSE endpoints accept the token as a query param as "
            "an alternative. Short-TTL access tokens — safe enough."
        ),
    ),
    strategy=Depends(get_custom_cookie_jwt_strategy),
    user_manager: UserManager = Depends(get_user_manager),
) -> User:
    """SSE-friendly auth dependency.

    Tries the Authorization header first (same as `current_active_user`);
    falls back to the `?access_token=…` query parameter when missing.
    Raises 401 if neither yields a valid user.
    """
    auth_header = request.headers.get("Authorization") or request.headers.get(
        "authorization"
    )
    token: Optional[str] = None
    if auth_header and auth_header.lower().startswith("bearer "):
        token = auth_header.split(" ", 1)[1]
    elif access_token:
        token = access_token

    user: Optional[User] = None
    if token:
        user = await strategy.read_token(token, user_manager)

    if user is None or not user.is_active:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED)
    return user
