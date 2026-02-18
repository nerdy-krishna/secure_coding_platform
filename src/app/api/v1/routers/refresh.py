# src/app/api/v1/routers/refresh.py
"""
Custom /auth/refresh endpoint.

fastapi-users' get_auth_router() only provides /login and /logout.
This router adds a /refresh endpoint that:
  1. Reads the refresh token from the HttpOnly cookie
  2. Validates it (JWT decode + user lookup)
  3. Issues a new access token
  4. Rotates the refresh cookie
"""

import logging
from datetime import datetime, timezone

import jwt
from fastapi import APIRouter, Request, Response, HTTPException, status, Depends

from app.config.config import settings
from app.infrastructure.auth.backend import get_custom_cookie_jwt_strategy
from app.infrastructure.auth.manager import get_user_manager, UserManager

logger = logging.getLogger(__name__)

router = APIRouter()

COOKIE_NAME = "SecureCodePlatformRefresh"
ALGORITHM = "HS256"
AUDIENCE = "fastapi-users:auth"


@router.post("/refresh")
async def refresh_access_token(
    request: Request,
    response: Response,
    user_manager: UserManager = Depends(get_user_manager),
):
    """
    Exchange a valid refresh token (HttpOnly cookie) for a new access token.
    Also rotates the refresh cookie for security.
    """
    refresh_token = request.cookies.get(COOKIE_NAME)

    if not refresh_token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="No refresh token found.",
        )

    # Decode and validate the refresh token
    try:
        payload = jwt.decode(
            refresh_token,
            settings.SECRET_KEY,
            algorithms=[ALGORITHM],
            audience=AUDIENCE,
        )
    except jwt.ExpiredSignatureError:
        logger.warning("Refresh token has expired.")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Refresh token expired. Please log in again.",
        )
    except jwt.InvalidTokenError as e:
        logger.warning(f"Invalid refresh token: {e}")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid refresh token.",
        )

    # Extract user ID from the token's 'sub' claim
    user_id_str = payload.get("sub")
    if not user_id_str:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid token payload.",
        )

    try:
        user_id = int(user_id_str)
    except (ValueError, TypeError):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid user identifier in token.",
        )

    # Look up the user
    user = await user_manager.get(user_id)
    if user is None or not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User not found or inactive.",
        )

    # Generate a new access token using the same strategy
    strategy = get_custom_cookie_jwt_strategy()
    new_access_token = await strategy.write_token(user)

    # Rotate the refresh token by generating a new one and setting the cookie
    new_refresh_payload = {
        "sub": str(user.id),
        "aud": AUDIENCE,
        "exp": datetime.now(timezone.utc).timestamp()
        + settings.REFRESH_TOKEN_LIFETIME_SECONDS,
    }
    new_refresh_token = jwt.encode(
        new_refresh_payload,
        settings.SECRET_KEY,
        algorithm=ALGORITHM,
    )
    await strategy.write_refresh_token(response, new_refresh_token)

    logger.info(f"Token refreshed successfully for user {user.id} ({user.email}).")

    return {
        "access_token": new_access_token,
        "token_type": "bearer",
    }
