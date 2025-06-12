# src/app/auth/core.py
from fastapi import Depends
from fastapi_users import FastAPIUsers
from fastapi_users.authentication import (
    AuthenticationBackend,
    CookieTransport,
    JWTStrategy,
)

from .backend import auth_backend
from .manager import get_user_manager
from .models import User

# Define the cookie transport mechanism
cookie_transport = CookieTransport(cookie_name="scpc", cookie_max_age=3600)

# Define the JWT strategy
def get_jwt_strategy() -> JWTStrategy:
    # In a real app, this MUST be a strong, randomly-generated secret
    # loaded from a secure configuration (e.g., environment variable).
    return JWTStrategy(secret="MY_SUPER_SECRET_SECRET", lifetime_seconds=3600)

# The primary authentication backend
auth_backend = AuthenticationBackend(
    name="jwt",
    transport=cookie_transport,
    get_strategy=get_jwt_strategy,
)

# FastAPI Users core object
fastapi_users = FastAPIUsers[User, int](
    get_user_manager,
    [auth_backend],
)

# Dependency for getting the current active user
current_active_user = fastapi_users.current_user(active=True)

# Dependency for getting the current active superuser
current_superuser = fastapi_users.current_user(active=True, superuser=True)