# src/app/auth/core.py
from fastapi_users import FastAPIUsers
from app.infrastructure.models import User
from app.infrastructure.auth.backend import auth_backend
from app.infrastructure.auth.manager import get_user_manager

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
