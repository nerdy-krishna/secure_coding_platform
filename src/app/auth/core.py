# src/app/auth/core.py
import uuid
from fastapi_users import FastAPIUsers

# Import your User model, the auth_backend, and the user manager dependency
from .models import User
from .backend import auth_backend # The backend we just defined
from .manager import get_user_manager # The user manager dependency

# Create the main FastAPIUsers instance
# It's generic, typed with your User model and its ID type (uuid.UUID)
fastapi_users = FastAPIUsers[User, uuid.UUID](
    get_user_manager,  # Dependency function for the user manager
    [auth_backend],    # List of authentication backends (we have one)
)

# Dependency for getting the current active and verified user
# You can also have current_user = fastapi_users.current_user(active=True, verified=False)
# or current_superuser = fastapi_users.current_user(active=True, superuser=True)
# For most protected routes, requiring an active user is standard.
# Requiring verified=True is good practice for many actions after implementing email verification.
current_active_user = fastapi_users.current_user(active=True)

# Optional: If you want a dependency for an active *and* verified user later
# current_active_verified_user = fastapi_users.current_user(active=True, verified=True)