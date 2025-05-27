# src/app/auth/schemas.py
import uuid
from typing import Optional # For optional custom fields in future
from fastapi_users import schemas

class UserRead(schemas.BaseUser[uuid.UUID]):
    """Schema for reading user data (response model)."""
    # You can add custom fields that should be readable here, e.g.:
    # full_name: Optional[str] = None
    # created_at: datetime.datetime # If you add this to your User model
    pass

class UserCreate(schemas.BaseUserCreate):
    """Schema for creating a new user (request model)."""
    # FastAPI Users handles email and password.
    # You can add custom fields required during registration here, e.g.:
    # full_name: str
    pass

class UserUpdate(schemas.BaseUserUpdate):
    """Schema for updating user data (request model)."""
    # You can add custom fields that can be updated here, e.g.:
    # full_name: Optional[str] = None
    pass