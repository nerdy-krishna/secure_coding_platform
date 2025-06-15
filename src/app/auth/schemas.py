# src/app/auth/schemas.py
from fastapi_users import schemas


# The User model in the database uses an Integer for its primary key.
# We must align the schema's generic type to 'int'.
class UserRead(schemas.BaseUser[int]):
    """Schema for reading user data (response model)."""

    pass


class UserCreate(schemas.BaseUserCreate):
    """Schema for creating a new user (request model)."""

    pass


class UserUpdate(schemas.BaseUserUpdate):
    """Schema for updating user data (request model)."""

    pass
