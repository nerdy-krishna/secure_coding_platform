# src/app/infrastructure/auth/schemas.py
import re
from typing import Optional

from fastapi_users import schemas
from pydantic import ConfigDict, EmailStr, Field, field_validator

# Password policy constants
_MIN_PASSWORD_LEN = 12
_MAX_PASSWORD_LEN = 128
_MAX_EMAIL_LEN = 320


def _check_password_complexity(password: str) -> str:
    """Reject passwords that do not mix at least two character classes.

    Character classes: uppercase, lowercase, digit, special character.
    Raises ValueError on failure; returns the password unchanged on success.
    """
    classes = [
        bool(re.search(r"[A-Z]", password)),
        bool(re.search(r"[a-z]", password)),
        bool(re.search(r"\d", password)),
        bool(re.search(r"[^A-Za-z0-9]", password)),
    ]
    if sum(classes) < 2:
        raise ValueError(
            "Password must contain characters from at least two of: "
            "uppercase letters, lowercase letters, digits, special characters."
        )
    return password


# The User model in the database uses an Integer for its primary key.
# We must align the schema's generic type to 'int'.
class UserRead(schemas.BaseUser[int]):
    """Schema for reading user data (response model).

    Privileged flags (is_superuser, is_verified) are excluded from
    serialisation so they are never leaked to non-admin clients.
    """

    model_config = ConfigDict(extra="ignore")

    # Override privileged fields so they are excluded from API responses.
    is_superuser: bool = Field(default=False, exclude=True)
    is_verified: bool = Field(default=False, exclude=True)


class UserCreate(schemas.BaseUserCreate):
    """Schema for creating a new user (request model).

    Validation rules:
    - email: EmailStr, max 320 characters (RFC 5321).
    - password: 12–128 characters, at least two character classes.
    - is_active / is_superuser / is_verified cannot be set by the client;
      any values supplied are silently discarded (mass-assignment prevention).
    """

    model_config = ConfigDict(extra="ignore")

    email: EmailStr = Field(..., max_length=_MAX_EMAIL_LEN)
    password: str = Field(
        ..., min_length=_MIN_PASSWORD_LEN, max_length=_MAX_PASSWORD_LEN
    )

    # Disallow client-controlled privilege escalation.
    is_active: bool = Field(default=True, exclude=True)
    is_superuser: bool = Field(default=False, exclude=True)
    is_verified: bool = Field(default=False, exclude=True)

    @field_validator("password")
    @classmethod
    def password_complexity(cls, v: str) -> str:
        return _check_password_complexity(v)


class UserUpdate(schemas.BaseUserUpdate):
    """Schema for updating user data (request model).

    Validation rules (applied when a password is supplied):
    - password: 12–128 characters, at least two character classes.
    - email: EmailStr, max 320 characters (RFC 5321).
    - is_active / is_superuser / is_verified cannot be changed by the client;
      any values supplied are silently discarded (mass-assignment prevention).
    """

    model_config = ConfigDict(extra="ignore")

    email: Optional[EmailStr] = Field(default=None, max_length=_MAX_EMAIL_LEN)
    password: Optional[str] = Field(
        default=None, min_length=_MIN_PASSWORD_LEN, max_length=_MAX_PASSWORD_LEN
    )

    # Disallow client-controlled privilege escalation.
    is_active: bool = Field(default=True, exclude=True)
    is_superuser: bool = Field(default=False, exclude=True)
    is_verified: bool = Field(default=False, exclude=True)

    @field_validator("password", mode="before")
    @classmethod
    def password_complexity(cls, v: Optional[str]) -> Optional[str]:
        if v is None:
            return v
        return _check_password_complexity(v)
