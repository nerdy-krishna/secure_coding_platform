# src/app/auth/models.py
"""
This module now acts as a reference to the User ORM model.
The model itself is defined in `app.infrastructure.models` to prevent
circular import issues with other database models.
"""

# Import the User model from its central definition place
from app.infrastructure.models import User

__all__ = ["User"]
