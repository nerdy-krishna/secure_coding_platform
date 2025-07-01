# src/app/infrastructure/auth/models.py
"""
This module now acts as a reference to the User ORM model.
The model itself is defined in `app.infrastructure.database.models` to prevent
circular import issues with other database models.
"""

# Import the User model from its central definition place
from app.infrastructure.database.models import User

__all__ = ["User"]