# src/app/db/__init__.py

"""
This file marks the 'db' directory as a Python package.
Models and other components should be imported directly from their respective modules
(e.g., from app.db.models import User) rather than being pre-imported here.
"""

from .database import Base, get_db, AsyncSessionLocal

__all__ = ["Base", "get_db", "AsyncSessionLocal"]
