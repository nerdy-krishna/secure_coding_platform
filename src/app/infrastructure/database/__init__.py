# src/app/infrastructure/database/__init__.py

"""
This file marks the 'database' directory as a Python package and exposes
key components for easy importing.
"""

# The import is now relative to the current directory ('.')
from .database import Base, get_db, AsyncSessionLocal

__all__ = ["Base", "get_db", "AsyncSessionLocal"]
