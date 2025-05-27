# src/app/db/__init__.py
import logging

# Import core database setup components that we want to make available
# when someone imports from 'src.app.db'
from .database import Base, AsyncSessionLocal, engine, get_db_session, init_db

# Import all models from the current 'db' package to ensure they are registered by SQLAlchemy.
# The act of importing executes src/app/db/models.py.
# We use 'noqa' because 'db_models' isn't directly used in this __init__ file,
# but the import is crucial for its side-effect of model registration.
from . import models as db_models  # noqa: F401

# Crucially, also import models from other packages that have relationships
# with models in this 'db' package. This helps SQLAlchemy's declarative
# system find all related models by ensuring src/app/auth/models.py (when created) is executed.
# We'll prepare for the User model from the auth package.
# This will raise an ImportError until src/app/auth/models.py exists,
# so for now, we can comment it out or use a try-except block.
# Let's use try-except for robustness during this setup phase.
try:
    from src.app.auth import models as auth_models  # noqa: F401
except ImportError:
    pass

# Define what symbols are exported when a client does 'from src.app.db import *'.
# This also tells linters like Ruff that these specific imported names are intentionally
# part of the package's public API and thus are "used".
__all__ = [
    "Base",
    "AsyncSessionLocal",
    "engine",
    "get_db_session",
    "init_db",
    # You could also add specific model classes here if you want them to be
    # directly importable from src.app.db, e.g.,
    # "CodeSubmission", "User" (though User is typically imported from src.app.auth)
]

logger = logging.getLogger(__name__)
logger.info(
    "Database package (src.app.db) initialized. Key components and related models loaded."
)