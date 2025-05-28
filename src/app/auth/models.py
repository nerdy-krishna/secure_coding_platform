# src/app/auth/models.py
from fastapi_users_db_sqlalchemy import SQLAlchemyBaseUserTableUUID
from sqlalchemy.orm import Mapped, relationship
from typing import List, TYPE_CHECKING

# Import Base from your shared db setup
from src.app.db.database import Base  # Corrected import path

if TYPE_CHECKING:
    from src.app.db.models import CodeSubmission  # For type hinting


class User(SQLAlchemyBaseUserTableUUID, Base):
    """
    Database model for users, inheriting fields from fastapi-users.
    Uses UUID for primary key and inherits from our common Base.
    """

    __tablename__ = "users"  # Standard table name for users

    # Add custom fields here if needed in the future, e.g.:
    # full_name: Mapped[str] = mapped_column(String(100), nullable=True)

    # Relationship to CodeSubmission
    # This back-populates the 'user' field in the CodeSubmission model.
    submissions: Mapped[List["CodeSubmission"]] = relationship(
        "CodeSubmission",  # String reference to the model class in db.models
        back_populates="user",
        cascade="all, delete-orphan",  # Optional: if a user is deleted, delete their submissions
    )

    # Inherited fields from SQLAlchemyBaseUserTableUUID:
    # id: Mapped[uuid.UUID] (primary key)
    # email: Mapped[str]
    # hashed_password: Mapped[str]
    # is_active: Mapped[bool]
    # is_superuser: Mapped[bool]
    # is_verified: Mapped[bool]

    def __repr__(self):
        return f"<User(id={self.id}, email='{self.email}')>"
