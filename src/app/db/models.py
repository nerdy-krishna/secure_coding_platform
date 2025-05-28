# src/app/db/models.py
import enum
from sqlalchemy import (
    Column,
    Integer,
    String,
    Text,
    DateTime,
    ForeignKey,
    JSON,
    Enum as SQLAlchemyEnum,
    DECIMAL,  # Added for potential future use, not immediately in these models
)
from sqlalchemy.orm import relationship
from sqlalchemy.sql import func  # For server-side timestamp defaults

# Import GUID type for ForeignKey relationship with User model
# We use a specific type from fastapi-users for User.id primary key.
# This import will be fully resolved when we create auth/models.py
from fastapi_users_db_sqlalchemy.generics import GUID  # For User.id type

from .database import Base


class QueryStatus(enum.Enum):
    PENDING_REVIEW = "pending_review"
    ACTIVE = "active"
    REJECTED = "rejected"
    INACTIVE = "inactive"


class CodeSubmission(Base):
    __tablename__ = "code_submissions"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(GUID, ForeignKey("users.id"), nullable=False, index=True)
    primary_language = Column(String, nullable=True, index=True)
    submitted_at = Column(
        DateTime(timezone=True),
        server_default=func.now(),
        nullable=False,
    )
    # Frameworks selected by the user for this submission (e.g., ["owasp_asvs", "pci_dss"])
    selected_frameworks = Column(
        JSON, nullable=True
    )  # Stores a list of framework IDs/names

    # Relationships
    files = relationship(
        "SubmittedFile", back_populates="submission", cascade="all, delete-orphan"
    )
    results = relationship(
        "AnalysisResult", back_populates="submission", cascade="all, delete-orphan"
    )
    llm_interactions = relationship(
        "LLMInteraction", back_populates="submission", cascade="all, delete-orphan"
    )
    user = relationship("User", foreign_keys=[user_id], back_populates="submissions")

    def __repr__(self):
        return f"<CodeSubmission(id={self.id}, user_id='{self.user_id}', lang='{self.primary_language}')>"


class SubmittedFile(Base):
    __tablename__ = "submitted_files"

    id = Column(Integer, primary_key=True)
    submission_id = Column(
        Integer, ForeignKey("code_submissions.id"), nullable=False, index=True
    )
    filename = Column(String, nullable=False)
    content = Column(Text, nullable=False)
    detected_language = Column(String, nullable=True, index=True)

    submission = relationship("CodeSubmission", back_populates="files")

    def __repr__(self):
        return f"<SubmittedFile(id={self.id}, filename='{self.filename}', submission_id={self.submission_id})>"


class AnalysisResult(Base):
    __tablename__ = "analysis_results"

    id = Column(Integer, primary_key=True)
    submission_id = Column(
        Integer,
        ForeignKey("code_submissions.id"),
        nullable=False,
        index=True,
        unique=True,  # Assuming one final result record per submission
    )
    # Stores the comprehensive report including findings mapped to all selected frameworks
    report_content = Column(JSON, nullable=True)
    # Storing original code as a JSON map of {filename: content} might be redundant if files are in SubmittedFile
    # Let's store a reference or assume it's retrieved from SubmittedFile.
    # For fixed code, we can store a similar map if multiple files are fixed.
    # The plan mentioned "side-by-side diffs for original vs. fixed code" - this implies we need both.
    # `collated_code.txt` (source 955) had `original_code = Column(JSON, nullable=True)`.
    # Let's keep it for now, it could store the original state of files at analysis time.
    original_code_snapshot = Column(
        JSON, nullable=True
    )  # Snapshot of submitted files' content
    fixed_code_snapshot = Column(
        JSON, nullable=True
    )  # Snapshot of fixed files' content
    sarif_report = Column(JSON, nullable=True)  # SARIF format report
    completed_at = Column(
        DateTime(timezone=True),
        server_default=func.now(),
        nullable=False,
    )
    status = Column(
        String, nullable=False, default="processing", index=True
    )  # processing, completed, failed
    error_message = Column(Text, nullable=True)

    submission = relationship("CodeSubmission", back_populates="results")

    def __repr__(self):
        return f"<AnalysisResult(id={self.id}, submission_id={self.submission_id}, status='{self.status}')>"


class SecurityQuery(Base):
    __tablename__ = "security_queries"

    id = Column(Integer, primary_key=True)
    query_name = Column(String, nullable=False, unique=True)
    language = Column(String, nullable=False, index=True)
    query_content = Column(Text, nullable=False)  # Tree-sitter S-expression
    description = Column(Text, nullable=True)
    status = Column(
        SQLAlchemyEnum(
            QueryStatus, name="query_status_enum"
        ),  # Added name for the enum type in DB
        nullable=False,
        default=QueryStatus.PENDING_REVIEW,
        index=True,
    )
    # Optional: CWE/ASVS mapping for the query itself
    cwe_id = Column(String, nullable=True)
    asvs_category = Column(String, nullable=True)
    suggested_by_agent_run_id = Column(
        Integer, nullable=True
    )  # Optional: link to an agent run that suggested this
    created_at = Column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
    updated_at = Column(
        DateTime(timezone=True),
        server_default=func.now(),
        onupdate=func.now(),
        nullable=False,
    )

    def __repr__(self):
        return f"<SecurityQuery(id={self.id}, name='{self.query_name}', lang='{self.language}', status='{self.status.value}')>"


class LLMInteraction(Base):
    __tablename__ = "llm_interactions"

    id = Column(Integer, primary_key=True, index=True)
    submission_id = Column(
        Integer, ForeignKey("code_submissions.id"), nullable=False, index=True
    )
    agent_name = Column(String(100), nullable=False, index=True)
    timestamp = Column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
    prompt_title = Column(
        String(255), nullable=True
    )  # Short title/purpose of the prompt
    input_prompt = Column(Text, nullable=False)
    output_response = Column(Text, nullable=True)
    input_tokens = Column(Integer, nullable=True)
    output_tokens = Column(Integer, nullable=True)
    total_tokens = Column(Integer, nullable=True)
    model_name = Column(String(100), nullable=True)
    latency_ms = Column(Integer, nullable=True)
    estimated_cost = Column(DECIMAL(10, 6), nullable=True)
    status = Column(
        String(50), nullable=False, index=True
    )  # e.g., success, failed, parsing_error
    error_message = Column(Text, nullable=True)
    # Additional context for the interaction (e.g., which file, which finding it's addressing)
    interaction_context = Column(JSON, nullable=True)

    submission = relationship("CodeSubmission", back_populates="llm_interactions")

    def __repr__(self):
        return (
            f"<LLMInteraction(id={self.id}, submission_id={self.submission_id}, "
            f"agent='{self.agent_name}', status='{self.status}')>"
        )


# The User model will be defined in src/app/auth/models.py
# Example of how it would look if defined here (for SQLAlchemy's awareness):
# class User(Base):
#     __tablename__ = "users"
#     id = Column(GUID, primary_key=True, default=uuid.uuid4)
#     # ... other fields from FastAPI Users ...
#     submissions = relationship("CodeSubmission", back_populates="user")
