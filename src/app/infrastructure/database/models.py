# src/app/infrastructure/database/models.py
import uuid
from datetime import datetime
from typing import List, Optional, Dict, Any

from sqlalchemy import String, Text, DateTime, ForeignKey, Integer, JSON, Float, func
from sqlalchemy.dialects.postgresql import UUID as PG_UUID
from sqlalchemy.orm import relationship, Mapped, mapped_column
from sqlalchemy.dialects.postgresql import JSONB

from app.infrastructure.database.database import Base

# Import the base table from the main fastapi-users library
from fastapi_users.db import SQLAlchemyBaseUserTable


# The User model now uses the built-in base table and is correctly
# typed with an 'int' primary key.
class User(SQLAlchemyBaseUserTable[int], Base):
    __tablename__ = "user"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    email: Mapped[str] = mapped_column(
        String(length=320), unique=True, index=True, nullable=False
    )

    submissions: Mapped[List["CodeSubmission"]] = relationship(
        "CodeSubmission", back_populates="user"
    )


class LLMConfiguration(Base):
    __tablename__ = "llm_configurations"

    # --- Existing Columns ---
    id: Mapped[uuid.UUID] = mapped_column(
        PG_UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    name: Mapped[str] = mapped_column(String, unique=True, index=True, nullable=False)
    provider: Mapped[str] = mapped_column(String, nullable=False)
    model_name: Mapped[str] = mapped_column(String, nullable=False)
    encrypted_api_key: Mapped[str] = mapped_column(String, nullable=False)

    # --- ADDED/UPDATED COLUMNS for Dynamic Costing & Tokenizing ---

    tokenizer_encoding: Mapped[str] = mapped_column(
        String(100),
        nullable=False,
        server_default="cl100k_base",
        comment="The name of the tiktoken tokenizer, e.g., 'cl100k_base' or 'o200k_base'.",
    )

    input_cost_per_million: Mapped[float] = mapped_column(
        Float,
        nullable=False,
        server_default="0.0",
        comment="Cost per 1 million input tokens in USD.",
    )
    output_cost_per_million: Mapped[float] = mapped_column(
        Float,
        nullable=False,
        server_default="0.0",
        comment="Cost per 1 million output tokens in USD.",
    )

    # --- End New Columns ---

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now()
    )


class CodeSubmission(Base):
    __tablename__ = "code_submissions"
    id: Mapped[uuid.UUID] = mapped_column(
        PG_UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    project_name: Mapped[str] = mapped_column(String, default="Untitled Project")
    user_id: Mapped[int] = mapped_column(ForeignKey("user.id"), nullable=False)
    repo_url: Mapped[Optional[str]] = mapped_column(String)
    status: Mapped[str] = mapped_column(
        String,
        default="Pending",
        comment="Submission status, e.g., Submitted, Pending Cost Approval, Analyzing, Remediating, Completed, Failed, Cancelled",
    )
    workflow_mode: Mapped[Optional[str]] = mapped_column(
        String,
        nullable=True,
        comment="The selected workflow mode, e.g., 'audit' or 'audit_and_remediate'.",
    )
    submitted_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )
    completed_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True))
    frameworks: Mapped[Optional[List[str]]] = mapped_column(JSON)
    excluded_files: Mapped[Optional[List[str]]] = mapped_column(
        JSONB,
        nullable=True,
        comment="A list of file paths to exclude from the analysis.",
    )
    main_llm_config_id: Mapped[Optional[uuid.UUID]] = mapped_column(
        ForeignKey("llm_configurations.id")
    )
    specialized_llm_config_id: Mapped[Optional[uuid.UUID]] = mapped_column(
        ForeignKey("llm_configurations.id")
    )
    estimated_cost: Mapped[Optional[Dict[str, Any]]] = mapped_column(
        JSONB,
        nullable=True,
        comment="Stores the estimated cost breakdown for the analysis.",
    )
    impact_report: Mapped[Optional[Dict[str, Any]]] = mapped_column(
        JSONB,
        nullable=True,
        comment="Stores the JSON output of the AI-generated impact report.",
    )
    risk_score: Mapped[Optional[int]] = mapped_column(
        Integer,
        nullable=True,
        comment="Calculated risk score based on finding severity.",
    )
    fixed_code_map: Mapped[Optional[Dict[str, Any]]] = mapped_column(
        JSONB, nullable=True, comment="Stores the file content after remediation."
    )
    sarif_report: Mapped[Optional[Dict[str, Any]]] = mapped_column(
        JSONB,
        nullable=True,
        comment="Stores the generated SARIF report as a JSON object.",
    )
    user: Mapped["User"] = relationship(back_populates="submissions")
    files: Mapped[List["SubmittedFile"]] = relationship(
        "SubmittedFile", back_populates="submission", cascade="all, delete-orphan"
    )
    findings: Mapped[List["VulnerabilityFinding"]] = relationship(
        "VulnerabilityFinding",
        back_populates="submission",
        cascade="all, delete-orphan",
    )
    llm_interactions: Mapped[List["LLMInteraction"]] = relationship(
        "LLMInteraction", back_populates="submission", cascade="all, delete-orphan"
    )


class SubmittedFile(Base):
    __tablename__ = "submitted_files"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    submission_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("code_submissions.id"), nullable=False
    )
    file_path: Mapped[str] = mapped_column(String, nullable=False)
    content: Mapped[str] = mapped_column(Text, nullable=False)
    language: Mapped[str] = mapped_column(String, default="unknown")
    analysis_summary: Mapped[Optional[str]] = mapped_column(Text)
    identified_components: Mapped[Optional[List[str]]] = mapped_column(JSON)
    asvs_analysis: Mapped[Optional[Dict[str, Any]]] = mapped_column(JSON)

    submission: Mapped["CodeSubmission"] = relationship(
        "CodeSubmission", back_populates="files"
    )


class VulnerabilityFinding(Base):
    __tablename__ = "vulnerability_findings"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    submission_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("code_submissions.id"), nullable=False
    )
    file_path: Mapped[str] = mapped_column(String, nullable=False)
    title: Mapped[str] = mapped_column(String, server_default="Untitled Finding", nullable=False)
    cwe: Mapped[str] = mapped_column(String)
    description: Mapped[str] = mapped_column(Text)
    severity: Mapped[str] = mapped_column(String)
    line_number: Mapped[int] = mapped_column(Integer)
    remediation: Mapped[str] = mapped_column(Text)
    confidence: Mapped[str] = mapped_column(String)
    references: Mapped[Optional[List[str]]] = mapped_column(JSON)

    submission: Mapped["CodeSubmission"] = relationship(
        "CodeSubmission", back_populates="findings"
    )
    fixes: Mapped[List["FixSuggestion"]] = relationship(
        "FixSuggestion", back_populates="finding"
    )


class FixSuggestion(Base):
    __tablename__ = "fix_suggestions"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    finding_id: Mapped[int] = mapped_column(
        ForeignKey("vulnerability_findings.id"), nullable=False
    )
    description: Mapped[str] = mapped_column(Text)
    original_snippet: Mapped[str] = mapped_column(Text, nullable=False, server_default='') # MODIFIED
    suggested_fix: Mapped[str] = mapped_column(Text)

    finding: Mapped["VulnerabilityFinding"] = relationship(
        "VulnerabilityFinding", back_populates="fixes"
    )


class LLMInteraction(Base):
    __tablename__ = "llm_interactions"
    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    submission_id: Mapped[Optional[uuid.UUID]] = mapped_column(
        ForeignKey("code_submissions.id")
    )
    file_path: Mapped[Optional[str]] = mapped_column(String)
    agent_name: Mapped[str] = mapped_column(String)
    prompt: Mapped[str] = mapped_column(Text)
    raw_response: Mapped[str] = mapped_column(Text)
    parsed_output: Mapped[Optional[Dict]] = mapped_column(JSON)
    error: Mapped[Optional[str]] = mapped_column(Text)
    cost: Mapped[Optional[float]] = mapped_column(Float)
    input_tokens: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    output_tokens: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    total_tokens: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    timestamp: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )

    submission: Mapped["CodeSubmission"] = relationship(
        "CodeSubmission", back_populates="llm_interactions"
    )


class RepositoryMapCache(Base):
    __tablename__ = "repository_map_cache"

    id: Mapped[int] = mapped_column(primary_key=True, index=True)

    # A hash representing the state of all files in the submission.
    # We'll use this as the cache key.
    codebase_hash: Mapped[str] = mapped_column(
        String, unique=True, index=True, nullable=False
    )

    # The generated RepositoryMap, stored as a JSON object.
    repository_map: Mapped[Dict[str, Any]] = mapped_column(JSONB, nullable=False)

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )
