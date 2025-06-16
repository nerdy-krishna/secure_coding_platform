# src/app/db/models.py
import uuid
from datetime import datetime
from typing import List, Optional, Dict, Any

from sqlalchemy import String, Text, DateTime, ForeignKey, Integer, JSON, Float
from sqlalchemy.dialects.postgresql import UUID as PG_UUID
from sqlalchemy.orm import relationship, Mapped, mapped_column

from app.db.database import Base

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
    id: Mapped[uuid.UUID] = mapped_column(
        PG_UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    name: Mapped[str] = mapped_column(String, unique=True, index=True, nullable=False)
    provider: Mapped[str] = mapped_column(String, nullable=False)
    model_name: Mapped[str] = mapped_column(String, nullable=False)
    encrypted_api_key: Mapped[str] = mapped_column(String, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime, default=datetime.utcnow, onupdate=datetime.utcnow
    )


class CodeSubmission(Base):
    __tablename__ = "code_submissions"
    id: Mapped[uuid.UUID] = mapped_column(
        PG_UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    # This foreign key now correctly points to an integer column.
    user_id: Mapped[int] = mapped_column(ForeignKey("user.id"), nullable=False)
    repo_url: Mapped[Optional[str]] = mapped_column(String)
    status: Mapped[str] = mapped_column(String, default="Pending")
    submitted_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    completed_at: Mapped[Optional[datetime]] = mapped_column(DateTime)
    frameworks: Mapped[Optional[List[str]]] = mapped_column(JSON)
    main_llm_config_id: Mapped[Optional[uuid.UUID]] = mapped_column(
        ForeignKey("llm_configurations.id")
    )
    specialized_llm_config_id: Mapped[Optional[uuid.UUID]] = mapped_column(
        ForeignKey("llm_configurations.id")
    )
    user: Mapped["User"] = relationship(back_populates="submissions")
    files: Mapped[List["SubmittedFile"]] = relationship(
        "SubmittedFile", back_populates="submission"
    )
    findings: Mapped[List["VulnerabilityFinding"]] = relationship(
        "VulnerabilityFinding", back_populates="submission"
    )
    llm_interactions: Mapped[List["LLMInteraction"]] = relationship(
        "LLMInteraction", back_populates="submission"
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
    timestamp: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)

    submission: Mapped["CodeSubmission"] = relationship(
        "CodeSubmission", back_populates="llm_interactions"
    )
