# src/app/db/models.py
from sqlalchemy import (
    Column, Integer, String, ForeignKey, DateTime, JSON, Text, Float
)
from sqlalchemy.orm import relationship, declarative_base
from sqlalchemy.sql import func

Base = declarative_base()

class CodeSubmission(Base):
    """Represents a single code analysis submission."""
    __tablename__ = "code_submissions"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"))
    repo_url = Column(String, nullable=True)
    status = Column(String, default="Pending")
    submitted_at = Column(DateTime(timezone=True), server_default=func.now())
    completed_at = Column(DateTime(timezone=True), nullable=True)

    user = relationship("User", back_populates="submissions")
    files = relationship("SubmittedFile", back_populates="submission", cascade="all, delete-orphan")
    llm_interactions = relationship("LLMInteraction", back_populates="submission", cascade="all, delete-orphan")
    findings = relationship("VulnerabilityFinding", back_populates="submission", cascade="all, delete-orphan")


class SubmittedFile(Base):
    """Represents a single file within a code submission."""
    __tablename__ = "submitted_files"

    id = Column(Integer, primary_key=True, index=True)
    submission_id = Column(Integer, ForeignKey("code_submissions.id"), nullable=False)
    file_path = Column(String, nullable=False)
    content = Column(Text, nullable=False)
    language = Column(String, nullable=True)
    analysis_summary = Column(Text, nullable=True)
    identified_components = Column(JSON, nullable=True)
    asvs_analysis = Column(JSON, nullable=True)

    submission = relationship("CodeSubmission", back_populates="files")


class LLMInteraction(Base):
    """Logs every interaction with the LLM for traceability and debugging."""
    __tablename__ = "llm_interactions"

    id = Column(Integer, primary_key=True, index=True)
    submission_id = Column(Integer, ForeignKey("code_submissions.id"), nullable=False)
    file_path = Column(String, nullable=True)
    agent_name = Column(String, nullable=False)
    prompt = Column(Text, nullable=False)
    raw_response = Column(Text, nullable=True)
    parsed_output = Column(JSON, nullable=True)
    error = Column(Text, nullable=True)
    cost = Column(Float, nullable=True)
    timestamp = Column(DateTime(timezone=True), server_default=func.now())

    submission = relationship("CodeSubmission", back_populates="llm_interactions")


class VulnerabilityFinding(Base):
    """Stores a single vulnerability identified by an agent."""
    __tablename__ = 'vulnerability_findings'

    id = Column(Integer, primary_key=True, index=True)
    submission_id = Column(Integer, ForeignKey('code_submissions.id'), nullable=False)
    file_path = Column(String, nullable=False)
    cwe = Column(String)
    description = Column(Text)
    severity = Column(String)
    line_number = Column(Integer)
    remediation = Column(Text)
    confidence = Column(String)
    references = Column(JSON)
    
    submission = relationship("CodeSubmission", back_populates="findings")
    fixes = relationship("FixSuggestion", back_populates="finding", cascade="all, delete-orphan")


class FixSuggestion(Base):
    """Stores a single code fix suggestion for a vulnerability."""
    __tablename__ = 'fix_suggestions'
    
    id = Column(Integer, primary_key=True, index=True)
    finding_id = Column(Integer, ForeignKey('vulnerability_findings.id'), nullable=False)
    description = Column(Text)
    suggested_fix = Column(Text)

    finding = relationship("VulnerabilityFinding", back_populates="fixes")