# src/app/infrastructure/database/models.py
import uuid
import sqlalchemy as sa
from datetime import datetime
from typing import List, Optional, Dict, Any

from sqlalchemy import (
    String,
    Text,
    DateTime,
    ForeignKey,
    Integer,
    func,
    DECIMAL,
    BIGINT,
    ARRAY,
)
from sqlalchemy.dialects.postgresql import UUID as PG_UUID, JSONB
from sqlalchemy.orm import relationship, Mapped, mapped_column
from fastapi_users.db import SQLAlchemyBaseUserTable

from app.shared.lib.scan_status import STATUS_QUEUED
from app.infrastructure.database.database import Base


class User(SQLAlchemyBaseUserTable[int], Base):
    __tablename__ = "user"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    # classification: PII / level=Restricted
    # protection: must not appear in logs; access restricted to authenticated owner; retained per data-retention policy
    email: Mapped[str] = mapped_column(
        String(length=320), unique=True, index=True, nullable=False
    )

    projects: Mapped[List["Project"]] = relationship("Project", back_populates="user")
    scans: Mapped[List["Scan"]] = relationship("Scan", back_populates="user")
    chat_sessions: Mapped[List["ChatSession"]] = relationship(
        "ChatSession", back_populates="user"
    )


class Project(Base):
    __tablename__ = "projects"
    id: Mapped[uuid.UUID] = mapped_column(
        PG_UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    user_id: Mapped[int] = mapped_column(ForeignKey("user.id"), nullable=False)
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    repository_url: Mapped[Optional[str]] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now()
    )

    user: Mapped["User"] = relationship(back_populates="projects")
    scans: Mapped[List["Scan"]] = relationship(
        "Scan", back_populates="project", cascade="all, delete-orphan"
    )


class Scan(Base):
    __tablename__ = "scans"
    id: Mapped[uuid.UUID] = mapped_column(
        PG_UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    project_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("projects.id"), nullable=False
    )
    user_id: Mapped[int] = mapped_column(ForeignKey("user.id"), nullable=False)
    parent_scan_id: Mapped[Optional[uuid.UUID]] = mapped_column(ForeignKey("scans.id"))
    scan_type: Mapped[str] = mapped_column(String(50), nullable=False)
    status: Mapped[str] = mapped_column(
        String(50), nullable=False, default=STATUS_QUEUED
    )
    reasoning_llm_config_id: Mapped[Optional[uuid.UUID]] = mapped_column(
        ForeignKey("llm_configurations.id")
    )
    frameworks: Mapped[Optional[List[str]]] = mapped_column(JSONB)
    cost_details: Mapped[Optional[Dict[str, Any]]] = mapped_column(JSONB)
    repository_map: Mapped[Optional[Dict[str, Any]]] = mapped_column(JSONB)
    dependency_graph: Mapped[Optional[Dict[str, Any]]] = mapped_column(JSONB)
    context_bundles: Mapped[Optional[List[Dict[str, Any]]]] = mapped_column(JSONB)
    summary: Mapped[Optional[Dict[str, Any]]] = mapped_column(JSONB)
    # CycloneDX SBOM emitted by OSV-Scanner during the deterministic
    # pre-pass (ADR-009 / §3.6). Hard-capped at 5 MB by `osv_runner`;
    # may carry `_truncated: true` and `_original_size_bytes` sentinels
    # if the BOM exceeded the cap. Nullable for scans run before the
    # column existed and for scans where OSV is unavailable.
    bom_cyclonedx: Mapped[Optional[Dict[str, Any]]] = mapped_column(JSONB)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )
    completed_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True))

    project: Mapped["Project"] = relationship(back_populates="scans")
    user: Mapped["User"] = relationship(back_populates="scans")
    events: Mapped[List["ScanEvent"]] = relationship(
        "ScanEvent", back_populates="scan", cascade="all, delete-orphan"
    )
    findings: Mapped[List["Finding"]] = relationship(
        "Finding", back_populates="scan", cascade="all, delete-orphan"
    )
    snapshots: Mapped[List["CodeSnapshot"]] = relationship(
        "CodeSnapshot", back_populates="scan", cascade="all, delete-orphan"
    )
    llm_interactions: Mapped[List["LLMInteraction"]] = relationship(
        "LLMInteraction", back_populates="scan"
    )
    risk_score: Mapped[Optional[int]] = mapped_column(Integer)


class ScanEvent(Base):
    __tablename__ = "scan_events"
    id: Mapped[int] = mapped_column(BIGINT, sa.Identity(always=True), primary_key=True)
    scan_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("scans.id"), nullable=False)
    stage_name: Mapped[str] = mapped_column(String(100), nullable=False)
    status: Mapped[str] = mapped_column(String(20), nullable=False)
    timestamp: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )
    # Optional per-event payload, surfaced over the SSE stream as the
    # `details` field. Used by §3.10b to carry per-file analysis
    # progress (`stage_name="FILE_ANALYZED"`,
    # `details={"file_path": ..., "findings_count": ...}`). Null for
    # legacy stage events that have no extra context.
    details: Mapped[Optional[Dict[str, Any]]] = mapped_column(JSONB, nullable=True)

    scan: Mapped["Scan"] = relationship(back_populates="events")


class ScanOutbox(Base):
    """Transactional outbox for RabbitMQ scan submissions.

    A row is inserted in the same transaction that creates the Scan; a sweep
    task reads unpublished rows and publishes them. This prevents the race
    where the scan row commits but the publish fails — leaving the scan
    stuck in QUEUED with no worker ever picking it up.
    """

    __tablename__ = "scan_outbox"
    id: Mapped[uuid.UUID] = mapped_column(
        PG_UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    scan_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("scans.id", ondelete="CASCADE"), nullable=False
    )
    queue_name: Mapped[str] = mapped_column(String(255), nullable=False)
    payload: Mapped[Dict[str, Any]] = mapped_column(JSONB, nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )
    published_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    attempts: Mapped[int] = mapped_column(Integer, nullable=False, default=0)


class SourceCodeFile(Base):
    __tablename__ = "source_code_files"
    hash: Mapped[str] = mapped_column(String(64), primary_key=True)
    content: Mapped[str] = mapped_column(Text, nullable=False)
    language: Mapped[str] = mapped_column(String(50), nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )


class CodeSnapshot(Base):
    __tablename__ = "code_snapshots"
    id: Mapped[uuid.UUID] = mapped_column(
        PG_UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    scan_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("scans.id"), nullable=False)
    snapshot_type: Mapped[str] = mapped_column(String(50), nullable=False)
    file_map: Mapped[Dict[str, str]] = mapped_column(JSONB, nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )

    scan: Mapped["Scan"] = relationship(back_populates="snapshots")


class Finding(Base):
    __tablename__ = "findings"
    id: Mapped[int] = mapped_column(BIGINT, sa.Identity(always=True), primary_key=True)
    scan_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("scans.id"), nullable=False)
    file_path: Mapped[str] = mapped_column(Text, nullable=False)
    line_number: Mapped[Optional[int]] = mapped_column(Integer)
    # V02.2.1: hard-capped at 512 characters at the persistence layer
    title: Mapped[str] = mapped_column(String(512), nullable=False)
    description: Mapped[Optional[str]] = mapped_column(Text)
    severity: Mapped[Optional[str]] = mapped_column(String(50))
    remediation: Mapped[Optional[str]] = mapped_column(Text)
    cwe: Mapped[Optional[str]] = mapped_column(String(50))
    confidence: Mapped[Optional[str]] = mapped_column(String(50))
    source: Mapped[Optional[str]] = mapped_column(String(32), nullable=True, index=True)
    cve_id: Mapped[Optional[str]] = mapped_column(String(64), nullable=True, index=True)
    corroborating_agents: Mapped[Optional[List[str]]] = mapped_column(JSONB)
    cvss_score: Mapped[Optional[float]] = mapped_column(DECIMAL(3, 1))
    cvss_vector: Mapped[Optional[str]] = mapped_column(String(100))
    references: Mapped[Optional[List[str]]] = mapped_column(JSONB)
    fixes: Mapped[Optional[Dict[str, Any]]] = mapped_column(JSONB)
    is_applied_in_remediation: Mapped[bool] = mapped_column(
        sa.Boolean, server_default="false", nullable=False
    )
    # Patch verifier (§3.9 / 2026-04-27). NULL = no verification attempted
    # (audit / suggest scans, scans before §3.9 shipped, or fixes that
    # weren't applied). True = re-running Semgrep over the patched code
    # no longer reports a finding for this rule at this file/line — the
    # fix worked. False = same Semgrep rule still fires at the same
    # location — fix didn't close the detection.
    fix_verified: Mapped[Optional[bool]] = mapped_column(
        sa.Boolean, nullable=True, default=None
    )

    # V02.2.1: enforce maximum string lengths at the DB layer
    __table_args__ = (
        sa.CheckConstraint(
            "length(description) <= 65535",
            name="ck_findings_description_maxlen",
        ),
        sa.CheckConstraint(
            "length(remediation) <= 65535",
            name="ck_findings_remediation_maxlen",
        ),
    )

    scan: Mapped["Scan"] = relationship(back_populates="findings")


class LLMConfiguration(Base):
    __tablename__ = "llm_configurations"
    id: Mapped[uuid.UUID] = mapped_column(
        PG_UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    name: Mapped[str] = mapped_column(
        String(255), unique=True, index=True, nullable=False
    )
    provider: Mapped[str] = mapped_column(String(50), nullable=False)
    model_name: Mapped[str] = mapped_column(String(100), nullable=False)
    tokenizer: Mapped[Optional[str]] = mapped_column(String(100))
    # classification: Secret / level=Confidential
    # protection: Fernet-encrypted at rest; must NOT be included in any LLMConfigurationRead Pydantic schema or API response
    # V15.3.1: info={"sensitive": True} prevents accidental serialisation by downstream Pydantic adapters
    encrypted_api_key: Mapped[str] = mapped_column(
        Text, nullable=False, info={"sensitive": True}
    )
    input_cost_per_million: Mapped[float] = mapped_column(
        DECIMAL(10, 6), nullable=False, server_default="0.0"
    )
    output_cost_per_million: Mapped[float] = mapped_column(
        DECIMAL(10, 6), nullable=False, server_default="0.0"
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=func.now()
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=func.now(), onupdate=func.now()
    )


class LLMInteraction(Base):
    __tablename__ = "llm_interactions"
    id: Mapped[int] = mapped_column(BIGINT, sa.Identity(always=True), primary_key=True)
    scan_id: Mapped[Optional[uuid.UUID]] = mapped_column(ForeignKey("scans.id"))
    chat_message_id: Mapped[Optional[int]] = mapped_column(
        ForeignKey("chat_messages.id")
    )
    agent_name: Mapped[str] = mapped_column(String(100), nullable=False)
    file_path: Mapped[Optional[str]] = mapped_column(Text)
    prompt_template_name: Mapped[Optional[str]] = mapped_column(String(100))
    # classification: LLM-payload / level=Restricted (may contain PII or secrets)
    # protection: redact via observability/mask before logs; retained per RETENTION_DAYS_LLM_INTERACTIONS then purged
    prompt_context: Mapped[Optional[Dict[str, Any]]] = mapped_column(JSONB)
    # classification: LLM-payload / level=Restricted (may contain PII or secrets)
    # protection: redact via observability/mask before logs; retained per RETENTION_DAYS_LLM_INTERACTIONS then purged
    raw_response: Mapped[str] = mapped_column(Text, nullable=False)
    # classification: LLM-payload / level=Restricted (may contain PII or secrets)
    # protection: redact via observability/mask before logs; retained per RETENTION_DAYS_LLM_INTERACTIONS then purged
    parsed_output: Mapped[Optional[Dict[str, Any]]] = mapped_column(JSONB)
    error: Mapped[Optional[str]] = mapped_column(Text)
    cost: Mapped[Optional[float]] = mapped_column(DECIMAL(10, 8))
    input_tokens: Mapped[Optional[int]] = mapped_column(Integer)
    output_tokens: Mapped[Optional[int]] = mapped_column(Integer)
    total_tokens: Mapped[Optional[int]] = mapped_column(Integer)
    timestamp: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )

    scan: Mapped[Optional["Scan"]] = relationship(back_populates="llm_interactions")
    chat_message: Mapped[Optional["ChatMessage"]] = relationship(
        back_populates="llm_interaction"
    )


class ChatSession(Base):
    __tablename__ = "chat_sessions"
    id: Mapped[uuid.UUID] = mapped_column(
        PG_UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    user_id: Mapped[int] = mapped_column(ForeignKey("user.id"), nullable=False)
    project_id: Mapped[Optional[uuid.UUID]] = mapped_column(ForeignKey("projects.id"))
    llm_config_id: Mapped[Optional[uuid.UUID]] = mapped_column(
        ForeignKey("llm_configurations.id")
    )
    title: Mapped[str] = mapped_column(String(255), nullable=False)
    frameworks: Mapped[Optional[List[str]]] = mapped_column(ARRAY(String))
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )

    user: Mapped["User"] = relationship(back_populates="chat_sessions")
    messages: Mapped[List["ChatMessage"]] = relationship(
        "ChatMessage", back_populates="session", cascade="all, delete-orphan"
    )


class ChatMessage(Base):
    __tablename__ = "chat_messages"
    id: Mapped[int] = mapped_column(BIGINT, sa.Identity(always=True), primary_key=True)
    session_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("chat_sessions.id"), nullable=False
    )
    role: Mapped[str] = mapped_column(String(20), nullable=False)
    # classification: UserContent / level=Restricted
    # protection: redact in logs; retained per RETENTION_DAYS_CHAT_MESSAGES then purged; must not appear in error responses
    content: Mapped[str] = mapped_column(Text, nullable=False)
    cost: Mapped[Optional[float]] = mapped_column(DECIMAL(10, 8))
    timestamp: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )

    session: Mapped["ChatSession"] = relationship(back_populates="messages")
    llm_interaction: Mapped[Optional["LLMInteraction"]] = relationship(
        "LLMInteraction", back_populates="chat_message"
    )


class Framework(Base):
    __tablename__ = "frameworks"
    id: Mapped[uuid.UUID] = mapped_column(
        PG_UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    name: Mapped[str] = mapped_column(
        String(255), nullable=False, unique=True, index=True
    )
    description: Mapped[str] = mapped_column(Text, nullable=False)
    agents: Mapped[List["Agent"]] = relationship(
        secondary="framework_agent_mappings", back_populates="frameworks"
    )


class Agent(Base):
    __tablename__ = "agents"
    id: Mapped[uuid.UUID] = mapped_column(
        PG_UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    name: Mapped[str] = mapped_column(
        String(255), nullable=False, unique=True, index=True
    )
    description: Mapped[str] = mapped_column(Text, nullable=False)
    domain_query: Mapped[Dict[str, Any]] = mapped_column(JSONB, nullable=False)
    frameworks: Mapped[List["Framework"]] = relationship(
        secondary="framework_agent_mappings", back_populates="agents"
    )


class FrameworkAgentMapping(Base):
    __tablename__ = "framework_agent_mappings"
    framework_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("frameworks.id"), primary_key=True
    )
    agent_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("agents.id"), primary_key=True
    )


class PromptTemplate(Base):
    __tablename__ = "prompt_templates"
    id: Mapped[uuid.UUID] = mapped_column(
        PG_UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    # Display name — not used for lookup or uniqueness. The compound
    # (agent_name, template_type, variant) unique constraint below is the
    # identity key; name is free-form so admins can duplicate display names
    # across variants (e.g., "SQLi Audit" can exist as both generic and
    # anthropic variants).
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    template_type: Mapped[str] = mapped_column(
        String(50), nullable=False, index=True, server_default="QUICK_AUDIT"
    )
    agent_name: Mapped[Optional[str]] = mapped_column(String(100))
    # "generic" = portable prompt that works across all providers (default).
    # "anthropic" = prompt tuned for Claude (cache-friendly prefix, tool use,
    # stronger reasoning instructions). The renderer picks by current
    # llm.optimization_mode with a fallback to "generic".
    variant: Mapped[str] = mapped_column(
        String(32), nullable=False, server_default="generic"
    )
    version: Mapped[int] = mapped_column(Integer, nullable=False, default=1)
    template_text: Mapped[str] = mapped_column(Text, nullable=False)

    __table_args__ = (
        sa.UniqueConstraint(
            "agent_name",
            "template_type",
            "variant",
            name="uq_prompt_templates_agent_type_variant",
        ),
    )


class RAGPreprocessingJob(Base):
    __tablename__ = "rag_preprocessing_jobs"
    id: Mapped[uuid.UUID] = mapped_column(
        PG_UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    user_id: Mapped[int] = mapped_column(ForeignKey("user.id"), nullable=False)
    framework_name: Mapped[str] = mapped_column(String(255), nullable=False)
    llm_config_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("llm_configurations.id"), nullable=False
    )
    original_file_hash: Mapped[str] = mapped_column(
        String(64), nullable=False, index=True
    )
    # classification: UserUpload / level=Restricted
    # protection: NULL after status transitions to COMPLETED unless raw_content_retention_consent=True;
    # purged via RAGJobRepository.purge_old_raw_content per RETENTION_DAYS_RAG_JOBS
    raw_content: Mapped[Optional[bytes]] = mapped_column(sa.LargeBinary, nullable=True)
    status: Mapped[str] = mapped_column(String(50), nullable=False, default="PENDING")
    estimated_cost: Mapped[Optional[Dict[str, Any]]] = mapped_column(JSONB)
    actual_cost: Mapped[Optional[float]] = mapped_column(DECIMAL(10, 8))
    processed_documents: Mapped[Optional[List[Dict[str, Any]]]] = mapped_column(JSONB)
    error_message: Mapped[Optional[str]] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )
    completed_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True))

    user: Mapped["User"] = relationship()
    llm_configuration: Mapped["LLMConfiguration"] = relationship()


class CweDetail(Base):
    __tablename__ = "cwe_details"
    id: Mapped[str] = mapped_column(String(20), primary_key=True)  # e.g., "CWE-22"
    name: Mapped[str] = mapped_column(Text, nullable=False)
    abstraction: Mapped[Optional[str]] = mapped_column(String(50))
    description: Mapped[str] = mapped_column(Text, nullable=False)
    rag_document_text: Mapped[str] = mapped_column(Text, nullable=False)

    owasp_mapping: Mapped[Optional["CweOwaspMapping"]] = relationship(
        back_populates="cwe_detail"
    )


class CweOwaspMapping(Base):
    __tablename__ = "cwe_owasp_mappings"
    cwe_id: Mapped[str] = mapped_column(ForeignKey("cwe_details.id"), primary_key=True)
    owasp_category_id: Mapped[str] = mapped_column(
        String(10), nullable=False
    )  # e.g., "A01"
    owasp_category_name: Mapped[str] = mapped_column(String(255), nullable=False)
    owasp_rank: Mapped[int] = mapped_column(Integer, nullable=False)

    cwe_detail: Mapped["CweDetail"] = relationship(back_populates="owasp_mapping")


class SystemConfiguration(Base):
    __tablename__ = "system_configurations"
    key: Mapped[str] = mapped_column(String(255), primary_key=True)
    # classification: Config / level=Secret when is_secret=true
    # protection: Fernet-encrypted when encrypted=true; never logged; redacted on non-admin API surfaces
    value: Mapped[Dict[str, Any]] = mapped_column(JSONB, nullable=False)
    description: Mapped[Optional[str]] = mapped_column(Text)
    is_secret: Mapped[bool] = mapped_column(
        sa.Boolean, server_default="false", nullable=False
    )
    encrypted: Mapped[bool] = mapped_column(
        sa.Boolean, server_default="false", nullable=False
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now()
    )


# --- Phase H.2 — User Groups + memberships ---------------------------
# Groups let multiple SCCAP users share scan visibility. A regular user
# sees their own scans plus scans owned by anyone in the same group;
# admins see everything. `UserGroup` is the group row; membership is a
# separate table so users can belong to multiple groups and so we can
# later add roles per group without reshaping UserGroup.


class UserGroup(Base):
    __tablename__ = "user_groups"
    id: Mapped[uuid.UUID] = mapped_column(
        PG_UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    name: Mapped[str] = mapped_column(String(255), nullable=False, unique=True)
    description: Mapped[Optional[str]] = mapped_column(Text)
    created_by: Mapped[int] = mapped_column(ForeignKey("user.id"), nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now()
    )

    memberships: Mapped[List["UserGroupMembership"]] = relationship(
        "UserGroupMembership",
        back_populates="group",
        cascade="all, delete-orphan",
    )


class UserGroupMembership(Base):
    __tablename__ = "user_group_memberships"
    group_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("user_groups.id", ondelete="CASCADE"), primary_key=True
    )
    user_id: Mapped[int] = mapped_column(
        ForeignKey("user.id", ondelete="CASCADE"), primary_key=True
    )
    # "owner" grants manage-members powers within the group (future scope);
    # "member" is read-only. Today the backend treats both the same for
    # scan visibility — admins do all management via /admin/user-groups.
    role: Mapped[str] = mapped_column(
        String(16), nullable=False, server_default="member"
    )
    joined_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )

    group: Mapped["UserGroup"] = relationship("UserGroup", back_populates="memberships")
