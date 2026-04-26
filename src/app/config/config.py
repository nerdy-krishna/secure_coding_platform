# src/app/config/config.py
from pydantic import SecretStr, field_validator, Field
from pydantic_settings import BaseSettings, SettingsConfigDict
from typing import List, Optional


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env", env_file_encoding="utf-8", extra="ignore"
    )

    # --- Database Configuration ---
    POSTGRES_USER: str
    POSTGRES_PASSWORD: str
    POSTGRES_DB: str
    POSTGRES_HOST: str
    POSTGRES_PORT: int
    POSTGRES_HOST_ALEMBIC: str
    DB_ECHO: bool = False

    # Derived database URLs
    ASYNC_DATABASE_URL: Optional[str] = None
    ALEMBIC_DATABASE_URL: Optional[str] = None

    @field_validator("ASYNC_DATABASE_URL", mode="before")
    def assemble_async_db_connection(cls, v, info):
        if v:
            return v
        values = info.data
        return f"postgresql+asyncpg://{values.get('POSTGRES_USER')}:{values.get('POSTGRES_PASSWORD')}@{values.get('POSTGRES_HOST')}:{values.get('POSTGRES_PORT')}/{values.get('POSTGRES_DB')}"

    @field_validator("ALEMBIC_DATABASE_URL", mode="before")
    def assemble_alembic_db_connection(cls, v, info):
        if v:
            return v
        values = info.data
        return f"postgresql+asyncpg://{values.get('POSTGRES_USER')}:{values.get('POSTGRES_PASSWORD')}@{values.get('POSTGRES_HOST_ALEMBIC')}:{values.get('POSTGRES_PORT')}/{values.get('POSTGRES_DB')}"

    # --- RabbitMQ Configuration (UPDATED) ---
    RABBITMQ_DEFAULT_USER: str
    RABBITMQ_DEFAULT_PASS: str
    RABBITMQ_HOST: str
    RABBITMQ_URL: Optional[str] = None

    # Renamed CODE_QUEUE for clarity and added the new approval queue
    RABBITMQ_SUBMISSION_QUEUE: str = "code_submission_queue"
    RABBITMQ_APPROVAL_QUEUE: str = "analysis_approved_queue"
    RABBITMQ_REMEDIATION_QUEUE: str = "remediation_trigger_queue"

    @field_validator("RABBITMQ_URL", mode="before")
    def assemble_rabbitmq_connection(cls, v, info):
        if v:
            return v
        values = info.data
        return f"amqp://{values.get('RABBITMQ_DEFAULT_USER')}:{values.get('RABBITMQ_DEFAULT_PASS')}@{values.get('RABBITMQ_HOST')}/"

    # --- Email (SMTP) Configuration ---
    SMTP_HOST: Optional[str] = None
    SMTP_PORT: int = 587
    SMTP_USER: Optional[str] = None
    SMTP_PASSWORD: Optional[str] = None
    SMTP_FROM: Optional[str] = None
    SMTP_TLS: bool = True
    SMTP_SSL: bool = False

    # --- Security & Auth ---
    SECRET_KEY: str
    ENCRYPTION_KEY: str
    ENVIRONMENT: str = "development"
    ACCESS_TOKEN_LIFETIME_SECONDS: int = 60 * 60  # 60 minutes
    REFRESH_TOKEN_LIFETIME_SECONDS: int = 60 * 60 * 24 * 7  # 7 days

    ALLOWED_ORIGINS_STR: str = Field(alias="ALLOWED_ORIGINS")

    @property
    def ALLOWED_ORIGINS(self) -> List[str]:
        return [origin.strip() for origin in self.ALLOWED_ORIGINS_STR.split(",")]

    # Canonical public URL for the frontend — used when building absolute links
    # in emails (password reset, verification). Falls back to the first entry
    # in ALLOWED_ORIGINS if unset; fail-fast in production if neither is usable.
    FRONTEND_BASE_URL: Optional[str] = None

    @property
    def frontend_base_url(self) -> str:
        if self.FRONTEND_BASE_URL:
            return self.FRONTEND_BASE_URL.rstrip("/")
        origins = self.ALLOWED_ORIGINS
        if origins and origins[0]:
            return origins[0].rstrip("/")
        if self.ENVIRONMENT == "production":
            raise RuntimeError(
                "FRONTEND_BASE_URL is not set and ALLOWED_ORIGINS is empty. "
                "Configure one of them so email links can be built."
            )
        return "http://localhost:5173"

    # --- Rate Limiting (NEW) ---
    # Requests Per Minute (RPM) for each LLM provider.
    # A value of 0 or less will effectively disable the rate limiter for that provider.
    OPENAI_REQUESTS_PER_MINUTE: int = Field(
        default=60, description="Max RPM for OpenAI models."
    )
    OPENAI_TOKENS_PER_MINUTE: int = Field(
        default=30000, description="Max TPM for OpenAI models."
    )
    GOOGLE_REQUESTS_PER_MINUTE: int = Field(
        default=60, description="Max RPM for Google models."
    )
    GOOGLE_TOKENS_PER_MINUTE: int = Field(
        default=60000, description="Max TPM for Google models."
    )
    ANTHROPIC_REQUESTS_PER_MINUTE: int = Field(
        default=30, description="Max RPM for Anthropic models."
    )
    ANTHROPIC_TOKENS_PER_MINUTE: int = Field(
        default=20000, description="Max TPM for Anthropic models."
    )

    # --- Worker ---
    # Hard upper bound for a single scan workflow invocation. If exceeded, the
    # workflow is cancelled, the scan marked FAILED, and the RabbitMQ message
    # NACK'd (without requeue) so it doesn't loop forever. Default: 2 hours.
    SCAN_WORKFLOW_TIMEOUT_SECONDS: int = Field(
        default=2 * 60 * 60, description="Max seconds a single scan workflow may run."
    )

    # --- RAG vector store (PR1 of Chroma → Qdrant migration) ---
    # Default `chroma` keeps existing deployments on the current path.
    # `dual` writes to both Chroma and Qdrant (reads stay on Chroma).
    # `qdrant` is reachable only after PR2 flips reads; the field
    # accepts it now so config validation matches what PR2 ships.
    RAG_VECTOR_STORE: str = Field(
        default="chroma",
        description="One of: chroma | dual | qdrant.",
    )
    QDRANT_HOST: str = "qdrant"
    QDRANT_PORT: int = 6333
    QDRANT_API_KEY: Optional[SecretStr] = None

    @field_validator("RAG_VECTOR_STORE")
    def _validate_rag_vector_store(cls, v: str) -> str:
        allowed = {"chroma", "dual", "qdrant"}
        if v not in allowed:
            raise ValueError(
                f"RAG_VECTOR_STORE must be one of {sorted(allowed)}; got {v!r}."
            )
        return v

    # --- Observability (Langfuse v3, optional) ---
    # Disabled by default; opt in by setting LANGFUSE_ENABLED=true plus the
    # public/secret keys minted from the self-hosted Langfuse UI. When
    # disabled, all instrumentation short-circuits — zero overhead, zero
    # network traffic. See `app.infrastructure.observability` and the run
    # `langfuse-otel-observability`.
    LANGFUSE_ENABLED: bool = False
    LANGFUSE_HOST: str = "http://langfuse-web:3000"
    LANGFUSE_PUBLIC_KEY: Optional[SecretStr] = None
    LANGFUSE_SECRET_KEY: Optional[SecretStr] = None


settings = Settings()  # type: ignore
