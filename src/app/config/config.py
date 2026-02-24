# src/app/config/config.py
from pydantic import field_validator, Field
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


settings = Settings()  # type: ignore
