from pydantic import BaseModel, EmailStr, Field
from typing import Literal, Optional


class SetupRequest(BaseModel):
    """schema for the initial setup request"""

    admin_email: EmailStr = Field(..., description="Email for the superuser account")
    admin_password: str = Field(
        ..., min_length=8, description="Password for the superuser account"
    )

    # LLM Configuration
    llm_provider: str = Field(
        ..., description="LLM Provider (openai, anthropic, gemini)"
    )
    llm_api_key: str = Field(..., description="API Key for the LLM Provider")
    llm_model: str = Field(..., description="Model name (e.g., gpt-4o, claude-3-opus)")
    llm_optimization_mode: Literal["anthropic_optimized", "multi_provider"] = Field(
        default="multi_provider",
        description=(
            "How the platform tunes prompts and features for the LLM. "
            "'anthropic_optimized' enables prompt caching, tuned variants, and "
            "tool use — requires llm_provider='anthropic'. 'multi_provider' is "
            "the portable default."
        ),
    )

    # System Configuration
    deployment_type: str = Field(..., description="Type of deployment (local or cloud)")
    frontend_url: Optional[str] = Field(
        default=None,
        description="Public URL for cloud deployment (e.g., http://123.45.67.89). Required if deployment_type is 'cloud'.",
    )


class SetupStatusResponse(BaseModel):
    """Schema for checking if setup is required"""

    is_setup_completed: bool = Field(
        ..., description="True if the system is already configured"
    )
