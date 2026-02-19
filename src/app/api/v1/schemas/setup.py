from pydantic import BaseModel, EmailStr, Field
from typing import Optional

class SetupRequest(BaseModel):
    """schema for the initial setup request"""
    admin_email: EmailStr = Field(..., description="Email for the superuser account")
    admin_password: str = Field(..., min_length=8, description="Password for the superuser account")
    
    # LLM Configuration
    llm_provider: str = Field(..., description="LLM Provider (openai, anthropic, gemini)")
    llm_api_key: str = Field(..., description="API Key for the LLM Provider")
    llm_model: str = Field(..., description="Model name (e.g., gpt-4o, claude-3-opus)")

    # System Configuration
    allowed_origins: Optional[list[str]] = Field(
        default=None, 
        description="List of allowed origins for CORS (e.g., https://my-domain.com). If empty, defaults to restricted set."
    )

class SetupStatusResponse(BaseModel):
    """Schema for checking if setup is required"""
    is_setup_completed: bool = Field(..., description="True if the system is already configured")
