# src/app/api/models.py

import datetime
import uuid
from pydantic import BaseModel, Field
from typing import List, Optional, Dict

# === LLM Configuration Schemas (NEW) ===


class LLMConfigurationBase(BaseModel):
    name: str = Field(
        ..., description="A unique, user-friendly name for the LLM configuration."
    )
    provider: str = Field(
        ..., description="The LLM provider (e.g., 'openai', 'google', 'anthropic')."
    )
    model_name: str = Field(
        ..., description="The specific model name (e.g., 'gpt-4o', 'gemini-1.5-pro')."
    )


class LLMConfigurationCreate(LLMConfigurationBase):
    api_key: str = Field(..., description="The API key for the provider.")


class LLMConfigurationRead(LLMConfigurationBase):
    id: uuid.UUID

    class Config:
        from_attributes = True


# --- Request Models (EXISTING, MERGED & UPDATED) ---


class SubmissionRequest(BaseModel):
    files: Optional[List[Dict[str, str]]] = Field(
        None, description="List of files, each a dict with 'path' and 'content'."
    )
    repo_url: Optional[str] = Field(
        None, description="URL of the Git repository to analyze."
    )
    # NEW fields based on our plan
    frameworks: List[str] = Field(
        ..., description="List of security frameworks to analyze against."
    )
    main_llm_config_id: uuid.UUID = Field(
        ..., description="ID of the LLM config for the main agent."
    )
    specialized_llm_config_id: uuid.UUID = Field(
        ..., description="ID of the LLM config for specialized agents."
    )


class SecurityQueryCreate(BaseModel):
    query_name: str
    language: str
    query_content: str
    description: Optional[str] = None
    cwe_id: Optional[str] = None
    asvs_category: Optional[str] = None


class SecurityQueryUpdate(BaseModel):
    query_name: Optional[str] = None
    query_content: Optional[str] = None
    description: Optional[str] = None
    status: Optional[str] = None


# --- Response Models (EXISTING, MODERNIZED) ---


class SubmissionResponse(BaseModel):
    submission_id: uuid.UUID  # Corrected from int to uuid
    message: str


class FixSuggestionResponse(BaseModel):
    id: int  # Assuming this remains an integer as it might not be a primary table
    description: str
    suggested_fix: str

    class Config:
        from_attributes = True


class VulnerabilityFindingResponse(BaseModel):
    id: int
    file_path: str
    cwe: str
    description: str
    severity: str
    line_number: int
    remediation: str
    confidence: str
    references: List[str]
    fixes: List[FixSuggestionResponse] = []

    class Config:
        from_attributes = True


class SubmissionResultResponse(BaseModel):
    id: uuid.UUID  # Corrected from int to uuid
    status: str
    submitted_at: datetime.datetime
    completed_at: Optional[datetime.datetime] = None
    findings: List[VulnerabilityFindingResponse] = []

    class Config:
        from_attributes = True


class SubmissionStatus(BaseModel):
    submission_id: uuid.UUID  # Corrected from int to uuid
    status: str
    submitted_at: Optional[datetime.datetime] = None
    completed_at: Optional[datetime.datetime] = None


class SecurityQueryResponse(BaseModel):
    id: int
    query_name: str
    language: str
    description: Optional[str]
    status: str
    created_at: datetime.datetime
    updated_at: datetime.datetime

    class Config:
        from_attributes = True


class LLMInteractionResponse(BaseModel):
    id: int
    agent_name: str
    timestamp: datetime.datetime
    prompt_title: Optional[str]
    status: str
    interaction_context: Optional[Dict]

    class Config:
        from_attributes = True


class DashboardStats(BaseModel):
    total_submissions: int
    pending_submissions: int
    completed_submissions: int
    total_findings: int
    high_severity_findings: int
