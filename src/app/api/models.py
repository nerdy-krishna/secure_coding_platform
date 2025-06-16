# src/app/api/models.py

from datetime import datetime
import uuid
from pydantic import UUID4, BaseModel, Field
from typing import List, Optional, Dict, Any

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
    submitted_at: datetime
    completed_at: Optional[datetime] = None
    findings: List[VulnerabilityFindingResponse] = []

    class Config:
        from_attributes = True


class SubmissionStatus(BaseModel):
    submission_id: uuid.UUID  # Corrected from int to uuid
    status: str
    submitted_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None


class SecurityQueryResponse(BaseModel):
    id: int
    query_name: str
    language: str
    description: Optional[str]
    status: str
    created_at: datetime
    updated_at: datetime

    class Config:
        from_attributes = True


class LLMInteractionResponse(BaseModel):
    id: int
    agent_name: str
    timestamp: datetime
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

class SubmissionHistoryItem(BaseModel):
    id: UUID4
    # project_name: Optional[str] = None # Frontend expects this, but not in DB model or current API model
    # primary_language: Optional[str] = None # Frontend expects this, but not in DB model or current API model
    status: str
    submitted_at: datetime
    completed_at: Optional[datetime] = None
    # total_findings: Optional[int] = None # Frontend expects this, consider adding if available

    class Config:
        from_attributes = True

# --- Detailed Analysis Result Models (NEW - for /result/{submission_id}) ---

# Re-uses VulnerabilityFindingResponse for individual findings within a file.
# Re-uses FixSuggestionResponse.

class SeverityCountsResponse(BaseModel):
    CRITICAL: int = 0
    HIGH: int = 0
    MEDIUM: int = 0
    LOW: int = 0
    INFORMATIONAL: int = 0

    class Config:
        from_attributes = True


class SummaryResponse(BaseModel):
    total_findings_count: int = 0
    files_analyzed_count: int = 0
    severity_counts: SeverityCountsResponse = Field(default_factory=SeverityCountsResponse)

    class Config:
        from_attributes = True


class OverallRiskScoreResponse(BaseModel):
    score: str = "N/A"
    severity: str = "N/A"

    class Config:
        from_attributes = True


class SubmittedFileReportItem(BaseModel):
    file_path: str
    findings: List[VulnerabilityFindingResponse] = []
    # Optional fields from db_models.SubmittedFile, now included:
    language: Optional[str] = None
    analysis_summary: Optional[str] = None
    identified_components: Optional[List[str]] = None
    asvs_analysis: Optional[Dict[str, Any]] = None

    class Config:
        from_attributes = True


class SummaryReportResponse(BaseModel):
    submission_id: uuid.UUID
    project_name: Optional[str] = "N/A"
    primary_language: Optional[str] = "N/A"
    selected_frameworks: List[str] = []
    analysis_timestamp: Optional[datetime] = None
    summary: SummaryResponse = Field(default_factory=SummaryResponse)
    files_analyzed: List[SubmittedFileReportItem] = []
    overall_risk_score: OverallRiskScoreResponse = Field(default_factory=OverallRiskScoreResponse)

    class Config:
        from_attributes = True


class AnalysisResultDetailResponse(BaseModel):
    summary_report: Optional[SummaryReportResponse] = None
    # Optional fields based on frontend's AnalysisResultResponse type:
    sarif_report: Optional[Dict] = None # SARIFLog is typically a JSON object
    text_report: Optional[str] = None
    original_code_map: Optional[Dict[str, str]] = None
    fixed_code_map: Optional[Dict[str, str]] = None

    class Config:
        from_attributes = True
