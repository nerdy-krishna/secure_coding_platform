# src/app/api/models.py

from datetime import datetime
import uuid
from pydantic import UUID4, BaseModel, Field
from typing import List, Optional, Dict, Any

# === LLM Configuration Schemas (UPDATED) ===


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
    # --- ADDED: New fields for dynamic configuration ---
    tokenizer_encoding: str = Field(
        default="cl100k_base",
        description="The name of the tiktoken tokenizer for this model (e.g., 'cl100k_base')."
    )
    input_cost_per_million: float = Field(
        default=0.0,
        description="Cost per 1 million input tokens in USD."
    )
    output_cost_per_million: float = Field(
        default=0.0,
        description="Cost per 1 million output tokens in USD."
    )
    # --- End of added fields ---


class LLMConfigurationCreate(LLMConfigurationBase):
    api_key: str = Field(..., description="The API key for the provider.")


class LLMConfigurationUpdate(BaseModel):
    name: Optional[str] = Field(
        None, description="A unique, user-friendly name for the LLM configuration."
    )
    provider: Optional[str] = Field(
        None, description="The LLM provider (e.g., 'openai', 'google', 'anthropic')."
    )
    model_name: Optional[str] = Field(
        None, description="The specific model name (e.g., 'gpt-4o', 'gemini-1.5-pro')."
    )
    api_key: Optional[str] = Field(
        None, description="The API key for the provider. If provided, it will be updated and re-encrypted."
    )
    tokenizer_encoding: Optional[str] = Field(
        None,
        description="The name of the tiktoken tokenizer for this model (e.g., 'cl100k_base')."
    )
    input_cost_per_million: Optional[float] = Field(
        None,
        description="Cost per 1 million input tokens in USD."
    )
    output_cost_per_million: Optional[float] = Field(
        None,
        description="Cost per 1 million output tokens in USD."
    )

    class Config:
        from_attributes = True


class LLMConfigurationRead(LLMConfigurationBase):
    id: uuid.UUID
    created_at: datetime
    updated_at: datetime

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
    frameworks: List[str] = Field(
        ..., description="List of security frameworks to analyze against."
    )
    main_llm_config_id: uuid.UUID = Field(
        ..., description="ID of the LLM config for the main agent."
    )
    specialized_llm_config_id: uuid.UUID = Field(
        ..., description="ID of the LLM config for specialized agents."
    )

# --- Individual File Model (NEW - for graph input) ---
class CodeFile(BaseModel):
    filename: str = Field(..., description="The name/path of the file.")
    content: str = Field(..., description="The content of the file.")


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
    submission_id: uuid.UUID
    message: str


class FixSuggestionResponse(BaseModel):
    id: int
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
    id: uuid.UUID
    status: str
    submitted_at: datetime
    completed_at: Optional[datetime] = None
    findings: List[VulnerabilityFindingResponse] = []

    class Config:
        from_attributes = True


class SubmissionStatus(BaseModel):
    submission_id: uuid.UUID
    status: str
    submitted_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    estimated_cost: Optional[Dict[str, Any]] = None

    class Config:
        from_attributes = True


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
    submission_id: Optional[uuid.UUID] = None
    file_path: Optional[str] = None
    agent_name: str
    timestamp: datetime
    cost: Optional[float] = None
    input_tokens: Optional[int] = None
    output_tokens: Optional[int] = None
    total_tokens: Optional[int] = None

    class Config:
        from_attributes = True


class DashboardStats(BaseModel):
    total_submissions: int
    pending_submissions: int
    completed_submissions: int
    total_findings: int
    high_severity_findings: int

class EstimatedCost(BaseModel):
    input_cost: float
    predicted_output_cost: float
    total_estimated_cost: float
    predicted_output_tokens: float

class ActualCost(BaseModel):
    total_cost: float
    total_input_tokens: int
    total_output_tokens: int
    total_tokens: int

class SubmissionHistoryItem(BaseModel):
    id: UUID4
    project_name: str
    status: str
    submitted_at: datetime
    completed_at: Optional[datetime] = None
    estimated_cost: Optional[EstimatedCost] = None
    actual_cost: Optional[ActualCost] = None

    class Config:
        from_attributes = True

class PaginatedSubmissionHistoryResponse(BaseModel):
    items: List[SubmissionHistoryItem]
    total: int

class ResultIndexItem(BaseModel):
    submission_id: uuid.UUID
    project_name: str
    completed_at: Optional[datetime]
    total_findings: int
    critical_findings: int
    high_findings: int
    medium_findings: int
    low_findings: int
    risk_score: int # We will calculate and add this

    class Config:
        from_attributes = True

class PaginatedResultsResponse(BaseModel):
    items: List[ResultIndexItem]
    total: int
    
class GitRepoPreviewRequest(BaseModel):
    repo_url: str

class RemediationRequest(BaseModel):
    categories_to_fix: List[str] = Field(..., description="A list of vulnerability categories (agent names) to remediate.")

# --- Detailed Analysis Result Models (NEW - for /result/{submission_id}) ---

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
    impact_report: Optional[Dict[str, Any]] = None
    sarif_report: Optional[Dict[str, Any]] = None
    summary_report: Optional[SummaryReportResponse] = None
    text_report: Optional[str] = None
    original_code_map: Optional[Dict[str, str]] = None
    fixed_code_map: Optional[Dict[str, str]] = None

    class Config:
        from_attributes = True
