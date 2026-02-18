# src/app/api/v1/models.py

from datetime import datetime
import uuid
from pydantic import UUID4, BaseModel, Field, field_validator
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
    tokenizer: Optional[str] = Field(
        None, description="The tokenizer to use for token counting (e.g., 'cl100k_base'). Defaults to model-specific or a general tokenizer if not provided."
    )
    input_cost_per_million: float = Field(
        default=0.0, description="Cost per 1 million input tokens in USD."
    )
    output_cost_per_million: float = Field(
        default=0.0, description="Cost per 1 million output tokens in USD."
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
    tokenizer: Optional[str] = Field(
        None, description="The tokenizer to use for token counting (e.g., 'cl100k_base')."
    )
    api_key: Optional[str] = Field(
        None,
        description="The API key for the provider. If provided, it will be updated and re-encrypted.",
    )
    input_cost_per_million: Optional[float] = Field(
        None, description="Cost per 1 million input tokens in USD."
    )
    output_cost_per_million: Optional[float] = Field(
        None, description="Cost per 1 million output tokens in USD."
    )

    class Config:
        from_attributes = True


class LLMConfigurationRead(LLMConfigurationBase):
    id: uuid.UUID
    created_at: datetime
    updated_at: datetime

    class Config:
        from_attributes = True


# --- Agent Schemas (NEW) ---
class AgentBase(BaseModel):
    name: str
    description: str
    domain_query: Dict[str, Any]

class AgentCreate(AgentBase):
    pass

class AgentUpdate(BaseModel):
    name: Optional[str] = None
    description: Optional[str] = None
    domain_query: Optional[str] = None

class AgentRead(AgentBase):
    id: uuid.UUID

    class Config:
        from_attributes = True

# --- Framework Schemas (NEW) ---
class FrameworkBase(BaseModel):
    name: str = Field(..., description="The unique name of the security framework (e.g., 'OWASP ASVS').")
    description: str = Field(..., description="A brief description of the framework.")

class FrameworkCreate(FrameworkBase):
    pass

class FrameworkUpdate(BaseModel):
    name: Optional[str] = None
    description: Optional[str] = None

class FrameworkRead(FrameworkBase):
    id: uuid.UUID
    agents: List[AgentRead] = []

    class Config:
        from_attributes = True

# --- Framework-Agent Mapping Schema (NEW) ---
class FrameworkAgentMappingUpdate(BaseModel):
    agent_ids: List[uuid.UUID]


# --- RAG Management Schemas (NEW) ---
class RAGDocumentDeleteRequest(BaseModel):
    document_ids: List[str]


# --- Prompt Template Schemas (NEW) ---
class PromptTemplateBase(BaseModel):
    name: str = Field(..., description="The unique name for the prompt template.")
    template_type: str = Field(..., description="The type of template (e.g., 'QUICK_AUDIT', 'DETAILED_REMEDIATION').")
    agent_name: Optional[str] = Field(None, description="The name of the agent this prompt is for.")
    version: int = Field(1, description="The version of the prompt template.")
    template_text: str = Field(..., description="The content of the prompt template.")

class PromptTemplateCreate(PromptTemplateBase):
    pass

class PromptTemplateUpdate(BaseModel):
    name: Optional[str] = None
    template_type: Optional[str] = None
    agent_name: Optional[str] = None
    version: Optional[int] = None
    template_text: Optional[str] = None

class PromptTemplateRead(PromptTemplateBase):
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
    original_snippet: str # ADDED
    suggested_fix: str

    class Config:
        from_attributes = True


class VulnerabilityFindingResponse(BaseModel):
    id: int
    file_path: str
    title: str
    cwe: str
    description: str
    severity: str
    line_number: int
    remediation: str
    confidence: str
    corroborating_agents: Optional[List[str]] = None
    cvss_score: Optional[float] = None
    cvss_vector: Optional[str] = None
    references: List[str]
    fixes: Optional[Dict[str, Any]] = None
    is_applied_in_remediation: bool = False

    @field_validator("fixes", mode="before")
    @classmethod
    def empty_dict_for_none_fixes(cls, v: Any) -> Any:
        if v is None:
            return None
        return v

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
    scan_id: Optional[uuid.UUID] = None
    file_path: Optional[str] = None
    agent_name: str
    timestamp: datetime
    cost: Optional[float] = None
    input_tokens: Optional[int] = None
    output_tokens: Optional[int] = None
    total_tokens: Optional[int] = None
    prompt_template_name: Optional[str] = None
    prompt_context: Optional[Dict[str, Any]] = None
    parsed_output: Optional[Dict[str, Any]] = None
    error: Optional[str] = None

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
    risk_score: int

    class Config:
        from_attributes = True


class PaginatedResultsResponse(BaseModel):
    items: List[ResultIndexItem]
    total: int


class GitRepoPreviewRequest(BaseModel):
    repo_url: str


class RemediationRequest(BaseModel):
    categories_to_fix: List[str] = Field(
        ...,
        description="A list of vulnerability categories (agent names) to remediate.",
    )


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
    severity_counts: SeverityCountsResponse = Field(
        default_factory=SeverityCountsResponse
    )

    class Config:
        from_attributes = True


class OverallRiskScoreResponse(BaseModel):
    score: int = 0
    severity: str = "N/A"

    class Config:
        from_attributes = True


class SubmittedFileReportItem(BaseModel):
    file_path: str
    findings: List[VulnerabilityFindingResponse] = []
    language: Optional[str] = None
    analysis_summary: Optional[str] = None
    skipped_reason: Optional[str] = None
    identified_components: Optional[List[str]] = None
    asvs_analysis: Optional[Dict[str, Any]] = None

    class Config:
        from_attributes = True


class SummaryReportResponse(BaseModel):
    submission_id: uuid.UUID
    project_id: uuid.UUID
    project_name: Optional[str] = "N/A"
    scan_type: str = "audit"
    primary_language: Optional[str] = "N/A"
    selected_frameworks: List[str] = []
    analysis_timestamp: Optional[datetime] = None
    summary: SummaryResponse = Field(default_factory=SummaryResponse)
    files_analyzed: List[SubmittedFileReportItem] = []
    overall_risk_score: OverallRiskScoreResponse = Field(
        default_factory=OverallRiskScoreResponse
    )

    class Config:
        from_attributes = True


class AnalysisResultDetailResponse(BaseModel):
    status: str
    impact_report: Optional[Dict[str, Any]] = None
    sarif_report: Optional[Dict[str, Any]] = None
    summary_report: Optional[SummaryReportResponse] = None
    text_report: Optional[str] = None
    original_code_map: Optional[Dict[str, str]] = None
    fixed_code_map: Optional[Dict[str, str]] = None

    class Config:
        from_attributes = True


class ScanResponse(BaseModel):
    scan_id: uuid.UUID
    project_id: uuid.UUID
    message: str

class ScanEventItem(BaseModel):
    stage_name: str
    status: str
    timestamp: datetime

    class Config:
        from_attributes = True

class ScanHistoryItem(BaseModel):
    id: uuid.UUID
    project_id: uuid.UUID
    project_name: str
    scan_type: str
    status: str
    created_at: datetime
    completed_at: Optional[datetime] = None
    cost_details: Optional[Dict[str, Any]] = None
    events: List[ScanEventItem] = []
    has_sarif_report: bool = False
    has_impact_report: bool = False

    class Config:
        from_attributes = True

class PaginatedScanHistoryResponse(BaseModel):
    items: List[ScanHistoryItem]
    total: int

class ProjectHistoryItem(BaseModel):
    id: uuid.UUID
    name: str
    repository_url: Optional[str] = None
    created_at: datetime
    updated_at: datetime
    scans: List[ScanHistoryItem] = []

    class Config:
        from_attributes = True

class PaginatedProjectHistoryResponse(BaseModel):
    items: List[ProjectHistoryItem]
    total: int