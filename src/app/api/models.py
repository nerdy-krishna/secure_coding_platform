# src/app/api/models.py
from pydantic import BaseModel, Field
from typing import List, Optional, Dict
import datetime

# --- Request Models ---

class SubmissionRequest(BaseModel):
    files: List[Dict[str, str]] = Field(description="List of files, each a dict with 'path' and 'content'.")
    repo_url: Optional[str] = Field(None, description="URL of the Git repository to analyze.")

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


# --- Response Models ---

class SubmissionResponse(BaseModel):
    submission_id: int
    message: str

class FixSuggestionResponse(BaseModel):
    id: int
    description: str
    suggested_fix: str

    class Config:
        orm_mode = True

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
        orm_mode = True

class SubmissionResultResponse(BaseModel):
    id: int
    status: str
    submitted_at: datetime.datetime
    completed_at: Optional[datetime.datetime] = None
    findings: List[VulnerabilityFindingResponse] = []

    class Config:
        orm_mode = True

class SubmissionStatus(BaseModel):
    submission_id: int
    status: str
    submitted_at: datetime.datetime
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
        orm_mode = True

class LLMInteractionResponse(BaseModel):
    id: int
    agent_name: str
    timestamp: datetime.datetime
    prompt_title: Optional[str]
    status: str
    interaction_context: Optional[Dict]

    class Config:
        orm_mode = True

class DashboardStats(BaseModel):
    total_submissions: int
    pending_submissions: int
    completed_submissions: int
    total_findings: int
    high_severity_findings: int