# src/app/core/schemas.py
from datetime import datetime, timezone
from typing import Any, Dict, List, TypedDict, Optional, Literal
import uuid

from pydantic import BaseModel, Field

WorkflowMode = Literal["audit", "suggest", "remediate"]


class CodeChunk(TypedDict):
    symbol_name: str
    code: str
    start_line: int
    end_line: int


class FixSuggestion(BaseModel):
    """A standard representation of a single code fix, including the original code."""

    description: str = Field(
        description="A brief description of the suggested code change."
    )
    original_snippet: str = Field(
        description="The exact, original code snippet that is vulnerable and should be replaced."
    )
    code: str = Field(
        description="The secure code snippet to replace the vulnerable part."
    )

class VulnerabilityFinding(BaseModel):
    cwe: str = Field(description="The CWE ID for the vulnerability (e.g., 'CWE-22').")
    title: str = Field(description="A concise, one-line title for the vulnerability.")
    description: str = Field(
        description="A detailed description of the vulnerability found."
    )
    severity: str = Field(
        description="The assessed severity (e.g., 'High', 'Medium', 'Low')."
    )
    line_number: int = Field(
        description="The line number in the code where the vulnerability occurs."
    )
    remediation: str = Field(
        description="A detailed explanation of how to fix the vulnerability."
    )
    confidence: str = Field(
        description="The confidence level of the finding (e.g., 'High', 'Medium', 'Low')."
    )
    references: List[str] = Field(
        default_factory=list, description="A list of URLs or reference links."
    )
    cvss_score: Optional[float] = Field(None, description="The calculated CVSS 3.1 score.")
    cvss_vector: Optional[str] = Field(None, description="The CVSS 3.1 vector string.")
    file_path: str
    fixes: Optional[FixSuggestion] = Field(
        default=None, description="The suggested code fix, including original and new snippets."
    )
    agent_name: Optional[str] = Field(
        default=None, description="The name of the agent that generated the finding."
    )


class FixResult(BaseModel):
    """Links a specific finding to its suggested fix for collation."""

    finding: VulnerabilityFinding
    suggestion: FixSuggestion


# --- ADDED: New model for a combined finding-and-fix result from a single LLM call ---
class RemediationResult(BaseModel):
    """Represents a single, self-contained vulnerability finding and its corresponding fix."""

    finding: VulnerabilityFinding
    suggestion: FixSuggestion


class AnalysisResult(BaseModel):
    """The structured output of an agent run."""

    # In audit mode, this contains findings.
    # In remediate mode, this contains full remediation results.
    findings: List[VulnerabilityFinding] = Field(default_factory=list)
    remediations: List[RemediationResult] = Field(default_factory=list)


class SpecializedAgentState(TypedDict):
    """Represents the state of any specialized agent's workflow."""

    scan_id: uuid.UUID
    llm_config_id: Optional[uuid.UUID]
    filename: str
    code_snippet: str
    workflow_mode: str
    file_content_for_verification: Optional[str]
    findings: List[VulnerabilityFinding]
    fixes: List[FixResult]
    error: Optional[str]



class LLMInteraction(BaseModel):
    scan_id: Optional[uuid.UUID] = None
    file_path: Optional[str] = None
    agent_name: str = Field(
        description="The name of the agent that initiated the interaction."
    )
    prompt_template_name: Optional[str] = Field(None, description="The name of the prompt template used.")
    prompt_context: Optional[Dict[str, Any]] = Field(None, description="The context data used to format the prompt.")
    raw_response: str = Field(description="The raw text response from the LLM.")
    parsed_output: Optional[Dict] = Field(
        None, description="The structured output after parsing the response."
    )
    error: Optional[str] = Field(
        None, description="Any validation or parsing errors that occurred."
    )
    cost: Optional[float] = Field(
        None, description="The estimated cost of the LLM interaction."
    )
    input_tokens: Optional[int] = Field(
        None, description="Number of input tokens for the interaction."
    )
    output_tokens: Optional[int] = Field(
        None, description="Number of output tokens for the interaction."
    )
    total_tokens: Optional[int] = Field(
        None, description="Total tokens for the interaction."
    )
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class ImpactReport(BaseModel):
    """
    Defines the structure of the high-level executive summary from the ImpactReportingAgent.
    """

    executive_summary: str = Field(
        description="A high-level overview of the project's security posture, written for a business audience."
    )
    vulnerability_overview: str = Field(
        description="A paragraph summarizing the types and distribution of vulnerabilities found."
    )
    high_risk_findings_summary: List[str] = Field(
        description="A bulleted list summarizing the most critical or high-risk findings."
    )
    remediation_strategy: str = Field(
        description="A paragraph outlining a strategic approach to remediation, such as which categories to prioritize."
    )
    # The fields below are kept for backward compatibility but the prompt will focus on the new ones
    vulnerability_categories: List[str] = Field(
        description="A list of the main categories of vulnerabilities found."
    )
    estimated_remediation_effort: str = Field(
        description="A qualitative estimate of the effort to fix the findings (e.g., 'Low', 'Medium', 'High')."
    )
    required_architectural_changes: List[str] = Field(
        description="A list of any significant architectural changes required."
    )


class FinalReport(BaseModel):
    """The final assembled report containing all components."""

    impact_analysis: ImpactReport
    sarif_report: Dict[str, Any]


class EnrichedDocument(BaseModel):
    """Represents a single document/control after LLM enrichment."""

    id: str
    original_document: str
    enriched_content: str
    metadata: Dict[str, Any]


class PreprocessingResponse(BaseModel):
    """The API response after a framework CSV has been processed."""

    framework_name: str
    llm_config_name: str
    processed_documents: List[EnrichedDocument]

class RAGJobStartResponse(BaseModel):
    """Response when starting a new RAG preprocessing job."""

    job_id: uuid.UUID
    framework_name: str
    status: str
    estimated_cost: Optional[Dict[str, Any]] = None
    message: str


class RAGJobStatusResponse(BaseModel):
    """Response for a job status check."""

    job_id: uuid.UUID
    framework_name: str
    status: str
    estimated_cost: Optional[Dict[str, Any]] = None
    actual_cost: Optional[float] = None
    processed_documents: Optional[List[EnrichedDocument]] = None
    error_message: Optional[str] = None