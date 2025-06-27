# src/app/agents/schemas.py
from datetime import datetime, timezone
from typing import Any, Dict, List, TypedDict, Optional, Literal
import uuid

from pydantic import BaseModel, Field

WorkflowMode = Literal["audit", "remediate"]


class VulnerabilityFinding(BaseModel):
    cwe: str = Field(description="The CWE ID for the vulnerability (e.g., 'CWE-22').")
    description: str = Field(description="A detailed description of the vulnerability found.")
    severity: str = Field(description="The assessed severity (e.g., 'High', 'Medium', 'Low').")
    line_number: int = Field(description="The line number in the code where the vulnerability occurs.")
    remediation: str = Field(description="A detailed explanation of how to fix the vulnerability.")
    confidence: str = Field(description="The confidence level of the finding (e.g., 'High', 'Medium', 'Low').")
    references: List[str] = Field(default_factory=list, description="A list of URLs or reference links.")
    file_path: str


class FixSuggestion(BaseModel):
    """A standard representation of a single code fix, including the original code."""
    description: str = Field(description="A brief description of the suggested code change.")
    original_snippet: str = Field(description="The exact, original code snippet that is vulnerable and should be replaced.")
    code: str = Field(description="The secure code snippet to replace the vulnerable part.")


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
    submission_id: uuid.UUID
    llm_config_id: Optional[uuid.UUID]
    filename: str
    code_snippet: str
    workflow_mode: WorkflowMode
    findings: List[VulnerabilityFinding]
    fixes: List[FixResult]
    error: Optional[str]


class LLMInteraction(BaseModel):
    submission_id: Optional[uuid.UUID] = None
    file_path: Optional[str] = None
    agent_name: str = Field(description="The name of the agent that initiated the interaction.")
    prompt: str = Field(description="The full prompt sent to the LLM.")
    raw_response: str = Field(description="The raw text response from the LLM.")
    parsed_output: Optional[Dict] = Field(None, description="The structured output after parsing the response.")
    error: Optional[str] = Field(None, description="Any validation or parsing errors that occurred.")
    cost: Optional[float] = Field(None, description="The estimated cost of the LLM interaction.")
    input_tokens: Optional[int] = Field(None, description="Number of input tokens for the interaction.")
    output_tokens: Optional[int] = Field(None, description="Number of output tokens for the interaction.")
    total_tokens: Optional[int] = Field(None, description="Total tokens for the interaction.")
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

class ImpactReport(BaseModel):
    """
    Defines the structure of the high-level executive summary from the ImpactReportingAgent.
    """
    executive_summary: str = Field(description="A high-level overview of the project's security posture.")
    vulnerability_categories: List[str] = Field(description="A list of the main categories of vulnerabilities found.")
    estimated_remediation_effort: str = Field(description="A qualitative estimate of the effort to fix the findings (e.g., 'Low', 'Medium', 'High').")
    required_architectural_changes: List[str] = Field(description="A list of any significant architectural changes required.")

class FinalReport(BaseModel):
    """The final assembled report containing all components."""
    impact_analysis: ImpactReport
    sarif_report: Dict[str, Any]