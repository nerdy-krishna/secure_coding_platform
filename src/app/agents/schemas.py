# src/app/agents/schemas.py
from typing import List, TypedDict, Optional

from pydantic import BaseModel, Field

class VulnerabilityFinding(BaseModel):
    """A standard representation of a single vulnerability."""
    cwe: str = Field(description="The CWE ID for the vulnerability (e.g., 'CWE-22').")
    description: str = Field(description="A detailed description of the vulnerability found.")
    severity: str = Field(description="The assessed severity (e.g., 'High', 'Medium', 'Low').")
    line_number: int = Field(description="The line number in the code where the vulnerability occurs.")
    remediation: str = Field(description="A detailed explanation of how to fix the vulnerability.")
    confidence: str = Field(description="The confidence level of the finding (e.g., 'High', 'Medium', 'Low').")
    references: List[str] = Field(description="A list of URLs or reference links for the vulnerability.")
    file_path: str  # This will be added programmatically by the agent

class AnalysisResult(BaseModel):
    """The structured output of a vulnerability assessment node."""
    findings: List[VulnerabilityFinding] = Field(description="A list of vulnerabilities found in the code.")

class FixSuggestion(BaseModel):
    """A standard representation of a single code fix."""
    description: str = Field(description="A brief description of the suggested code change.")
    code: str = Field(description="The secure code snippet to replace the vulnerable part.")

class FixResult(BaseModel):
    """Links a specific finding to its suggested fix for collation."""
    finding: VulnerabilityFinding = Field(description="The original vulnerability finding.")
    suggestion: FixSuggestion = Field(description="The suggested fix for the finding.")

class SpecializedAgentState(TypedDict):
    """Represents the state of any specialized agent's workflow."""
    submission_id: int
    filename: str
    code_snippet: str
    findings: List[VulnerabilityFinding]
    fixes: List[FixResult]
    error: Optional[str]