# src/app/agents/schemas.py
from typing import Dict, List, TypedDict, Optional, Literal # Added Literal
import uuid

from pydantic import BaseModel, Field

# --- ADDED: New Type for Workflow Mode ---
WorkflowMode = Literal["audit", "remediate"]


class VulnerabilityFinding(BaseModel):
    """A standard representation of a single vulnerability."""

    cwe: str = Field(description="The CWE ID for the vulnerability (e.g., 'CWE-22').")
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
        description="A list of URLs or reference links for the vulnerability."
    )
    file_path: str


class AnalysisResult(BaseModel):
    """The structured output of a vulnerability assessment node."""

    findings: List[VulnerabilityFinding] = Field(
        description="A list of vulnerabilities found in the code."
    )


class FixSuggestion(BaseModel):
    """A standard representation of a single code fix."""

    description: str = Field(
        description="A brief description of the suggested code change."
    )
    code: str = Field(
        description="The secure code snippet to replace the vulnerable part."
    )


class FixResult(BaseModel):
    """Links a specific finding to its suggested fix for collation."""

    finding: VulnerabilityFinding = Field(
        description="The original vulnerability finding."
    )
    suggestion: FixSuggestion = Field(description="The suggested fix for the finding.")


class SpecializedAgentState(TypedDict):
    """Represents the state of any specialized agent's workflow."""

    submission_id: uuid.UUID
    llm_config_id: Optional[uuid.UUID]
    filename: str
    code_snippet: str
    
    # --- ADDED: The new field to control agent behavior ---
    workflow_mode: WorkflowMode

    # Outputs
    findings: List[VulnerabilityFinding]
    fixes: List[FixResult]
    error: Optional[str]


class LLMInteraction(BaseModel):
    """A standard representation of a single interaction with an LLM."""

    submission_id: Optional[uuid.UUID] = None
    file_path: Optional[str] = None
    agent_name: str = Field(
        description="The name of the agent that initiated the interaction."
    )
    prompt: str = Field(description="The full prompt sent to the LLM.")
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