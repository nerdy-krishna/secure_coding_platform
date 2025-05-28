# src/app/api/models.py
from pydantic import BaseModel, Field, model_validator, ConfigDict
from typing import List, Optional, Dict, Any
import datetime  # For datetime fields


class CodeFile(BaseModel):
    """Represents a single file with content."""

    filename: str = Field(
        ...,
        description="Filename including extension (e.g., 'main.py', 'utils/helper.java')",
    )
    content: str = Field(..., description="The actual source code content of the file.")


class CodeInput(BaseModel):
    """
    Model for receiving code input.
    Accepts either a single code snippet or a list of files.
    """

    code: Optional[str] = Field(None, description="A single source code snippet.")
    language: Optional[str] = Field(
        None,
        description="The primary programming language of the 'code' snippet or project.",
    )
    files: Optional[List[CodeFile]] = Field(
        None, description="A list of files representing the codebase or relevant parts."
    )
    # Optional: Add selected_frameworks for the submission, if it's part of the initial API call
    selected_frameworks: Optional[List[str]] = Field(
        None,
        description="List of security framework IDs/names to analyze against (e.g., ['owasp_asvs', 'pci_dss']).",
    )

    @model_validator(mode="before")  # Pydantic v2 syntax for root_validator
    @classmethod
    def check_code_or_files(cls, values: Dict[str, Any]) -> Dict[str, Any]:
        code, files = values.get("code"), values.get("files")
        language = values.get("language")
        if code is not None and files is not None:
            raise ValueError(
                "Provide either 'code' (with 'language') or 'files', not both."
            )
        if code is None and files is None:
            raise ValueError("Provide either 'code' (with 'language') or 'files'.")
        if code is not None and language is None:
            raise ValueError("'language' must be provided if 'code' is specified.")
        return values

    # Pydantic v2 uses model_config as a dictionary or ConfigDict
    model_config = ConfigDict(
        json_schema_extra={
            "examples": [
                {
                    "summary": "Single Python Snippet",
                    "value": {
                        "code": "def hello():\\n  print('Hello, world!')",
                        "language": "python",
                        "selected_frameworks": ["owasp_asvs_v5.0"],
                    },
                },
                {
                    "summary": "Multiple Files",
                    "value": {
                        "files": [
                            {
                                "filename": "main.py",
                                "content": "import util\\nprint(util.greet())",
                            },
                            {
                                "filename": "util.py",
                                "content": "def greet():\\n  return 'Hello from util'",
                            },
                        ],
                        "language": "python",  # Optional if languages can be inferred per file
                        "selected_frameworks": ["pci_dss_v4.0", "hipaa"],
                    },
                },
            ]
        }
    )


class AnalysisResultResponse(BaseModel):
    """Pydantic model for returning AnalysisResult data."""

    id: int
    submission_id: int
    report_content: Optional[Dict[str, Any]] = None  # Assuming it's JSON-compatible
    # original_code_snapshot and fixed_code_snapshot are stored as JSON strings in DB (maps of filename:content)
    # For the response, we might want to parse them back to Dicts or keep as strings.
    # Pydantic will try to convert if the type hint is Dict. If they are indeed JSON strings,
    # the type hint here should perhaps be Optional[str] or use a validator to parse.
    # Let's assume for now they will be parsed to Dict by the time they reach here or are fine as Any.
    original_code_snapshot: Optional[Dict[str, Any]] = None
    fixed_code_snapshot: Optional[Dict[str, Any]] = None
    sarif_report: Optional[Dict[str, Any]] = None
    completed_at: datetime.datetime
    status: Optional[str] = None
    error_message: Optional[str] = None

    model_config = ConfigDict(from_attributes=True)  # For ORM mode in Pydantic v2


# --- Schemas for Submission History (from collated_code.txt) ---
class SubmissionHistoryItem(BaseModel):
    """Schema for a single item in the user's submission history."""

    id: int
    primary_language: Optional[str] = None
    submitted_at: datetime.datetime
    status: Optional[str] = "Processing"
    selected_frameworks: Optional[List[str]] = None  # Added from DB model

    model_config = ConfigDict(from_attributes=True)


class SubmissionHistoryResponse(BaseModel):
    """Response schema for a list of submission history items."""

    submissions: List[SubmissionHistoryItem]
    total: int


# --- Schemas for LLM Metrics (from collated_code.txt) ---
class LLMAgentPerformanceMetrics(BaseModel):
    agent_name: str
    total_calls: int
    successful_calls: int
    failed_calls: int
    success_rate: float
    average_latency_ms: Optional[float] = None
    average_input_tokens: Optional[float] = None
    average_output_tokens: Optional[float] = None
    average_total_tokens: Optional[float] = None
    total_estimated_cost: Optional[float] = None
    average_estimated_cost_per_call: Optional[float] = None


class LLMOverallSummaryMetrics(BaseModel):
    total_interactions_logged: int
    total_successful_calls: int
    total_failed_calls: int
    overall_success_rate: float
    overall_average_latency_ms: Optional[float] = None
    total_estimated_cost_all_calls: Optional[float] = None


class LLMAgentsMetricsResponse(BaseModel):
    metrics: List[LLMAgentPerformanceMetrics]
