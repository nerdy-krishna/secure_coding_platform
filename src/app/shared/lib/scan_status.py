"""Canonical Scan.status values.

Import these constants anywhere a scan status is compared or assigned. The
string values mirror what is persisted in the `scans.status` column.
"""

from typing import Final

STATUS_QUEUED: Final[str] = "QUEUED"
STATUS_PENDING_APPROVAL: Final[str] = "PENDING_COST_APPROVAL"
STATUS_QUEUED_FOR_SCAN: Final[str] = "QUEUED_FOR_SCAN"
STATUS_ANALYZING_CONTEXT: Final[str] = "ANALYZING_CONTEXT"
STATUS_RUNNING_AGENTS: Final[str] = "RUNNING_AGENTS"
STATUS_GENERATING_REPORTS: Final[str] = "GENERATING_REPORTS"
STATUS_COMPLETED: Final[str] = "COMPLETED"
STATUS_REMEDIATION_COMPLETED: Final[str] = "REMEDIATION_COMPLETED"
STATUS_FAILED: Final[str] = "FAILED"
STATUS_CANCELLED: Final[str] = "CANCELLED"
# Terminal status set by `blocked_pre_llm_node` when the deterministic
# SAST pre-pass finds a Critical secret (Gitleaks). The scan ends
# before any LLM call is made — saves cost and prevents the secret
# from being forwarded to the model provider.
STATUS_BLOCKED_PRE_LLM: Final[str] = "BLOCKED_PRE_LLM"

# Scan statuses that represent a scan still moving toward completion.
ACTIVE_SCAN_STATUSES: Final[tuple[str, ...]] = (
    STATUS_QUEUED,
    STATUS_PENDING_APPROVAL,
    STATUS_QUEUED_FOR_SCAN,
    STATUS_ANALYZING_CONTEXT,
    STATUS_RUNNING_AGENTS,
    STATUS_GENERATING_REPORTS,
)

# Scan statuses that represent a terminal success state.
COMPLETED_SCAN_STATUSES: Final[tuple[str, ...]] = (
    STATUS_COMPLETED,
    STATUS_REMEDIATION_COMPLETED,
)
