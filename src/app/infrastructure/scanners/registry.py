"""Per-file scanner routing.

Mirrors the extension-based routing used by the LLM agents (see
`shared/lib/agent_routing.resolve_agents_for_file`). Today only Bandit
is wired up (Python-only). Semgrep and Gitleaks slots are reserved for
follow-up runs.
"""

from __future__ import annotations

from pathlib import PurePosixPath
from typing import List


_PYTHON_EXTENSIONS = {".py", ".pyi"}


def scanners_for_file(rel_path: str) -> List[str]:
    """Return the list of scanner names applicable to ``rel_path``.

    Scanners run per-file; the registry stays open for future additions
    (e.g. ``"semgrep"`` for most languages, ``"gitleaks"`` for any text
    file).
    """
    suffix = PurePosixPath(rel_path).suffix.lower()
    scanners: List[str] = []
    if suffix in _PYTHON_EXTENSIONS:
        scanners.append("bandit")
    return scanners
