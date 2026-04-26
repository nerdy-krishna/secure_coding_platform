"""Per-file scanner routing + minified-bundle detection.

Mirrors the extension-based routing used by the LLM agents (see
`shared/lib/agent_routing.resolve_agents_for_file`). Bandit is
Python-only; Semgrep covers the multi-language subset its
`p/security-audit` rule pack flags; Gitleaks scans any text-shaped
file for secret patterns.

Minified bundles (`*.min.js`, `*.bundle.js`, `*.min.css`) carry a
lower per-file byte cap to dodge Semgrep's documented multi-minute
parse pathology on large minified inputs.
"""

from __future__ import annotations

from pathlib import PurePosixPath
from typing import List


_PYTHON_EXTENSIONS = {".py", ".pyi"}

# Languages Semgrep's `p/security-audit` rule pack covers in the
# version we ship. Adding extensions here is fine — Semgrep silently
# skips files for which it has no rules.
_SEMGREP_EXTENSIONS = {
    ".py",
    ".pyi",
    ".js",
    ".jsx",
    ".ts",
    ".tsx",
    ".java",
    ".go",
    ".rb",
    ".php",
    ".cs",
    ".c",
    ".cpp",
    ".cc",
    ".h",
    ".hpp",
}

# Files Gitleaks scans for secrets. Source code + common config /
# documentation that has historically leaked credentials.
_GITLEAKS_EXTENSIONS = _SEMGREP_EXTENSIONS | {
    ".env",
    ".yml",
    ".yaml",
    ".json",
    ".toml",
    ".ini",
    ".cfg",
    ".conf",
    ".sh",
    ".md",
    ".txt",
    ".properties",
}

# Per-file size cap (bytes) for minified bundles — Semgrep on a 5 MB
# minified JS file is the most likely real-world timeout trigger.
MINIFIED_BYTE_LIMIT = 256 * 1024

_MINIFIED_SUFFIXES = (".min.js", ".bundle.js", ".min.css")


def is_minified(rel_path: str) -> bool:
    """Heuristic: does the path look like a minified web bundle?

    Used by `deterministic_prescan_node` to apply the lower
    `MINIFIED_BYTE_LIMIT` instead of the general 1 MiB cap.
    """
    lowered = rel_path.lower()
    return any(lowered.endswith(suffix) for suffix in _MINIFIED_SUFFIXES)


def scanners_for_file(rel_path: str) -> List[str]:
    """Return the list of scanner names applicable to ``rel_path``.

    Scanners run per-file (or per-tree, scanner's choice — Bandit and
    Semgrep walk the staged dir themselves; Gitleaks too); the
    registry just decides which scanners are *eligible* for a given
    file extension.
    """
    suffix = PurePosixPath(rel_path).suffix.lower()
    scanners: List[str] = []
    if suffix in _PYTHON_EXTENSIONS:
        scanners.append("bandit")
    if suffix in _SEMGREP_EXTENSIONS:
        scanners.append("semgrep")
    if suffix in _GITLEAKS_EXTENSIONS:
        scanners.append("gitleaks")
    return scanners
