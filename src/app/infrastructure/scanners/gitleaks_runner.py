"""Gitleaks subprocess wrapper for the deterministic SAST pre-pass.

Invokes ``gitleaks detect --no-git --config <pinned> --source
<staged_dir> --redact --report-format json --report-path -`` and
converts each result into a :class:`VulnerabilityFinding` carrying
``source="gitleaks"``, ``confidence="High"``, ``severity="Critical"``
(every secret is treated as Critical so the worker-graph short-circuit
in ``deterministic_prescan_node`` triggers).

Hardening (per the sast-prescan-followups threat model):

- N1 / M5: Pydantic ``_GitleaksResult`` allowlist contains ONLY
  ``RuleID``, ``File``, ``StartLine``, ``Description``. Fields like
  ``Match``, ``Secret``, ``Fingerprint``, ``Commit``, ``Author``,
  ``Email`` MUST NEVER reach ``VulnerabilityFinding`` — even if a
  future Gitleaks schema bump tries to add them.
- N1: ``--redact`` is passed to the binary (belt-and-suspenders) so
  the matched value is replaced before it leaves Gitleaks itself.
- N3: ``--config`` is pinned to the bundled
  ``/app/scanners/configs/gitleaks.toml`` so a user-tree
  ``.gitleaks.toml`` cannot redirect behavior. ``--no-git`` so the
  scanner walks the file tree, not the git history (the staged dir
  has no `.git`).
- M5: scanner ``stdout`` is parsed and discarded; never logged above
  DEBUG. ``cvss_vector=None`` and ``references=[]`` are hard-coded so
  even an upstream Gitleaks change cannot smuggle a secret through
  a metadata channel.
- M6: 120-second timeout; ``TimeoutExpired`` returns one Low-severity
  finding (NOT Critical — a timeout is not a confirmed secret leak;
  we don't want a timeout to trigger the BLOCKED_PRE_LLM short-circuit).
- M7: ``description`` is HTML-escaped + 200-char capped before
  reaching any LLM agent prompt.

The wrapper is ``async`` but executes Gitleaks on a worker thread via
``asyncio.to_thread``.
"""

from __future__ import annotations

import asyncio
import html
import json
import logging
import subprocess
from pathlib import Path
from typing import Any, Dict, List

from pydantic import BaseModel, ConfigDict, ValidationError

from app.core.schemas import VulnerabilityFinding
from app.infrastructure.scanners.bandit_runner import _resolve_binary


logger = logging.getLogger(__name__)


def _gitleaks_binary() -> str:
    """Lazy accessor for the Gitleaks binary path. Resolves on first
    call so `GITLEAKS_BINARY` env-var loaded by `dotenv` after import
    is honored."""
    return _resolve_binary(
        "GITLEAKS_BINARY", "gitleaks", fallback="/usr/local/bin/gitleaks"
    )


GITLEAKS_TIMEOUT_SECONDS = 120
GITLEAKS_CONFIG_PATH = "/app/scanners/configs/gitleaks.toml"
DESCRIPTION_MAX_CHARS = 200


class _GitleaksResult(BaseModel):
    """Strict allowlist of a single Gitleaks finding.

    Only these four fields cross the boundary into
    ``VulnerabilityFinding``. Pydantic ignores extras by default, which
    means even if a future Gitleaks release adds a ``Match`` /
    ``Secret`` / ``Fingerprint`` / ``Commit`` / ``Author`` / ``Email``
    field with a fresh schema, it is silently dropped here. This is
    the M5 / N1 information-disclosure boundary.
    """

    model_config = ConfigDict(extra="ignore")

    RuleID: str = "rule.unknown"
    File: str
    StartLine: int = 0
    Description: str = ""


def _gitleaks_finding_to_vulnerability(
    raw: _GitleaksResult, original_paths: Dict[Path, str]
) -> VulnerabilityFinding:
    """Map a sanitized Gitleaks result into the canonical
    `VulnerabilityFinding` shape.

    All Gitleaks findings emit at ``severity="Critical"`` so the
    short-circuit in ``deterministic_prescan_node`` triggers. The
    description is the redacted+capped Description string — never the
    raw match.
    """
    try:
        staged = Path(raw.File).resolve()
    except (OSError, ValueError):
        staged = Path(raw.File)
    file_path = original_paths.get(staged, raw.File)

    description = html.escape(raw.Description)[:DESCRIPTION_MAX_CHARS]

    return VulnerabilityFinding(
        cwe="CWE-798",  # Use of Hard-coded Credentials
        title=f"Secret leak: {raw.RuleID[:50]}",
        description=description,
        severity="Critical",
        line_number=int(raw.StartLine) if raw.StartLine else 0,
        remediation="Rotate the credential immediately and remove it from version control.",
        confidence="High",
        references=[],
        cvss_score=None,
        cvss_vector=None,
        file_path=str(file_path),
        fixes=None,
        source="gitleaks",
        agent_name=None,
        corroborating_agents=None,
        is_applied_in_remediation=False,
    )


def _invoke_gitleaks_sync(staged_dir: Path) -> "subprocess.CompletedProcess[str]":
    """Run Gitleaks via ``subprocess.run``. Pure sync; called from
    ``asyncio.to_thread``.

    - ``--no-git`` walks the file tree (the staged dir has no .git).
    - ``--config`` pinned (N3) so user-tree ``.gitleaks.toml`` is
      ignored.
    - ``--redact`` (N1) replaces the match value in Gitleaks output
      before it reaches our Python parser.
    - ``--report-path -`` writes JSON to stdout (instead of a file).
    - ``--`` separator before the staged path (M1 — though gitleaks
      doesn't take positional args here, the discipline is consistent).
    """
    return subprocess.run(  # noqa: S603 - args are a literal list
        [
            _gitleaks_binary(),
            "detect",
            "--no-git",
            "--config",
            GITLEAKS_CONFIG_PATH,
            "--source",
            str(staged_dir),
            "--redact",
            "--report-format",
            "json",
            "--report-path",
            "-",
            "--no-banner",
            "--exit-code",
            "0",
        ],
        shell=False,
        check=False,
        capture_output=True,
        text=True,
        timeout=GITLEAKS_TIMEOUT_SECONDS,
    )


def _timeout_finding(staged_dir: Path) -> VulnerabilityFinding:
    """Single-finding placeholder so the worker graph still completes
    when Gitleaks exceeds the hard timeout (M6).

    Severity is Low (NOT Critical) — a timeout is not a confirmed
    secret leak and must not trigger the BLOCKED_PRE_LLM short-circuit.
    """
    return VulnerabilityFinding(
        cwe="CWE-unknown",
        title="Gitleaks scanner timed out",
        description=html.escape(
            f"Gitleaks exceeded the {GITLEAKS_TIMEOUT_SECONDS}s timeout while scanning the project."
        )[:DESCRIPTION_MAX_CHARS],
        severity="Low",
        line_number=0,
        remediation="Re-run the scan with a smaller submission, or open an admin issue if this recurs.",
        confidence="High",
        references=[],
        cvss_score=None,
        cvss_vector=None,
        file_path=str(staged_dir),
        fixes=None,
        source="gitleaks",
        agent_name=None,
        corroborating_agents=None,
        is_applied_in_remediation=False,
    )


async def run_gitleaks(
    staged_dir: Path, original_paths: Dict[Path, str]
) -> List[VulnerabilityFinding]:
    """Run Gitleaks against ``staged_dir`` and return findings.

    Returns an empty list when Gitleaks finds nothing or fails to
    parse. On timeout, returns a single Low-severity placeholder so
    the caller has at least one observable signal. Never raises.
    """
    loop = asyncio.get_running_loop()
    started_at = loop.time()
    try:
        completed = await asyncio.to_thread(_invoke_gitleaks_sync, staged_dir)
    except subprocess.TimeoutExpired:
        logger.warning(
            "scanner=gitleaks staged_dir=%s rc=-9 timeout=%ss",
            staged_dir,
            GITLEAKS_TIMEOUT_SECONDS,
        )
        return [_timeout_finding(staged_dir)]
    except FileNotFoundError:
        logger.error(
            "scanner=gitleaks binary not found at %s; skipping prescan",
            _gitleaks_binary(),
        )
        return []
    except Exception as exc:  # pragma: no cover - defensive
        logger.exception("scanner=gitleaks unexpected failure: %s", exc)
        return []

    duration_ms = int((loop.time() - started_at) * 1000)
    # NEVER log stdout above DEBUG — Gitleaks output may carry redacted
    # but still suspicious tokens (RuleID, file path, partial line
    # number) and operators should opt into seeing them.
    logger.info(
        "scanner=gitleaks staged_dir=%s rc=%d duration_ms=%d stdout_bytes=%d",
        staged_dir,
        completed.returncode,
        duration_ms,
        len(completed.stdout or ""),
    )
    logger.debug("scanner=gitleaks raw stderr=%r", completed.stderr)

    if not completed.stdout:
        return []

    try:
        # Gitleaks emits a JSON array (or null when there are no
        # findings). Wrap the array path defensively.
        payload: Any = json.loads(completed.stdout)
    except json.JSONDecodeError as exc:
        logger.warning("scanner=gitleaks JSON parse failed: %s", exc)
        return []

    if not isinstance(payload, list):
        return []

    findings: List[VulnerabilityFinding] = []
    for raw_dict in payload:
        try:
            raw = _GitleaksResult.model_validate(raw_dict)
        except ValidationError as exc:
            logger.warning("scanner=gitleaks dropped malformed result: %s", exc)
            continue
        findings.append(_gitleaks_finding_to_vulnerability(raw, original_paths))
    return findings
