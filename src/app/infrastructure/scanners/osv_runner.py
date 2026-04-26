"""OSV-Scanner runner — dependency CVE pre-pass + CycloneDX SBOM (ADR-009).

Mirrors `gitleaks_runner.py` shape: subprocess invocation against the
staged file tree, JSON output parsed through a Pydantic allowlist,
findings mapped to `VulnerabilityFinding` with `source="osv"`. OSV-
Scanner natively emits a CycloneDX 1.5 BOM via `--format cyclonedx-1-5`,
so cdxgen is not added as a separate dep.

Per the threat model:
- Single-binary install at `/usr/local/bin/osv-scanner` (SHA-pinned at
  build time in the worker `Dockerfile` — M8 / G1).
- BOM payload is hard-capped at 5 MB before persisting, with a
  `_truncated` / `_original_size_bytes` sentinel rewriting `components`
  to `[]`. WARN-log fires at 2 MB so operators see the cliff coming
  before they hit it. (M3 / G2.)
- Per-call timeout (180s default); on TimeoutExpired the runner
  returns ``([], None)`` and logs a WARN — never raises into the
  worker graph (matches Gitleaks/Semgrep policy N15).
- Strict Pydantic allowlist on each vulnerability row so future OSV
  schema additions cannot leak unbounded text into our BOM JSONB.
"""

from __future__ import annotations

import asyncio
import html
import json
import logging
import subprocess
import tempfile
import uuid
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from pydantic import BaseModel, ConfigDict, ValidationError

from app.core.schemas import VulnerabilityFinding
from app.infrastructure.scanners.bandit_runner import _resolve_binary

logger = logging.getLogger(__name__)

OSV_BINARY = _resolve_binary(
    "OSV_BINARY", "osv-scanner", fallback="/usr/local/bin/osv-scanner"
)
OSV_TIMEOUT_SECONDS = 180
DESCRIPTION_MAX_CHARS = 200

# BOM size policy — see threat-model G2 / M3.
BOM_HARD_CAP_BYTES = 5 * 1024 * 1024  # 5 MB
BOM_WARN_THRESHOLD_BYTES = 2 * 1024 * 1024  # 2 MB

# OSV severity strings → SCCAP severity enum. Anything we don't
# recognise drops to "Medium" so it still surfaces but doesn't
# trip the Critical-Gitleaks override modal trigger.
_SEVERITY_MAP: Dict[str, str] = {
    "CRITICAL": "Critical",
    "HIGH": "High",
    "MODERATE": "Medium",
    "MEDIUM": "Medium",
    "LOW": "Low",
}


class _OSVAffectedPackage(BaseModel):
    model_config = ConfigDict(extra="ignore")
    name: str = ""
    ecosystem: str = ""
    version: str = ""


class _OSVAffected(BaseModel):
    model_config = ConfigDict(extra="ignore")
    package: _OSVAffectedPackage = _OSVAffectedPackage()


class _OSVSeverity(BaseModel):
    model_config = ConfigDict(extra="ignore")
    type: str = ""
    score: str = ""


class _OSVVulnerability(BaseModel):
    """Strict allowlist of an OSV vulnerability row (per-package).

    Only these fields cross the boundary into a `VulnerabilityFinding`.
    Pydantic ignores extras by default; even if a future OSV release
    adds free-text fields, they're silently dropped here. Mirrors the
    `_GitleaksResult` info-disclosure boundary.
    """

    model_config = ConfigDict(extra="ignore")

    id: str = ""
    summary: str = ""
    aliases: List[str] = []
    severity: List[_OSVSeverity] = []
    affected: List[_OSVAffected] = []
    database_specific: Dict[str, Any] = {}


class _OSVPackageEntry(BaseModel):
    model_config = ConfigDict(extra="ignore")
    package: _OSVAffectedPackage = _OSVAffectedPackage()
    vulnerabilities: List[_OSVVulnerability] = []
    groups: List[Dict[str, Any]] = []


class _OSVResultsPayload(BaseModel):
    model_config = ConfigDict(extra="ignore")
    source: Dict[str, Any] = {}
    packages: List[_OSVPackageEntry] = []


class _OSVScanOutput(BaseModel):
    model_config = ConfigDict(extra="ignore")
    results: List[_OSVResultsPayload] = []


def _pick_severity(row: _OSVVulnerability) -> str:
    """Map OSV severity vector to SCCAP severity string.

    OSV emits two severity sources: the canonical `severity[].type` /
    `score` (e.g. `CVSS_V3`) and a vendor-specific
    `database_specific.severity` (often a plain enum like `HIGH`).
    Prefer the latter when present because it's the one OSV's UI shows;
    fall back to a CVSS lookup if needed; otherwise default Medium.
    """
    db_sev = row.database_specific.get("severity")
    if isinstance(db_sev, str):
        mapped = _SEVERITY_MAP.get(db_sev.strip().upper())
        if mapped:
            return mapped
    # CVSS_V3 base score → severity bucket.
    for sev in row.severity:
        score = sev.score.strip()
        if not score or "/" not in score:
            continue
        # CVSS vector format; the base score isn't extractable without
        # parsing; settle for "High" on CVSS_V3, "Medium" otherwise.
        if "CVSS:3" in score:
            return "High"
    return "Medium"


def _row_to_finding(
    row: _OSVVulnerability,
    pkg: _OSVAffectedPackage,
    source_path: str,
) -> VulnerabilityFinding:
    """Convert one OSV vulnerability row into a `VulnerabilityFinding`.

    `cve_id` prefers the first `CVE-...` alias; the title falls back
    to the OSV advisory id (`GHSA-...`, `OSV-...`) when no CVE alias
    is present. `description` is HTML-escaped + truncated to 200 chars
    matching the Gitleaks runner's defensive policy.
    """
    cve_alias = next(
        (a for a in row.aliases if a.upper().startswith("CVE-")),
        row.id,
    )
    description = html.escape(row.summary or "")[:DESCRIPTION_MAX_CHARS]
    title = f"{pkg.name}@{pkg.version}: {cve_alias}"[:200]
    severity = _pick_severity(row)
    return VulnerabilityFinding(
        cwe="CWE-1104",  # Use of Unmaintained Third-Party Components
        title=title,
        description=description,
        severity=severity,
        line_number=0,
        remediation=(
            f"Upgrade `{pkg.name}` past the affected version range. "
            f"See {row.id} for upstream guidance."
        ),
        confidence="High",
        references=[],
        cvss_score=None,
        cvss_vector=None,
        file_path=source_path,
        fixes=None,
        source="osv",
        cve_id=cve_alias if cve_alias.upper().startswith("CVE-") else None,
        agent_name=None,
        corroborating_agents=None,
        is_applied_in_remediation=False,
    )


def _truncate_bom(bom: Optional[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
    """Apply the BOM size policy.

    - Compute the serialised size.
    - If > 5 MB: replace `components` with `[]`, set `_truncated: true`
      and `_original_size_bytes`. Returns the truncated dict so the
      JSONB write succeeds.
    - If > 2 MB: WARN-log so operators see the trend.
    - Otherwise: return as-is.
    """
    if not bom:
        return bom
    try:
        encoded = json.dumps(bom).encode("utf-8")
    except (TypeError, ValueError) as e:
        logger.warning("BOM is not JSON-serialisable; dropping. err=%s", e)
        return None
    size = len(encoded)
    if size > BOM_HARD_CAP_BYTES:
        logger.warning(
            "OSV BOM size %d B exceeds %d B cap; truncating components.",
            size,
            BOM_HARD_CAP_BYTES,
        )
        bom = {
            **bom,
            "components": [],
            "_truncated": True,
            "_original_size_bytes": size,
        }
    elif size > BOM_WARN_THRESHOLD_BYTES:
        logger.warning(
            "OSV BOM size %d B exceeds %d B WARN threshold; consider trimming.",
            size,
            BOM_WARN_THRESHOLD_BYTES,
        )
    return bom


def _run_osv_subprocess(
    binary: str,
    staged_dir: Path,
    bom_path: Path,
    json_path: Path,
) -> Tuple[int, str, str]:
    """Invoke OSV-Scanner twice (CycloneDX BOM + JSON findings).

    Two invocations because OSV-Scanner v2.x emits exactly one format
    per run; the JSON output carries the vulnerability rows we need
    for `VulnerabilityFinding`s, and the CycloneDX run emits the BOM
    we persist.

    Returns the exit code, stdout, stderr of the JSON run only — the
    CycloneDX run's content lives at ``bom_path``.
    """
    bom_proc = subprocess.run(  # noqa: S603 (allowlisted binary, no shell)
        [
            binary,
            "scan",
            "source",
            "--recursive",
            "--format",
            "cyclonedx-1-5",
            "--output",
            str(bom_path),
            str(staged_dir),
        ],
        capture_output=True,
        text=True,
        timeout=OSV_TIMEOUT_SECONDS,
        check=False,
    )
    if bom_proc.returncode not in (0, 1):  # 1 = vulns found, expected
        logger.warning(
            "OSV BOM run exited with %d; stderr=%s",
            bom_proc.returncode,
            (bom_proc.stderr or "")[:500],
        )

    findings_proc = subprocess.run(  # noqa: S603
        [
            binary,
            "scan",
            "source",
            "--recursive",
            "--format",
            "json",
            "--output",
            str(json_path),
            str(staged_dir),
        ],
        capture_output=True,
        text=True,
        timeout=OSV_TIMEOUT_SECONDS,
        check=False,
    )
    return (
        findings_proc.returncode,
        findings_proc.stdout or "",
        findings_proc.stderr or "",
    )


async def run_osv(
    staged_dir: Path,
    original_paths: Dict[Path, str],
    *,
    scan_id: Optional[uuid.UUID] = None,
) -> Tuple[List[VulnerabilityFinding], Optional[Dict[str, Any]]]:
    """Run OSV-Scanner against the staged file tree.

    Returns ``(findings, bom_cyclonedx)``. `bom_cyclonedx` is ``None``
    when OSV is unavailable or returned an unparseable BOM; findings
    is the empty list on the same conditions. Either or both can be
    empty/None on a clean repo.

    The runner never raises into the worker graph: any subprocess
    failure or parse error is downgraded to a WARN log + empty result
    (matches the existing scanner-fail policy).
    """
    if not OSV_BINARY:
        logger.error(
            "scanner=osv binary not found at %s; skipping prescan",
            OSV_BINARY,
        )
        return [], None

    # `scan_id` is accepted for log correlation only; the runner does
    # not stamp it on findings (the worker graph attaches scan_id at
    # `save_findings` time).
    sid = scan_id or uuid.uuid4()
    with tempfile.TemporaryDirectory(prefix="osv-out-") as tmp:
        tmp_path = Path(tmp)
        bom_path = tmp_path / "bom.cyclonedx.json"
        json_path = tmp_path / "vulns.json"
        try:
            rc, _stdout, stderr = await asyncio.to_thread(
                _run_osv_subprocess, OSV_BINARY, staged_dir, bom_path, json_path
            )
        except subprocess.TimeoutExpired:
            logger.warning(
                "scanner=osv timed out after %ds; skipping", OSV_TIMEOUT_SECONDS
            )
            return [], None
        except Exception as e:
            logger.warning("scanner=osv subprocess error: %s", e)
            return [], None

        if rc not in (0, 1):
            logger.warning("scanner=osv exited rc=%d; stderr=%s", rc, stderr[:500])
            # Fall through and try to parse what we have anyway.

        bom: Optional[Dict[str, Any]] = None
        if bom_path.exists():
            try:
                with open(bom_path, "r", encoding="utf-8") as f:
                    bom = json.load(f)
            except (OSError, ValueError) as e:
                logger.warning("scanner=osv could not parse BOM: %s", e)
                bom = None

        findings: List[VulnerabilityFinding] = []
        if json_path.exists():
            try:
                with open(json_path, "r", encoding="utf-8") as f:
                    raw = json.load(f)
                parsed = _OSVScanOutput.model_validate(raw)
            except (OSError, ValueError, ValidationError) as e:
                logger.warning("scanner=osv could not parse findings JSON: %s", e)
                parsed = _OSVScanOutput()

            for results in parsed.results:
                source_path = (results.source or {}).get("path", "lockfile")
                # OSV nests vulns inside `packages[].vulnerabilities[]`.
                for pkg_entry in results.packages:
                    for vuln in pkg_entry.vulnerabilities:
                        try:
                            findings.append(
                                _row_to_finding(vuln, pkg_entry.package, source_path)
                            )
                        except Exception as e:
                            logger.warning(
                                "scanner=osv finding-conversion failed: %s", e
                            )
                            continue

        bom = _truncate_bom(bom)
        logger.info(
            "scanner=osv scan_id=%s findings=%d bom_present=%s",
            sid,
            len(findings),
            bom is not None,
        )
        # original_paths kwarg unused for OSV (it's a whole-tree scanner,
        # not file-routed); kept for parity with the registry signature.
        del original_paths
        return findings, bom
