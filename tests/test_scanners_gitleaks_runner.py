"""Unit tests for the Gitleaks subprocess wrapper.

Mocks subprocess invocation; the runtime binary is verified separately
via `docker compose build worker`. These tests focus on the
information-disclosure boundary: the strict Pydantic allowlist must
drop any future Gitleaks field that could leak the matched secret
(`Match`, `Secret`, `Fingerprint`, `Commit`, `Author`, `Email`).
"""

from __future__ import annotations

import json
import logging
import subprocess
from pathlib import Path

import pytest

from app.infrastructure.scanners import gitleaks_runner
from app.infrastructure.scanners.gitleaks_runner import (
    DESCRIPTION_MAX_CHARS,
    GITLEAKS_TIMEOUT_SECONDS,
    _GitleaksResult,
    run_gitleaks,
)


pytestmark = pytest.mark.asyncio


def _fake_completed(stdout: str, returncode: int = 0) -> subprocess.CompletedProcess:
    return subprocess.CompletedProcess(
        args=["gitleaks"], returncode=returncode, stdout=stdout, stderr=""
    )


async def test_gitleaks_finds_secret_and_emits_critical_severity(monkeypatch):
    payload = json.dumps(
        [
            {
                "RuleID": "aws-access-token",
                "File": "/tmp/staged/config.py",
                "StartLine": 12,
                "Description": "AWS Access Key",
            }
        ]
    )
    monkeypatch.setattr(
        gitleaks_runner, "_invoke_gitleaks_sync", lambda _d: _fake_completed(payload)
    )
    findings = await run_gitleaks(
        Path("/tmp/staged"),
        original_paths={Path("/tmp/staged/config.py"): "config.py"},
    )
    assert len(findings) == 1
    f = findings[0]
    assert f.source == "gitleaks"
    assert (
        f.severity == "Critical"
    ), "all gitleaks findings emit Critical for short-circuit"
    assert f.confidence == "High"
    assert f.cwe == "CWE-798"
    assert f.file_path == "config.py"
    assert f.line_number == 12
    # Hard-coded null-out of metadata channels (N1).
    assert f.cvss_score is None
    assert f.cvss_vector is None
    assert f.references == []


async def test_gitleaks_returns_empty_for_no_findings(monkeypatch):
    monkeypatch.setattr(
        gitleaks_runner, "_invoke_gitleaks_sync", lambda _d: _fake_completed("[]")
    )
    assert await run_gitleaks(Path("/tmp/staged"), original_paths={}) == []


async def test_gitleaks_allowlist_drops_match_and_secret_and_fingerprint():
    """The Pydantic model must IGNORE (not propagate) any field that
    could leak the raw secret value, even if Gitleaks adds new fields
    in a future release.
    """
    raw = {
        "RuleID": "stripe-api-key",
        "File": "/tmp/staged/billing.py",
        "StartLine": 7,
        "Description": "Stripe API Key",
        # All of the following MUST NOT cross the boundary:
        "Match": "sk_live_REDACTED_BUT_PRETEND_REAL",
        "Secret": "sk_live_REAL_SECRET_VALUE",
        "Fingerprint": "abc123:billing.py:stripe-api-key:7",
        "Commit": "deadbeef",
        "Author": "victim@example.com",
        "Email": "victim@example.com",
    }
    parsed = _GitleaksResult.model_validate(raw)
    # Only the allowlisted fields exist on the parsed model.
    dumped = parsed.model_dump()
    assert set(dumped.keys()) == {"RuleID", "File", "StartLine", "Description"}
    for forbidden in ("Match", "Secret", "Fingerprint", "Commit", "Author", "Email"):
        assert forbidden not in dumped


async def test_gitleaks_stdout_never_logged_above_debug(monkeypatch, caplog):
    """Log discipline: stdout (which carries scanner output) is logged
    only at DEBUG; INFO carries `(rc, duration_ms, stdout_bytes)` only.
    """
    sentinel = "GITLEAKS_RAW_PAYLOAD_DO_NOT_LOG"
    payload = json.dumps(
        [{"RuleID": sentinel, "File": "/x.py", "StartLine": 1, "Description": "x"}]
    )
    monkeypatch.setattr(
        gitleaks_runner, "_invoke_gitleaks_sync", lambda _d: _fake_completed(payload)
    )
    with caplog.at_level(
        logging.INFO, logger="app.infrastructure.scanners.gitleaks_runner"
    ):
        await run_gitleaks(Path("/tmp/staged"), original_paths={})
    info_messages = "\n".join(
        r.getMessage() for r in caplog.records if r.levelno >= logging.INFO
    )
    assert (
        sentinel not in info_messages
    ), "raw stdout must not appear in INFO/WARNING logs"


async def test_gitleaks_description_is_html_escaped_and_truncated(monkeypatch):
    long_msg = "<img src=x onerror=alert(1)> " + ("z" * 500)
    payload = json.dumps(
        [{"RuleID": "test", "File": "/x.py", "StartLine": 1, "Description": long_msg}]
    )
    monkeypatch.setattr(
        gitleaks_runner, "_invoke_gitleaks_sync", lambda _d: _fake_completed(payload)
    )
    findings = await run_gitleaks(Path("/tmp/staged"), original_paths={})
    assert len(findings) == 1
    assert len(findings[0].description) <= DESCRIPTION_MAX_CHARS
    assert "<img" not in findings[0].description
    assert "&lt;img" in findings[0].description


async def test_gitleaks_timeout_returns_low_not_critical(monkeypatch, caplog):
    """A timeout is NOT a confirmed secret leak — must NOT trigger
    the BLOCKED_PRE_LLM short-circuit. Hence Low severity.
    """

    def _raise(_d):
        raise subprocess.TimeoutExpired(
            cmd="gitleaks", timeout=GITLEAKS_TIMEOUT_SECONDS
        )

    monkeypatch.setattr(gitleaks_runner, "_invoke_gitleaks_sync", _raise)
    findings = await run_gitleaks(Path("/tmp/staged"), original_paths={})
    assert len(findings) == 1
    assert findings[0].severity == "Low"
    assert findings[0].source == "gitleaks"


async def test_gitleaks_binary_missing_returns_empty(monkeypatch):
    def _raise(_d):
        raise FileNotFoundError("gitleaks not installed")

    monkeypatch.setattr(gitleaks_runner, "_invoke_gitleaks_sync", _raise)
    assert await run_gitleaks(Path("/tmp/staged"), original_paths={}) == []
