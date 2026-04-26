"""Unit tests for the OSV-Scanner runner (ADR-009 / §3.6).

Covers:
- Pydantic allowlist drops extra fields from OSV output.
- Severity mapping (database_specific.severity → SCCAP enum).
- BOM truncation: hard cap at 5 MB, WARN at 2 MB.
- TimeoutExpired short-circuit returns ([], None).
"""

from __future__ import annotations

import json
import logging
import subprocess
from typing import Any
from unittest.mock import patch

import pytest


def test_severity_map_for_known_levels() -> None:
    from app.infrastructure.scanners.osv_runner import (
        _OSVVulnerability,
        _pick_severity,
    )

    high = _OSVVulnerability(database_specific={"severity": "HIGH"})
    medium = _OSVVulnerability(database_specific={"severity": "MODERATE"})
    critical = _OSVVulnerability(database_specific={"severity": "CRITICAL"})
    low = _OSVVulnerability(database_specific={"severity": "LOW"})

    assert _pick_severity(critical) == "Critical"
    assert _pick_severity(high) == "High"
    assert _pick_severity(medium) == "Medium"
    assert _pick_severity(low) == "Low"


def test_severity_unknown_falls_back_to_medium() -> None:
    from app.infrastructure.scanners.osv_runner import (
        _OSVVulnerability,
        _pick_severity,
    )

    unknown = _OSVVulnerability(database_specific={"severity": "WHATEVER"})
    assert _pick_severity(unknown) == "Medium"


def test_pydantic_allowlist_drops_extras() -> None:
    """Future OSV releases adding novel fields shouldn't leak into the
    Finding payload. The allowlist accepts only declared fields."""
    from app.infrastructure.scanners.osv_runner import _OSVVulnerability

    raw = {
        "id": "GHSA-xxxx",
        "summary": "test",
        "aliases": ["CVE-2024-1"],
        "_secret_field_added_in_some_future_osv_version": "<script>alert(1)</script>",
        "deeply": {"nested": {"junk": True}},
    }
    parsed = _OSVVulnerability.model_validate(raw)
    assert parsed.id == "GHSA-xxxx"
    assert parsed.aliases == ["CVE-2024-1"]
    # Extras silently dropped — no attribute access on the parsed object.
    assert not hasattr(parsed, "_secret_field_added_in_some_future_osv_version")


def test_truncate_bom_under_threshold_passes_through() -> None:
    from app.infrastructure.scanners.osv_runner import _truncate_bom

    small = {"bomFormat": "CycloneDX", "components": [{"name": "a"}]}
    out = _truncate_bom(small)
    assert out == small  # unchanged


def test_truncate_bom_over_hard_cap_is_truncated() -> None:
    """BOM > 5 MB gets `_truncated: true` + zeroed components."""
    from app.infrastructure.scanners.osv_runner import _truncate_bom

    huge_components = [
        {"name": f"pkg-{i}", "purl": "pkg:npm/x@1.0", "blob": "X" * 1024}
        for i in range(6000)
    ]
    bom = {"bomFormat": "CycloneDX", "components": huge_components}
    out = _truncate_bom(bom)
    assert out is not None
    assert out["_truncated"] is True
    assert out["components"] == []
    assert out["_original_size_bytes"] > 5 * 1024 * 1024


def test_truncate_bom_warn_threshold_logs(caplog: pytest.LogCaptureFixture) -> None:
    from app.infrastructure.scanners.osv_runner import _truncate_bom

    midsize = {
        "bomFormat": "CycloneDX",
        "components": [{"name": f"pkg-{i}", "blob": "Y" * 1024} for i in range(2500)],
    }
    caplog.set_level(logging.WARNING, logger="app.infrastructure.scanners.osv_runner")
    out = _truncate_bom(midsize)
    assert out is midsize  # unchanged
    assert any("WARN threshold" in rec.message for rec in caplog.records)


@pytest.mark.asyncio
async def test_run_osv_handles_timeout(tmp_path) -> None:
    """A subprocess timeout returns ([], None) and never raises."""
    from app.infrastructure.scanners.osv_runner import run_osv

    def _raise_timeout(*_a: Any, **_k: Any) -> None:
        raise subprocess.TimeoutExpired(cmd=["osv-scanner"], timeout=1)

    with patch(
        "app.infrastructure.scanners.osv_runner._run_osv_subprocess",
        side_effect=_raise_timeout,
    ):
        findings, bom = await run_osv(tmp_path, original_paths={})
    assert findings == []
    assert bom is None


@pytest.mark.asyncio
async def test_run_osv_parses_findings_and_bom(tmp_path) -> None:
    """End-to-end happy path with a stubbed subprocess: BOM file + JSON
    file land at the expected paths; runner parses both."""
    from app.infrastructure.scanners import osv_runner as mod

    bom_payload = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "components": [{"name": "pkg-a"}],
    }
    json_payload = {
        "results": [
            {
                "source": {"path": "requirements.txt"},
                "packages": [
                    {
                        "package": {
                            "name": "requests",
                            "version": "2.0.0",
                            "ecosystem": "PyPI",
                        },
                        "vulnerabilities": [
                            {
                                "id": "GHSA-xxxx-yyyy",
                                "summary": "test summary",
                                "aliases": ["CVE-2024-1"],
                                "database_specific": {"severity": "HIGH"},
                            }
                        ],
                    }
                ],
            }
        ]
    }

    def _fake_subprocess(binary, staged_dir, bom_path, json_path):
        bom_path.write_text(json.dumps(bom_payload), encoding="utf-8")
        json_path.write_text(json.dumps(json_payload), encoding="utf-8")
        return 1, "", ""  # rc=1 = vulns found, expected

    with patch(
        "app.infrastructure.scanners.osv_runner._run_osv_subprocess",
        side_effect=_fake_subprocess,
    ):
        findings, bom = await mod.run_osv(tmp_path, original_paths={})

    assert bom is not None
    assert bom["bomFormat"] == "CycloneDX"
    assert len(findings) == 1
    f = findings[0]
    assert f.source == "osv"
    assert f.cve_id == "CVE-2024-1"
    assert f.severity == "High"
    assert "requests" in f.title
    assert f.confidence == "High"
