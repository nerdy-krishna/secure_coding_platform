"""Unit tests for the §3.9 patch-verifier node.

Covers:
- No-op for non-REMEDIATE scans.
- No-op when there are no applied Semgrep findings.
- Verified vs. unverified marking based on the post-Semgrep replay.
- Failure is non-fatal — Semgrep crash leaves `fix_verified=NULL`.
"""

from __future__ import annotations

import uuid
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

# `worker_graph` (transitively pulled by the verify node) imports
# `tree_sitter_languages` via the consolidate node. Skip on the api
# container if it's not installed.
pytest.importorskip("tree_sitter_languages")

from app.core.schemas import VulnerabilityFinding  # noqa: E402

pytestmark = pytest.mark.asyncio


def _finding(
    *,
    cwe: str = "CWE-89",
    file_path: str = "app.py",
    line_number: int = 5,
    source: str = "semgrep",
    applied: bool = True,
) -> VulnerabilityFinding:
    return VulnerabilityFinding(
        cwe=cwe,
        title="SQL injection",
        description="-",
        severity="High",
        line_number=line_number,
        remediation="-",
        confidence="High",
        references=[],
        cvss_score=None,
        cvss_vector=None,
        file_path=file_path,
        fixes=None,
        source=source,
        agent_name=None,
        corroborating_agents=None,
        is_applied_in_remediation=applied,
    )


def _state(**overrides) -> dict:
    base = {
        "scan_id": uuid.uuid4(),
        "scan_type": "REMEDIATE",
        "current_scan_status": "RUNNING_AGENTS",
        "utility_llm_config_id": None,
        "reasoning_llm_config_id": None,
        "files": None,
        "initial_file_map": None,
        "final_file_map": None,
        "patched_files": {"app.py": "patched content"},
        "repository_map": None,
        "dependency_graph": None,
        "all_relevant_agents": {},
        "live_codebase": None,
        "findings": [_finding()],
        "proposed_fixes": None,
        "agent_results": None,
        "bom_cyclonedx": None,
        "prescan_approval": None,
        "error_message": None,
    }
    base.update(overrides)
    return base


async def test_verify_skipped_for_non_remediate_scan() -> None:
    from app.infrastructure.workflows.nodes.verify import verify_patches_node

    state = _state(scan_type="AUDIT")
    result = await verify_patches_node(state)
    assert result == {}


async def test_verify_skipped_when_no_patched_files() -> None:
    from app.infrastructure.workflows.nodes.verify import verify_patches_node

    state = _state(patched_files={})
    result = await verify_patches_node(state)
    assert result == {}


async def test_verify_skipped_when_no_applied_semgrep_findings() -> None:
    from app.infrastructure.workflows.nodes.verify import verify_patches_node

    # Bandit finding (different source) — verifier should leave alone.
    state = _state(findings=[_finding(source="bandit")])
    result = await verify_patches_node(state)
    assert result == {}


async def test_verify_marks_finding_verified_when_semgrep_no_longer_detects(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Original Semgrep finding for CWE-89 in app.py; replay returns
    NO finding for that CWE/file → mark as verified=True."""
    from app.infrastructure.workflows.nodes import verify as verify_mod

    state = _state(findings=[_finding(cwe="CWE-89", file_path="app.py")])

    # Stub stage_files to a no-op context manager.
    class _Ctx:
        def __enter__(self):
            return ("/tmp/staged", {})

        def __exit__(self, *_):
            return False

    monkeypatch.setattr(verify_mod, "stage_files", lambda _files: _Ctx())
    # Replay returns no findings → verified.
    monkeypatch.setattr(verify_mod, "run_semgrep", AsyncMock(return_value=[]))

    fake_repo = MagicMock()
    fake_repo.create_scan_event = AsyncMock()
    fake_session = MagicMock()
    fake_session.__aenter__ = AsyncMock(return_value=fake_session)
    fake_session.__aexit__ = AsyncMock(return_value=False)
    monkeypatch.setattr(verify_mod, "AsyncSessionLocal", lambda: fake_session)
    monkeypatch.setattr(verify_mod, "ScanRepository", lambda _db: fake_repo)

    result = await verify_patches_node_invoke(state)
    findings = result["findings"]
    assert findings[0].fix_verified is True
    fake_repo.create_scan_event.assert_awaited_once()


async def test_verify_marks_finding_unverified_when_semgrep_still_detects(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Replay still reports CWE-89 in app.py → mark as verified=False."""
    from app.infrastructure.workflows.nodes import verify as verify_mod

    state = _state(findings=[_finding(cwe="CWE-89", file_path="app.py")])

    class _Ctx:
        def __enter__(self):
            return ("/tmp/staged", {})

        def __exit__(self, *_):
            return False

    monkeypatch.setattr(verify_mod, "stage_files", lambda _files: _Ctx())
    # Replay returns a finding for the same CWE+file → unverified.
    monkeypatch.setattr(
        verify_mod,
        "run_semgrep",
        AsyncMock(return_value=[_finding(cwe="CWE-89", file_path="app.py")]),
    )

    fake_repo = MagicMock()
    fake_repo.create_scan_event = AsyncMock()
    fake_session = MagicMock()
    fake_session.__aenter__ = AsyncMock(return_value=fake_session)
    fake_session.__aexit__ = AsyncMock(return_value=False)
    monkeypatch.setattr(verify_mod, "AsyncSessionLocal", lambda: fake_session)
    monkeypatch.setattr(verify_mod, "ScanRepository", lambda _db: fake_repo)

    result = await verify_patches_node_invoke(state)
    findings = result["findings"]
    assert findings[0].fix_verified is False


async def test_verify_swallows_semgrep_replay_failure(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Subprocess crash → return empty {}; verifier failure must not
    block the scan from saving its remediation results."""
    from app.infrastructure.workflows.nodes import verify as verify_mod

    state = _state(findings=[_finding(cwe="CWE-89", file_path="app.py")])

    class _Ctx:
        def __enter__(self):
            return ("/tmp/staged", {})

        def __exit__(self, *_):
            return False

    monkeypatch.setattr(verify_mod, "stage_files", lambda _files: _Ctx())
    monkeypatch.setattr(
        verify_mod,
        "run_semgrep",
        AsyncMock(side_effect=RuntimeError("semgrep boom")),
    )

    fake_session = MagicMock()
    fake_session.__aenter__ = AsyncMock(return_value=fake_session)
    fake_session.__aexit__ = AsyncMock(return_value=False)
    monkeypatch.setattr(verify_mod, "AsyncSessionLocal", lambda: fake_session)

    result = await verify_patches_node_invoke(state)
    assert result == {}
    # Original finding's fix_verified stayed at None (no mutation).
    assert state["findings"][0].fix_verified is None


# Helper: late import + invoke. Each test imports the module so monkeypatch
# binds to the node's namespace, not a stale top-level reference.
async def verify_patches_node_invoke(state: dict) -> dict:
    from app.infrastructure.workflows.nodes.verify import verify_patches_node

    return await verify_patches_node(state)


# Silence "patch is unused" warnings — kept available for future test extension.
_ = patch
