"""Regression tests for the removal of the unused Fast LLM tier.

These tests guard the two backwards-compatibility invariants from
the threat model:

- **N3:** Legacy clients posting `fast_llm_config_id` to
  `POST /api/v1/scans` must NOT 422. FastAPI's `Form(...)` parser
  silently drops unknown form fields by default, so this should
  hold without code change. The test pins the behavior.

- **N4:** A worker `WorkerState` dict carrying a leftover
  `fast_llm_config_id` from a paused-before-deploy scan must
  resume cleanly. `WorkerState` is a `TypedDict` (no runtime key
  validation), so extra keys are silently retained — the test
  confirms downstream nodes ignore the stale key.
"""

from __future__ import annotations

import uuid
from typing import Any, Dict

import pytest

# Worker graph pulls tree_sitter via its imports; only collect when
# the worker venv is available (api container's pytest skips cleanly).
pytest.importorskip("tree_sitter_languages")

from app.infrastructure.workflows import worker_graph  # noqa: E402


def _legacy_state_with_fast_llm() -> Dict[str, Any]:
    """Build a `WorkerState`-shaped dict that includes the removed
    `fast_llm_config_id` key, simulating a checkpoint from before the
    column drop.
    """
    return {
        "scan_id": uuid.uuid4(),
        "scan_type": "AUDIT",
        "current_scan_status": None,
        "utility_llm_config_id": None,
        # Legacy key — must not crash the post-removal code:
        "fast_llm_config_id": uuid.uuid4(),
        "reasoning_llm_config_id": None,
        "files": {},
        "initial_file_map": None,
        "final_file_map": None,
        "repository_map": None,
        "dependency_graph": None,
        "all_relevant_agents": {},
        "live_codebase": None,
        "findings": [],
        "proposed_fixes": None,
        "agent_results": None,
        "error_message": None,
    }


@pytest.mark.asyncio
async def test_resume_worker_state_with_legacy_fast_llm_key():
    """N4: a node that consumes `WorkerState` must accept dicts that
    still carry the removed `fast_llm_config_id` key. We exercise
    `deterministic_prescan_node` because it's the first node a
    resumed scan re-enters and it has no DB dependency for the
    no-files case.
    """
    state = _legacy_state_with_fast_llm()
    state["files"] = {}  # empty → fast skip path, no DB / scanner I/O
    result = await worker_graph.deterministic_prescan_node(state)
    # Empty result expected (no files); the key invariant is "no raise".
    assert result == {}


def test_worker_state_typeddict_does_not_declare_fast_llm():
    """N4 (structural): the post-removal `WorkerState` must NOT have
    `fast_llm_config_id` as a declared field. TypedDict's
    `__annotations__` is the canonical introspection surface.
    """
    annotations = worker_graph.WorkerState.__annotations__
    assert "fast_llm_config_id" not in annotations
    # Sister tiers remain.
    assert "utility_llm_config_id" in annotations
    assert "reasoning_llm_config_id" in annotations


def test_create_scan_endpoint_does_not_declare_fast_llm_param():
    """N3 (structural): the `POST /api/v1/scans` Form parameter list
    must NOT include `fast_llm_config_id`. Combined with FastAPI's
    documented behavior (`Form(...)` silently ignores unknown form
    fields), this guarantees legacy clients still posting the field
    don't 422.
    """
    import inspect

    from app.api.v1.routers.projects import create_scan

    params = inspect.signature(create_scan).parameters
    assert "fast_llm_config_id" not in params, (
        "fast_llm_config_id must not be a Form param on the scan submission "
        "endpoint after this run. FastAPI Form(...) silently ignores extras, "
        "so legacy clients still posting it will succeed; the regression "
        "check is that the param is gone."
    )
    assert "utility_llm_config_id" in params
    assert "reasoning_llm_config_id" in params


def test_scan_repo_create_scan_does_not_declare_fast_llm_param():
    """N3 (structural): `ScanRepository.create_scan` must not accept
    `fast_llm_config_id`."""
    import inspect

    from app.infrastructure.database.repositories.scan_repo import ScanRepository

    params = inspect.signature(ScanRepository.create_scan).parameters
    assert "fast_llm_config_id" not in params
    assert "utility_llm_config_id" in params
    assert "reasoning_llm_config_id" in params
