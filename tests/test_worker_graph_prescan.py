"""Focused unit tests for ``deterministic_prescan_node``.

A full end-to-end LangGraph compile-and-run is out of scope for a Low-risk
single-PR slice (would require seeding a Scan + ORIGINAL_SUBMISSION
snapshot in the test DB, plus driving the AsyncPostgresSaver through
the cost-approval interrupt). These tests instead exercise the node
in isolation and rely on:

- The graph wiring being verified at code-review / manual-smoke time.
- The node never calling ``interrupt()`` (asserted structurally below).
- Persistence happening at ``save_results_node`` (single save site;
  unchanged by this PR).
"""

from __future__ import annotations

import uuid
from typing import Any, Dict

import pytest

# `worker_graph` pulls in `tree_sitter_languages`, which only ships in
# the worker container's venv. The API-container test environment used
# by `docker compose exec app pytest` lacks it, so collection fails
# unless we skip-mark the whole module up front.
pytest.importorskip("tree_sitter_languages")

from app.core.schemas import VulnerabilityFinding  # noqa: E402
from app.infrastructure.workflows import worker_graph  # noqa: E402


pytestmark = pytest.mark.asyncio


def _state(**overrides: Any) -> Dict[str, Any]:
    base: Dict[str, Any] = {
        "scan_id": uuid.uuid4(),
        "scan_type": "AUDIT",
        "current_scan_status": "RUNNING_AGENTS",
        "utility_llm_config_id": None,
        "fast_llm_config_id": None,
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
    base.update(overrides)
    return base


async def test_prescan_returns_empty_when_no_files():
    state = _state(files={})
    result = await worker_graph.deterministic_prescan_node(state)
    assert result == {}


async def test_prescan_skips_non_python_files():
    state = _state(files={"app/main.go": "package main\n"})
    result = await worker_graph.deterministic_prescan_node(state)
    assert result == {}


async def test_prescan_skips_oversize_python_files():
    huge = "x = 1\n" * (worker_graph.PRESCAN_FILE_BYTE_LIMIT // 6 + 1)
    state = _state(files={"big.py": huge})
    result = await worker_graph.deterministic_prescan_node(state)
    assert result == {}


async def test_prescan_returns_findings_with_source_bandit_for_real_python(monkeypatch):
    """Integration of the node + Bandit subprocess. Requires the
    `bandit` binary to be present in the worker venv (it is in the
    runtime Docker image; locally pip-installed during dev).
    """
    state = _state(
        files={
            "vuln.py": (
                "import subprocess\n"
                "def run(user_input):\n"
                "    subprocess.call(user_input, shell=True)\n"
            )
        }
    )
    result = await worker_graph.deterministic_prescan_node(state)
    findings = result.get("findings", [])
    assert findings, "Expected Bandit to flag at least one issue"
    assert all(isinstance(f, VulnerabilityFinding) for f in findings)
    assert all(f.source == "bandit" for f in findings)
    assert all(f.confidence == "High" for f in findings)


async def test_prescan_returns_error_message_on_unexpected_failure(monkeypatch):
    async def _explode(*_args, **_kwargs):
        raise RuntimeError("kaboom")

    monkeypatch.setattr(worker_graph, "run_bandit", _explode)
    state = _state(files={"x.py": "y = 1\n"})
    result = await worker_graph.deterministic_prescan_node(state)
    assert "error_message" in result
    assert "kaboom" in result["error_message"]


async def test_prescan_does_not_persist_findings_in_node(monkeypatch):
    """Persistence is deferred to ``save_results_node`` (single save
    site). The prescan node must not open its own session-and-save.
    """
    saw_save = False

    class _RaisingScanRepository:
        def __init__(self, *_args, **_kwargs):
            pass

        async def save_findings(self, *_args, **_kwargs):
            nonlocal saw_save
            saw_save = True

    monkeypatch.setattr(worker_graph, "ScanRepository", _RaisingScanRepository)
    state = _state(files={"x.py": "y = 1\n"})
    await worker_graph.deterministic_prescan_node(state)
    assert saw_save is False, "deterministic_prescan_node must not save findings itself"


async def test_prescan_node_does_not_call_interrupt():
    """Static guarantee: the prescan node body must not invoke
    ``interrupt()`` (the cost-approval interrupt lives in
    ``estimate_cost_node`` and must not be duplicated). AST-based so
    a docstring mentioning the word ``interrupt`` does not trip the
    check.
    """
    import ast
    import inspect
    import textwrap

    src = textwrap.dedent(inspect.getsource(worker_graph.deterministic_prescan_node))
    tree = ast.parse(src)
    calls = [
        node
        for node in ast.walk(tree)
        if isinstance(node, ast.Call)
        and (
            (isinstance(node.func, ast.Name) and node.func.id == "interrupt")
            or (isinstance(node.func, ast.Attribute) and node.func.attr == "interrupt")
        )
    ]
    assert calls == [], (
        "deterministic_prescan_node must not call interrupt(); the "
        "cost-approval interrupt lives in estimate_cost_node."
    )
