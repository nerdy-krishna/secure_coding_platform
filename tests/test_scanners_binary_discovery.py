"""Tests for the shared `_resolve_binary` helper used by all SAST runners.

Resolution order (per N14): ``$<NAME>_BINARY`` env var → ``shutil.which``
→ hardcoded fallback. Lets local dev outside Docker iterate without a
fixed venv layout.
"""

from __future__ import annotations

import pytest

from app.infrastructure.scanners.bandit_runner import _resolve_binary


@pytest.fixture(autouse=True)
def _clear_resolve_binary_cache():
    """`_resolve_binary` is `@functools.cache`d (Feature-7 F2 — lazy
    resolution so .env-loaded `*_BINARY` is honored). Clear between
    tests so monkeypatched env / shutil.which combinations don't
    collide on cached values."""
    _resolve_binary.cache_clear()
    yield
    _resolve_binary.cache_clear()


def test_env_var_wins(monkeypatch):
    monkeypatch.setenv("FAKE_TOOL_BINARY", "/custom/path/fake-tool")
    monkeypatch.setattr(
        "app.infrastructure.scanners.bandit_runner.shutil.which",
        lambda _name: "/usr/bin/fake-tool",
    )
    assert (
        _resolve_binary("FAKE_TOOL_BINARY", "fake-tool", fallback="/fallback")
        == "/custom/path/fake-tool"
    )


def test_shutil_which_used_when_env_var_absent(monkeypatch):
    monkeypatch.delenv("FAKE_TOOL_BINARY", raising=False)
    monkeypatch.setattr(
        "app.infrastructure.scanners.bandit_runner.shutil.which",
        lambda _name: "/usr/bin/fake-tool",
    )
    assert (
        _resolve_binary("FAKE_TOOL_BINARY", "fake-tool", fallback="/fallback")
        == "/usr/bin/fake-tool"
    )


def test_hardcoded_fallback_used_when_nothing_else(monkeypatch):
    monkeypatch.delenv("FAKE_TOOL_BINARY", raising=False)
    monkeypatch.setattr(
        "app.infrastructure.scanners.bandit_runner.shutil.which",
        lambda _name: None,
    )
    assert (
        _resolve_binary("FAKE_TOOL_BINARY", "fake-tool", fallback="/opt/fake")
        == "/opt/fake"
    )


def test_default_fallback_uses_app_venv(monkeypatch):
    monkeypatch.delenv("FAKE_TOOL_BINARY", raising=False)
    monkeypatch.setattr(
        "app.infrastructure.scanners.bandit_runner.shutil.which",
        lambda _name: None,
    )
    assert (
        _resolve_binary("FAKE_TOOL_BINARY", "fake-tool") == "/app/.venv/bin/fake-tool"
    )
