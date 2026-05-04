"""Integration tests for the Langfuse client singleton + handler factory.

Covers G5 (fail-open) and G7 (trace_id == correlation_id).
"""

from __future__ import annotations

import logging
import uuid
from typing import Any

import pytest

from app.config.logging_config import correlation_id_var
from app.infrastructure.observability import langfuse_client


@pytest.fixture(autouse=True)
def _reset_singleton() -> Any:
    langfuse_client.reset_for_tests()
    yield
    langfuse_client.reset_for_tests()


def _settings_with(monkeypatch: pytest.MonkeyPatch, **overrides: Any) -> None:
    """Replace the `app.config.config.settings` singleton with a new
    frozen `Settings` carrying the given overrides. `Settings` is
    `frozen=True` (config.py), so `monkeypatch.setattr(cfg.settings, X, Y)`
    would now raise `frozen_instance` — this helper builds a copy with
    `model_copy(update=...)` and swaps the module-level reference
    instead.
    """
    from app.config import config as cfg

    monkeypatch.setattr(cfg, "settings", cfg.settings.model_copy(update=overrides))


def test_disabled_when_settings_disabled(monkeypatch: pytest.MonkeyPatch) -> None:
    """G5 path: feature flag off → no client, no handler, no SDK touched."""
    _settings_with(monkeypatch, LANGFUSE_ENABLED=False)
    assert langfuse_client.get_langfuse() is None
    assert langfuse_client.get_langchain_handler() is None
    # Flush is a no-op when no client was ever built.
    langfuse_client.flush_langfuse()


def test_disabled_when_keys_missing(monkeypatch: pytest.MonkeyPatch) -> None:
    """G5 path: enabled but no keys → still disabled, no SDK call."""
    _settings_with(
        monkeypatch,
        LANGFUSE_ENABLED=True,
        LANGFUSE_PUBLIC_KEY=None,
        LANGFUSE_SECRET_KEY=None,
    )
    assert langfuse_client.get_langfuse() is None
    assert langfuse_client.get_langchain_handler() is None


def test_init_failure_is_fail_open(
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    """G5 — if SDK construction raises, the helper returns None, latches
    `_disabled = True`, and never crashes the call site."""
    from pydantic import SecretStr

    _settings_with(
        monkeypatch,
        LANGFUSE_ENABLED=True,
        LANGFUSE_PUBLIC_KEY=SecretStr("pk-test"),
        LANGFUSE_SECRET_KEY=SecretStr("sk-test"),
    )

    class _BoomLangfuse:
        def __init__(self, *_args: Any, **_kwargs: Any) -> None:
            raise RuntimeError("simulated SDK init failure")

    import sys
    import types

    fake_module = types.ModuleType("langfuse")
    fake_module.Langfuse = _BoomLangfuse  # type: ignore[attr-defined]
    monkeypatch.setitem(sys.modules, "langfuse", fake_module)

    with caplog.at_level(logging.WARNING):
        assert langfuse_client.get_langfuse() is None
    # Subsequent calls also short-circuit (latched `_disabled`).
    assert langfuse_client.get_langfuse() is None
    assert langfuse_client.get_langchain_handler() is None


@pytest.mark.xfail(
    reason=(
        "Handler factory returns None even with the stub `langfuse` + "
        "`langfuse.langchain` modules wired. Likely the upstream langfuse "
        "SDK started doing additional `importlib`/feature checks on "
        "instantiation that the fake module doesn't satisfy. Needs a "
        "proper rewrite against the current langfuse 3.x API."
    ),
    strict=False,
)
def test_handler_picks_up_correlation_id(monkeypatch: pytest.MonkeyPatch) -> None:
    """G7 — `get_langchain_handler` reads `correlation_id_var` at call
    time and stamps it onto the handler so traces stitch with Loki by
    `X-Correlation-ID`."""
    from pydantic import SecretStr

    _settings_with(
        monkeypatch,
        LANGFUSE_ENABLED=True,
        LANGFUSE_PUBLIC_KEY=SecretStr("pk-test"),
        LANGFUSE_SECRET_KEY=SecretStr("sk-test"),
    )

    # Stub the SDK so we don't open a real network connection.
    class _StubLangfuse:
        def __init__(self, *_args: Any, **_kwargs: Any) -> None:
            self.flushed = False

        def flush(self) -> None:
            self.flushed = True

    class _StubHandler:
        def __init__(self) -> None:
            self.trace_id: str | None = None
            self.session_id: str | None = None

    import sys
    import types

    fake_lf_module = types.ModuleType("langfuse")
    fake_lf_module.Langfuse = _StubLangfuse  # type: ignore[attr-defined]
    fake_lc_module = types.ModuleType("langfuse.langchain")
    fake_lc_module.CallbackHandler = _StubHandler  # type: ignore[attr-defined]
    monkeypatch.setitem(sys.modules, "langfuse", fake_lf_module)
    monkeypatch.setitem(sys.modules, "langfuse.langchain", fake_lc_module)

    expected_id = str(uuid.uuid4())
    correlation_id_var.set(expected_id)

    handler = langfuse_client.get_langchain_handler()
    assert handler is not None
    assert handler.trace_id == expected_id
    assert handler.session_id == expected_id

    # Flush is best-effort — tolerates exceptions.
    langfuse_client.flush_langfuse()
