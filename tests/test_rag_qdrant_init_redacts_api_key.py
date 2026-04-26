"""Threat-model G11 — Qdrant init-error logs MUST NOT leak the API key.

`QdrantStore.__init__` dumps `QDRANT_*` env vars on init failure for
operator triage. The dump filter MUST skip any var whose name contains
`API_KEY` so a `QDRANT_API_KEY=secret-…` value never lands in CI logs.
"""

from __future__ import annotations

import logging
import os

import pytest


def test_init_failure_redacts_api_key(
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    # Plant the secret in env.
    secret_value = "redact-this-please-xyz123"
    monkeypatch.setenv("QDRANT_API_KEY", secret_value)
    monkeypatch.setenv("QDRANT_HOST", "127.0.0.1")
    # Port 1 is a guaranteed connection refusal on Linux.
    monkeypatch.setenv("QDRANT_PORT", "1")

    # Force the SCCAP Settings to re-read env so the SecretStr field
    # picks up the planted key.
    from app.config import config as cfg

    monkeypatch.setattr(
        cfg.settings,
        "QDRANT_API_KEY",
        cfg.SecretStr(secret_value),
        raising=False,
    )
    monkeypatch.setattr(cfg.settings, "QDRANT_HOST", "127.0.0.1", raising=False)
    monkeypatch.setattr(cfg.settings, "QDRANT_PORT", 1, raising=False)

    caplog.set_level(logging.CRITICAL, logger="app.infrastructure.rag.qdrant_store")

    from app.infrastructure.rag.qdrant_store import QdrantStore

    with pytest.raises(Exception):
        QdrantStore()

    full_log = caplog.text + " ".join(
        str(getattr(r, "args", "")) for r in caplog.records
    )
    assert (
        secret_value not in full_log
    ), f"QDRANT_API_KEY value {secret_value!r} leaked into logs:\n{full_log!r}"
    # Positive: env-dump still works for non-secret keys.
    assert "QDRANT_HOST" in full_log
    # Be defensive — clean up just in case.
    os.environ.pop("QDRANT_API_KEY", None)
