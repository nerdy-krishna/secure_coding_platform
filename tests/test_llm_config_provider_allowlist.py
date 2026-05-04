"""Pydantic-allowlist tests for the `provider` field on the LLM-config schema.

Threat-model mitigation #1 from `add-deepseek-grok-llm-support`: an
unvalidated provider string lets an admin (or a hijacked admin session)
persist arbitrary provider values that fall through to the `len/4`
token-estimate path and bypass cost gating. The fix is a
`Literal[...]` allowlist on `LLMConfigurationBase.provider` and
`LLMConfigurationUpdate.provider`. FastAPI converts a Pydantic
`ValidationError` on a request body into HTTP 422; testing the model
directly is the same guarantee at the unit-test level.
"""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from app.api.v1.models import LLMConfigurationCreate, LLMConfigurationUpdate


def test_create_rejects_unknown_provider():
    with pytest.raises(ValidationError) as exc_info:
        LLMConfigurationCreate(
            name="bogus",
            provider="bogus-vendor",  # type: ignore[arg-type]
            model_name="some-model",
            api_key="sk-test-1234567890",
        )
    errors = exc_info.value.errors()
    assert any(
        e["loc"] == ("provider",) and e["type"].startswith("literal_error")
        for e in errors
    ), errors


@pytest.mark.parametrize(
    "provider,model_name",
    [
        ("openai", "gpt-4o"),
        ("anthropic", "claude-sonnet-4-5"),
        ("google", "gemini-2.5-flash"),
        ("deepseek", "deepseek-chat"),
        ("xai", "grok-2-latest"),
    ],
)
def test_create_accepts_supported_providers(provider, model_name):
    cfg = LLMConfigurationCreate(
        name=f"{provider}-test",
        provider=provider,  # type: ignore[arg-type]
        model_name=model_name,
        api_key="sk-test-1234567890",
    )
    assert cfg.provider == provider
    assert cfg.model_name == model_name


def test_update_rejects_unknown_provider():
    with pytest.raises(ValidationError) as exc_info:
        LLMConfigurationUpdate(provider="bogus-vendor")  # type: ignore[arg-type]
    errors = exc_info.value.errors()
    assert any(
        e["loc"] == ("provider",) and e["type"].startswith("literal_error")
        for e in errors
    ), errors


@pytest.mark.parametrize("provider", ["deepseek", "xai"])
def test_update_accepts_new_providers(provider):
    upd = LLMConfigurationUpdate(provider=provider)  # type: ignore[arg-type]
    assert upd.provider == provider


def test_update_allows_unset_provider():
    upd = LLMConfigurationUpdate(name="rename-only")
    assert upd.provider is None


def test_read_accepts_legacy_provider_value():
    """`LLMConfigurationRead.provider` is intentionally relaxed to `str`
    so that legacy rows persisted by the pre-2026-04-27 setup form (which
    spelled Google as 'gemini') still serialise. Without this relaxation,
    `GET /api/v1/llm-configs/` would 500 against any deployment that
    wasn't normalised by Alembic c0f39ef37367 yet.
    """
    import uuid
    from datetime import datetime, timezone

    from app.api.v1.models import LLMConfigurationRead

    payload = {
        "id": uuid.uuid4(),
        "name": "legacy",
        "provider": "gemini",  # value not in the Literal allowlist
        "model_name": "gemini-1.5-pro",
        "tokenizer": None,
        "input_cost_per_million": 0.0,
        "output_cost_per_million": 0.0,
        "created_at": datetime.now(timezone.utc),
        "updated_at": datetime.now(timezone.utc),
    }
    read = LLMConfigurationRead.model_validate(payload)
    assert read.provider == "gemini"
