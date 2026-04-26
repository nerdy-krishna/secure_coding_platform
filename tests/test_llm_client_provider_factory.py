"""Regression: `LLMClient._build_model` must construct a model for every
provider in the `LLMConfigurationBase.provider` allowlist.

Before `add-deepseek-grok-llm-support` the factory only had branches for
openai/anthropic/google. Adding deepseek and xai to the schema allowlist
(threat-model mitigation #1) without extending the factory would have
let admins persist configs that crash the worker at scan time. This test
pins the parity going forward — if a future provider is added to the
`Literal` but not to `_build_model`, this test is what catches it.
"""

from __future__ import annotations

from types import SimpleNamespace
from typing import Any

import pytest
from pydantic_ai.models.anthropic import AnthropicModel
from pydantic_ai.models.google import GoogleModel
from pydantic_ai.models.openai import OpenAIModel

from app.infrastructure.llm_client import LLMClient


def _stub_db_config(provider: str, model_name: str) -> Any:
    """Duck-typed `DB_LLMConfiguration` stand-in for unit-level testing
    of `_build_model`. The real ORM object carries decrypted_api_key as
    an attribute set by the repo loader; we mimic that here."""
    return SimpleNamespace(
        id="00000000-0000-0000-0000-000000000000",
        provider=provider,
        model_name=model_name,
        decrypted_api_key="sk-test-not-real",
    )


@pytest.mark.parametrize(
    "provider,model_name,expected_class",
    [
        ("openai", "gpt-4o", OpenAIModel),
        ("anthropic", "claude-sonnet-4-5", AnthropicModel),
        ("google", "gemini-2.5-flash", GoogleModel),
        # OpenAI-compatible APIs — both should resolve to OpenAIModel
        # with a custom base_url under the hood.
        ("deepseek", "deepseek-chat", OpenAIModel),
        ("xai", "grok-2-latest", OpenAIModel),
    ],
)
def test_build_model_constructs_for_every_allowlisted_provider(
    provider, model_name, expected_class
):
    client = LLMClient(_stub_db_config(provider, model_name))
    model = client._build_model()
    assert isinstance(model, expected_class), (
        f"{provider}/{model_name}: expected {expected_class.__name__}, "
        f"got {type(model).__name__}"
    )


def test_build_model_rejects_unknown_provider():
    """Defence-in-depth: even if the schema's `Literal` is widened in
    one place but not the other, the factory still raises rather than
    silently routing to a wrong provider."""
    client = LLMClient(_stub_db_config("not-a-real-provider", "x"))
    with pytest.raises(ValueError, match="Unsupported LLM provider"):
        client._build_model()
