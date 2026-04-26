"""Unit tests for the Langfuse trace-payload redaction (G1).

The `mask` function is the single security control that prevents
customer secrets — secrets that slipped past Gitleaks at pre-LLM time —
from persisting in ClickHouse / MinIO via Langfuse traces. These tests
pin the contract.
"""

from __future__ import annotations

import pytest

from app.infrastructure.observability.mask import mask


@pytest.mark.parametrize(
    "given, expected",
    [
        # 1) Provider-style key patterns get redacted regardless of context.
        (
            "AKIAIOSFODNN7EXAMPLE",
            "***",
        ),
        (
            "leaked here: AKIAIOSFODNN7EXAMPLE in code",
            "leaked here: *** in code",
        ),
        (
            "OPENAI_API_KEY=sk-proj-1234567890abcdefghij",
            "OPENAI_API_KEY=***",
        ),
        (
            "ANTHROPIC=sk-ant-api03-abcdefghij1234567890",
            "ANTHROPIC=***",
        ),
        (
            "github=ghp_abcdefghij1234567890ABCDEFGHIJ",
            "github=***",
        ),
        # 2) Keyword=value redacts the value, preserves the keyword so
        # the trace reader still sees "secret was here". Whitespace and
        # quotes around the value are tolerated.
        (
            'password = "hunter2sup3rsecret"',
            "password = ***",
        ),
        # `Authorization: Bearer <token>` redacts both the scheme (matched
        # by the keyword=value pattern) and the token (matched by the
        # bare high-entropy pattern). Slightly chattier output than a
        # single replacement, but strictly more secure — both halves are
        # scrubbed regardless of which regex misses.
        (
            "Authorization: Bearer abcdefghij1234567890ABCDEFGHIJ",
            "Authorization: *** ***",
        ),
        # 3) High-entropy bare strings (≥20 chars, Shannon > 4.0) get
        # redacted. Note: redaction operates on word-boundary tokens.
        (
            "the token A1b2C3d4E5f6G7h8I9j0K1L2 is here",
            "the token *** is here",
        ),
        # Negative cases — should pass through unchanged.
        ("hello world", "hello world"),
        ("aaaaaaaaaaaaaaaaaaaaaaaa", "aaaaaaaaaaaaaaaaaaaaaaaa"),  # low entropy
        ("short", "short"),
        ("file_path.py", "file_path.py"),
    ],
)
def test_mask_string_cases(given: str, expected: str) -> None:
    assert mask(given) == expected


def test_mask_recurses_dicts_and_lists() -> None:
    payload = {
        "system_prompt": "You are an analyst.",
        "user_prompt": "OPENAI_API_KEY=sk-proj-1234567890abcdefghij analyse this",
        "files": [
            {"path": "config.env", "content": "password=very_long_secret_value"},
            {"path": "ok.py", "content": "print('hello')"},
        ],
    }
    redacted = mask(payload)
    assert isinstance(redacted, dict)
    assert redacted["system_prompt"] == "You are an analyst."
    assert "***" in redacted["user_prompt"]
    assert "sk-proj" not in redacted["user_prompt"]
    assert redacted["files"][0]["content"] == "password=***"
    assert redacted["files"][1]["content"] == "print('hello')"


def test_mask_passes_through_non_string() -> None:
    assert mask(None) is None
    assert mask(42) == 42
    assert mask(True) is True


def test_mask_does_not_raise_on_unexpected_types() -> None:
    class Weird:
        def __str__(self) -> str:
            raise RuntimeError("boom")

    obj = Weird()
    # Returns the original object on any exception in the descent.
    assert mask(obj) is obj
