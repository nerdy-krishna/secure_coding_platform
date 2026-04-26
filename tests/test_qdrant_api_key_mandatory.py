"""Threat-model G6 — `QDRANT_API_KEY` is mandatory + placeholder rejected.

Settings construction must:
- Reject empty (raises `ValidationError` naming the field).
- Reject the literal `.env.example` placeholder `change-me-qdrant-key`
  with an operator-readable message that names the field.
- Accept any other non-empty value.
"""

from __future__ import annotations

import pytest
from pydantic import SecretStr, ValidationError


def test_qdrant_api_key_real_value_succeeds() -> None:
    """A real key passes the validator and is stored as a SecretStr."""
    from app.config.config import Settings

    s = Settings(QDRANT_API_KEY=SecretStr("real-secret-value-1234"))
    assert s.QDRANT_API_KEY.get_secret_value() == "real-secret-value-1234"


def test_qdrant_api_key_placeholder_rejected() -> None:
    """The .env.example placeholder is rejected with a field-named message."""
    from app.config.config import Settings

    with pytest.raises(ValidationError) as exc:
        Settings(QDRANT_API_KEY=SecretStr("change-me-qdrant-key"))
    msg = str(exc.value)
    assert "QDRANT_API_KEY" in msg
    assert "placeholder" in msg.lower()


def test_qdrant_api_key_empty_rejected() -> None:
    """Empty string is rejected with a 'required' message naming the field."""
    from app.config.config import Settings

    with pytest.raises(ValidationError) as exc:
        Settings(QDRANT_API_KEY=SecretStr(""))
    msg = str(exc.value)
    assert "QDRANT_API_KEY" in msg
    assert "required" in msg.lower()
