"""Factory routing — `RAG_VECTOR_STORE` flag picks the right impl.

This test stubs out `ChromaStore` and `QdrantStore` so we don't need
either container running; we just want to assert that the factory
returns the right class for each flag value.
"""

from __future__ import annotations

import sys
import types
from typing import Any

import pytest


def _install_stub(monkeypatch: pytest.MonkeyPatch, name: str, cls_name: str) -> Any:
    """Install a stub module that exposes a class with the given name."""

    class _Stub:
        instances = 0

        def __init__(self) -> None:
            type(self).instances += 1

    _Stub.__name__ = cls_name
    mod = types.ModuleType(name)
    setattr(mod, cls_name, _Stub)
    monkeypatch.setitem(sys.modules, name, mod)
    return _Stub


@pytest.mark.parametrize(
    "flag,expected",
    [
        ("chroma", "ChromaStore"),
        ("qdrant", "QdrantStore"),
        ("dual", "DualWriteStore"),
    ],
)
def test_factory_returns_expected_class(
    monkeypatch: pytest.MonkeyPatch, flag: str, expected: str
) -> None:
    from app.config import config as cfg
    from app.infrastructure.rag import factory

    # Reset singleton between rows.
    factory.reset_for_tests()

    monkeypatch.setattr(cfg.settings, "RAG_VECTOR_STORE", flag, raising=False)

    # Stub Chroma and Qdrant impls so we don't need real containers.
    _install_stub(monkeypatch, "app.infrastructure.rag.chroma_store", "ChromaStore")
    _install_stub(monkeypatch, "app.infrastructure.rag.qdrant_store", "QdrantStore")

    store = factory.get_vector_store()
    assert type(store).__name__ == expected


def test_factory_rejects_unknown_flag(monkeypatch: pytest.MonkeyPatch) -> None:
    from app.config import config as cfg
    from app.infrastructure.rag import factory

    factory.reset_for_tests()
    # Bypass the validator by setting via __dict__ — simulates the
    # case where the user inserts a value through other means.
    monkeypatch.setattr(cfg.settings, "RAG_VECTOR_STORE", "memory", raising=False)
    with pytest.raises(ValueError):
        factory.get_vector_store()
