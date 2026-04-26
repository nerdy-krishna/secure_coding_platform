"""Factory routing — qdrant-only after ADR-008.

The `RAG_VECTOR_STORE` choice point and the `ChromaStore` /
`DualWriteStore` siblings are gone. The factory always returns a
`QdrantStore`; this test stubs the concrete impl so we don't need
the container running.
"""

from __future__ import annotations

import sys
import types

import pytest


def _install_qdrant_stub(monkeypatch: pytest.MonkeyPatch) -> None:
    class _Stub:
        instances = 0

        def __init__(self) -> None:
            type(self).instances += 1

    _Stub.__name__ = "QdrantStore"
    mod = types.ModuleType("app.infrastructure.rag.qdrant_store")
    setattr(mod, "QdrantStore", _Stub)
    monkeypatch.setitem(sys.modules, "app.infrastructure.rag.qdrant_store", mod)


def test_factory_returns_qdrant_store(monkeypatch: pytest.MonkeyPatch) -> None:
    from app.infrastructure.rag import factory

    factory.reset_for_tests()
    _install_qdrant_stub(monkeypatch)

    store = factory.get_vector_store()
    assert type(store).__name__ == "QdrantStore"


def test_factory_singleton_reuses_instance(monkeypatch: pytest.MonkeyPatch) -> None:
    from app.infrastructure.rag import factory

    factory.reset_for_tests()
    _install_qdrant_stub(monkeypatch)

    a = factory.get_vector_store()
    b = factory.get_vector_store()
    assert a is b
