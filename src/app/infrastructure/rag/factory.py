"""Factory for the single `VectorStore` impl (ADR-008).

ADR-007's `RAG_VECTOR_STORE=chroma|dual|qdrant` choice point is gone.
Qdrant is the only backend; this factory is a thin singleton wrapper
around `QdrantStore` so callers don't import the concrete class
directly (keeps the door open for the async-client swap noted in the
PR3 follow-ups).

The eager-build hook in `app.main.lifespan` calls `get_vector_store()`
once at startup, wrapped in try/except — Qdrant down at boot doesn't
block API startup, lazy retry kicks in on the next caller.
"""

from __future__ import annotations

import logging
import threading
from typing import Optional

from app.infrastructure.rag.base import VectorStore

logger = logging.getLogger(__name__)

_lock = threading.Lock()
_instance: Optional[VectorStore] = None


def reset_for_tests() -> None:
    """Test-only: drop the singleton."""
    global _instance
    with _lock:
        _instance = None


def get_vector_store() -> VectorStore:
    """Return the process-local `VectorStore`. Builds on first call."""
    global _instance
    if _instance is not None:
        return _instance
    with _lock:
        if _instance is not None:
            return _instance
        _instance = _build_store()
    return _instance


def _build_store() -> VectorStore:
    from app.infrastructure.rag.qdrant_store import QdrantStore

    return QdrantStore()
