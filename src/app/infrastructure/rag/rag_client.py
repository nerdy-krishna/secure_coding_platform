"""Back-compat shim for the legacy `RAGService` import path.

Pre-PR1 code did:

    from app.infrastructure.rag.rag_client import get_rag_service

This module preserves that import path but delegates to
`app.infrastructure.rag.factory.get_vector_store()` so callers see the
flag-driven impl without changing their imports. Will be deleted in
PR3 when Chroma + the legacy module name go away together.
"""

from __future__ import annotations

import logging
from typing import Optional

from app.infrastructure.rag.base import (  # re-exported for typing
    CWE_COLLECTION_NAME,
    SECURITY_GUIDELINES_COLLECTION,
    VectorStore,
)
from app.infrastructure.rag.factory import get_vector_store

logger = logging.getLogger(__name__)

# Type alias kept for callers that imported the symbol for typing.
RAGService = VectorStore


def get_rag_service() -> Optional[VectorStore]:
    """Return the configured `VectorStore`, or None on init failure.

    Pre-PR1 callers tolerate `None` already; we keep that contract.
    """
    try:
        return get_vector_store()
    except Exception as e:
        logger.error("Failed to construct VectorStore: %s", e, exc_info=True)
        return None


__all__ = [
    "CWE_COLLECTION_NAME",
    "SECURITY_GUIDELINES_COLLECTION",
    "RAGService",
    "VectorStore",
    "get_rag_service",
]
