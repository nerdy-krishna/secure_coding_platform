"""Back-compat shim — re-exports the factory + Protocol under the old names.

ADR-008 retired Chroma + the `dual` flag and made Qdrant the only
backend, but the old import path
`from app.infrastructure.rag.rag_client import get_rag_service,
RAGService` is still used by ~7 call sites (routers, services, agents,
operator scripts). Keeping a thin re-export shim here lets the
migration ship without touching every site; new code should import
directly from `app.infrastructure.rag.factory` /
`app.infrastructure.rag.base`.
"""

from __future__ import annotations

import logging
from typing import Optional

from app.infrastructure.rag.base import (
    CWE_COLLECTION_NAME,
    SECURITY_GUIDELINES_COLLECTION,
    VectorStore,
)
from app.infrastructure.rag.factory import get_vector_store

logger = logging.getLogger(__name__)

# Type alias kept for callers that import `RAGService` purely for typing.
RAGService = VectorStore


def get_rag_service() -> Optional[VectorStore]:
    """Return the configured `VectorStore`, or None on init failure.

    Pre-PR3 callers tolerate `None` already; we keep that contract.
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
