"""RAG (retrieval-augmented generation) layer.

Pick a `VectorStore` via `get_vector_store()`. Two concrete impls today
(`ChromaStore`, `QdrantStore`) plus the `DualWriteStore` wrapper for
the migration window. The legacy `get_rag_service` symbol still works
- it lives in `rag_client.py` and delegates to `get_vector_store()`.
"""

from app.infrastructure.rag.base import (
    CWE_COLLECTION_NAME,
    SECURITY_GUIDELINES_COLLECTION,
    RAGQueryResult,
    VectorStore,
)
from app.infrastructure.rag.factory import get_vector_store
from app.infrastructure.rag.rag_client import RAGService, get_rag_service

__all__ = [
    "CWE_COLLECTION_NAME",
    "RAGService",
    "RAGQueryResult",
    "SECURITY_GUIDELINES_COLLECTION",
    "VectorStore",
    "get_rag_service",
    "get_vector_store",
]
