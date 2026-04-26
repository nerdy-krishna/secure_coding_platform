"""RAG (retrieval-augmented generation) layer.

ADR-008 (Chroma → Qdrant migration finished): Qdrant is the only
backend. Pick a `VectorStore` via `get_vector_store()`. The legacy
`get_rag_service` symbol still works (re-exported by `rag_client.py`)
to avoid churn across the ~7 historic call sites.
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
