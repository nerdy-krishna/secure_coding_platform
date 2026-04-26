"""Factory + `DualWriteStore` — flag-driven choice of vector store.

`get_vector_store()` is the only entry point callers should use:

    from app.infrastructure.rag.factory import get_vector_store
    store = get_vector_store()
    results = store.query_guidelines(["sql injection"], n_results=5)

The chosen impl depends on `settings.RAG_VECTOR_STORE`:
    * `chroma` (default) → `ChromaStore` only.
    * `dual`             → `DualWriteStore`: writes to both, reads
                            still come from Chroma.
    * `qdrant`           → `QdrantStore` only (PR2 enables the read
                            path; PR1 still ships this branch so config
                            validation accepts it).

Threat-model gate G4 (fail-open dual-write): Qdrant write failures are
caught, logged at WARN with `correlation_id_var.get()` attached, and
the call returns successfully. Chroma write failures bubble — Chroma
is still the read source in PR1, so we fail hard there.
"""

from __future__ import annotations

import logging
import threading
from typing import Any, Dict, List, Optional

from app.config.config import settings
from app.config.logging_config import correlation_id_var
from app.infrastructure.rag.base import RAGQueryResult, VectorStore

logger = logging.getLogger(__name__)

_lock = threading.Lock()
_instance: Optional[VectorStore] = None


def reset_for_tests() -> None:
    """Test-only: drop the singleton."""
    global _instance
    with _lock:
        _instance = None


def get_vector_store() -> VectorStore:
    """Return the process-local `VectorStore` per `RAG_VECTOR_STORE`."""
    global _instance
    if _instance is not None:
        return _instance
    with _lock:
        if _instance is not None:
            return _instance
        _instance = _build_store()
    return _instance


def _build_store() -> VectorStore:
    mode = settings.RAG_VECTOR_STORE
    if mode == "chroma":
        from app.infrastructure.rag.chroma_store import ChromaStore

        return ChromaStore()
    if mode == "qdrant":
        from app.infrastructure.rag.qdrant_store import QdrantStore

        return QdrantStore()
    if mode == "dual":
        from app.infrastructure.rag.chroma_store import ChromaStore
        from app.infrastructure.rag.qdrant_store import QdrantStore

        primary = ChromaStore()
        try:
            secondary: Optional[VectorStore] = QdrantStore()
        except Exception as e:
            # Fail-open: if Qdrant is unreachable at boot, log loudly
            # and keep going on Chroma alone. The operator sees this
            # in startup logs and re-enables Qdrant when the container
            # is healthy.
            logger.warning(
                "Qdrant init failed; falling back to Chroma-only for this process. "
                "Error: %s",
                e,
            )
            secondary = None
        return DualWriteStore(primary=primary, secondary=secondary)
    raise ValueError(f"Invalid RAG_VECTOR_STORE: {mode!r}")


class DualWriteStore:
    """Writes go to both stores; reads from `primary` only (PR1).

    `secondary` may be None if Qdrant init failed at boot — in that
    case the wrapper degrades to a Chroma-only store, and writes log
    a WARN per call.
    """

    def __init__(self, primary: VectorStore, secondary: Optional[VectorStore]) -> None:
        self._primary = primary
        self._secondary = secondary

    # ----- writes ----- #

    def add(
        self,
        documents: List[str],
        metadatas: List[Dict[str, Any]],
        ids: List[str],
    ) -> None:
        self._primary.add(documents, metadatas, ids)
        self._safe_secondary("add", documents, metadatas, ids)

    def delete(self, ids: List[str]) -> None:
        self._primary.delete(ids)
        self._safe_secondary("delete", ids)

    def delete_by_framework(self, framework_name: str) -> int:
        n = self._primary.delete_by_framework(framework_name)
        self._safe_secondary("delete_by_framework", framework_name)
        return n

    def _safe_secondary(self, method: str, *args: Any) -> None:
        if self._secondary is None:
            return
        try:
            getattr(self._secondary, method)(*args)
        except Exception as e:
            logger.warning(
                "Qdrant write failed (method=%s); continuing on Chroma only.",
                method,
                extra={
                    "correlation_id": correlation_id_var.get(),
                    "qdrant_method": method,
                    "qdrant_error": str(e),
                },
            )

    # ----- reads (delegated to primary in PR1) ----- #

    def query_guidelines(
        self,
        query_texts: List[str],
        n_results: int = 5,
        where: Optional[Dict[str, Any]] = None,
    ) -> RAGQueryResult:
        return self._primary.query_guidelines(query_texts, n_results, where)

    def query_cwe_collection(
        self, query_texts: List[str], n_results: int = 3
    ) -> RAGQueryResult:
        return self._primary.query_cwe_collection(query_texts, n_results)

    def get_by_framework(self, framework_name: str) -> Dict[str, Any]:
        return self._primary.get_by_framework(framework_name)

    def get_framework_stats(self) -> Dict[str, int]:
        return self._primary.get_framework_stats()

    def health_check(self) -> bool:
        return self._primary.health_check()
