"""Chroma implementation of `VectorStore`.

Extracted from the previous monolithic `rag_client.py`. The only
behavioural change: embeddings are computed app-side via
`app.infrastructure.rag.embedder` (formerly Chroma auto-embedded
server-side). This is the same `all-MiniLM-L6-v2` ONNX bundle, so
existing collections still produce same-cluster results — see
`tests/test_rag_embedder_parity.py` for the golden-vector pin.
"""

from __future__ import annotations

import logging
import os
import socket
from typing import Any, Dict, List, Optional

import chromadb
import requests
from chromadb.api import ClientAPI
from chromadb.api.types import Where

from app.infrastructure.rag.base import (
    CWE_COLLECTION_NAME,
    SECURITY_GUIDELINES_COLLECTION,
    RAGQueryResult,
)
from app.infrastructure.rag.embedder import embed

logger = logging.getLogger(__name__)

CHROMA_HOST = os.getenv("CHROMA_HOST", "vector_db")
CHROMA_PORT = int(os.getenv("CHROMA_PORT", 8000))


def _test_connection(host: str, port: int) -> bool:
    """Socket + HTTP heartbeat — same pattern as the pre-PR1 code."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(5)
        result = sock.connect_ex((host, port))
        sock.close()
        if result == 0:
            try:
                response = requests.get(
                    f"http://{host}:{port}/api/v1/heartbeat", timeout=10
                )
                return response.status_code == 200
            except requests.exceptions.RequestException:
                return False
        return False
    except Exception as e:
        logger.error("Chroma connection test failed: %s", e)
        return False


class ChromaStore:
    """Implements `VectorStore` against ChromaDB 0.5.x."""

    _client: Optional[ClientAPI] = None
    _guidelines_collection: Optional[Any] = None
    _cwe_collection: Optional[Any] = None

    def __init__(self) -> None:
        if not _test_connection(CHROMA_HOST, CHROMA_PORT):
            raise ConnectionError(
                f"Cannot establish basic connection to {CHROMA_HOST}:{CHROMA_PORT}"
            )

        client = chromadb.HttpClient(
            host=CHROMA_HOST,
            port=CHROMA_PORT,
            ssl=False,
            headers={"Connection": "keep-alive"},
        )
        client.heartbeat()

        # Collections were originally created with Chroma's
        # DefaultEmbeddingFunction so existing data has the same
        # embedding model. We pass it again here so collection
        # creation in fresh deployments matches the prior behaviour;
        # writes/queries from this PR pass `embeddings=` directly so
        # the auto-embed path is no longer taken at runtime.
        from chromadb.utils import embedding_functions  # local import

        ef = embedding_functions.DefaultEmbeddingFunction()
        self._guidelines_collection = client.get_or_create_collection(
            name=SECURITY_GUIDELINES_COLLECTION,
            embedding_function=ef,  # type: ignore[arg-type]
        )
        self._cwe_collection = client.get_or_create_collection(
            name=CWE_COLLECTION_NAME,
            embedding_function=ef,  # type: ignore[arg-type]
        )
        self._client = client
        logger.info("ChromaStore initialised against %s:%s", CHROMA_HOST, CHROMA_PORT)

    # ------------------------------------------------------------------
    # VectorStore protocol
    # ------------------------------------------------------------------

    def add(
        self,
        documents: List[str],
        metadatas: List[Dict[str, Any]],
        ids: List[str],
    ) -> None:
        if not self._guidelines_collection:
            raise ConnectionError("ChromaDB collection is not available.")
        embeddings = embed(documents)
        self._guidelines_collection.upsert(
            documents=documents,
            metadatas=metadatas,
            ids=ids,
            embeddings=embeddings,  # type: ignore[arg-type]
        )

    def query_guidelines(
        self,
        query_texts: List[str],
        n_results: int = 5,
        where: Optional[Dict[str, Any]] = None,
    ) -> RAGQueryResult:
        if not self._guidelines_collection:
            raise ConnectionError("Security Guidelines collection not available.")
        query_embeddings = embed(query_texts)
        where_filter: Optional[Where] = where  # type: ignore[assignment]
        results = self._guidelines_collection.query(
            query_embeddings=query_embeddings,
            n_results=n_results,
            where=where_filter,
        )
        return results  # type: ignore[return-value]

    def query_cwe_collection(
        self, query_texts: List[str], n_results: int = 3
    ) -> RAGQueryResult:
        if not self._cwe_collection:
            raise ConnectionError("CWE collection not available.")
        query_embeddings = embed(query_texts)
        results = self._cwe_collection.query(
            query_embeddings=query_embeddings,
            n_results=n_results,
        )
        return results  # type: ignore[return-value]

    def get_by_framework(self, framework_name: str) -> Dict[str, Any]:
        if not self._guidelines_collection:
            raise ConnectionError("ChromaDB collection is not available.")
        where_filter: Where = {"framework_name": {"$eq": framework_name}}
        return self._guidelines_collection.get(
            where=where_filter,
            include=["metadatas", "documents"],
        )

    def get_framework_stats(self) -> Dict[str, int]:
        if not self._guidelines_collection:
            raise ConnectionError("ChromaDB collection is not available.")
        stats: Dict[str, int] = {}
        for fw in ["asvs", "proactive_controls", "cheatsheets"]:
            result = self._guidelines_collection.get(
                where={"framework_name": {"$eq": fw}},
                include=[],
            )
            stats[fw] = len(result.get("ids", []))
        return stats

    def delete_by_framework(self, framework_name: str) -> int:
        if not self._guidelines_collection:
            raise ConnectionError("ChromaDB collection is not available.")
        docs = self.get_by_framework(framework_name)
        ids_to_delete = docs.get("ids", [])
        if not ids_to_delete:
            return 0
        self.delete(ids=ids_to_delete)
        return len(ids_to_delete)

    def delete(self, ids: List[str]) -> None:
        if not self._guidelines_collection:
            raise ConnectionError("ChromaDB collection is not available.")
        self._guidelines_collection.delete(ids=ids)

    def health_check(self) -> bool:
        return _test_connection(CHROMA_HOST, CHROMA_PORT)
