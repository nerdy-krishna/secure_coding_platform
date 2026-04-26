"""Qdrant implementation of `VectorStore`.

PR1 of the Chroma → Qdrant migration. This impl is exercised only when
`RAG_VECTOR_STORE` is `dual` or `qdrant`; reads stay on Chroma in PR1,
so the methods that return data are wired but their outputs are not
served to live callers yet.

Threat-model gates carried into this module:
- G5 (filter parity)  — `_translate_filter` covers `$eq`, `$ne`,
  `$in`, `$and`, `$or` plus the literal filter shape used by
  `analysis_node` in `generic_specialized_agent.py`.
- G7 (placeholder env hygiene) — handled by `.env.example`, not this
  file.
- G11 (logs redact `QDRANT_API_KEY`) — `_log_init_error_env` skips any
  env var whose name contains `API_KEY`.
"""

from __future__ import annotations

import asyncio
import logging
import os
import uuid
from typing import Any, Dict, List, Optional

from qdrant_client import QdrantClient
from qdrant_client.http import models as qmodels

from app.config.config import settings
from app.infrastructure.rag.base import (
    CWE_COLLECTION_NAME,
    SECURITY_GUIDELINES_COLLECTION,
    RAGQueryResult,
)
from app.infrastructure.rag.embedder import embed

logger = logging.getLogger(__name__)

# MiniLM-L6-v2 output dim and metric — must match what Chroma produces
# for these two collections so PR2's read-flip doesn't regress recall.
VECTOR_SIZE = 384
DISTANCE = qmodels.Distance.COSINE


def _api_key() -> Optional[str]:
    secret = settings.QDRANT_API_KEY
    if secret is None:
        return None
    if hasattr(secret, "get_secret_value"):
        v = secret.get_secret_value()
    else:
        v = str(secret)
    return v or None


def _log_init_error_env() -> None:
    """Dump QDRANT_* env vars to the log on init failure, redacting
    anything that looks like a secret. Mirrors the Chroma path."""
    logger.critical("Environment variables (QDRANT_*):")
    for key, value in os.environ.items():
        if "QDRANT" not in key.upper():
            continue
        # G11 — never log API keys.
        if "API_KEY" in key.upper():
            continue
        logger.critical("  %s=%s", key, value)


def _translate_filter(where: Optional[Dict[str, Any]]) -> Optional[qmodels.Filter]:
    """Translate Chroma `where` syntax into a Qdrant `Filter`.

    Supported operators:
      - leaf clause `{"key": {"$eq": v}}`     → `must=[FieldCondition(...)]`
      - leaf clause `{"key": {"$ne": v}}`     → `must_not=[FieldCondition(...)]`
      - leaf clause `{"key": {"$in": [...]]}}` → `must=[FieldCondition(MatchAny)]`
      - composite `{"$and": [<leaf>, ...]}`   → `must=[...]`
      - composite `{"$or":  [<leaf>, ...]}`   → `should=[...]` with min_should=1
      - implicit `{"key1": v1, "key2": v2}`   → `must=[eq, eq]` (Chroma allows
        a flat dict of equalities; we honour the same shorthand)

    `analysis_node` in `generic_specialized_agent.py` constructs filters
    of the form `{"$and": [{"scan_ready": {"$eq": True}}, {"$or": [...]}]}`,
    which is fully covered by the recursive walk below.
    """
    if not where:
        return None

    must: List[qmodels.Condition] = []
    must_not: List[qmodels.Condition] = []
    should: List[qmodels.Condition] = []

    for key, val in where.items():
        if key == "$and":
            for clause in val:
                child = _translate_filter(clause)
                if child is None:
                    continue
                if child.must:
                    must.extend(child.must)
                if child.must_not:
                    must_not.extend(child.must_not)
                if child.should:
                    must.append(qmodels.Filter(should=child.should))
            continue
        if key == "$or":
            for clause in val:
                child = _translate_filter(clause)
                if child is None:
                    continue
                # The child becomes a single Filter inside `should`;
                # passing must/must_not/should together preserves the
                # AND-within-each-OR-branch semantics. Splitting them
                # into separate `should` siblings (the previous shape)
                # would have flattened `$or:[{$and:[a,not b]}, c]` into
                # `should:[a, not b, c]`, broadening the match.
                # Security review F1.
                should.append(
                    qmodels.Filter(
                        must=child.must,
                        must_not=child.must_not,
                        should=child.should,
                    )
                )
            continue

        # Leaf clauses: either {"key": {"$op": v}} or {"key": v}.
        if isinstance(val, dict) and len(val) == 1:
            op, op_val = next(iter(val.items()))
            if op == "$eq":
                must.append(
                    qmodels.FieldCondition(
                        key=key, match=qmodels.MatchValue(value=op_val)
                    )
                )
            elif op == "$ne":
                must_not.append(
                    qmodels.FieldCondition(
                        key=key, match=qmodels.MatchValue(value=op_val)
                    )
                )
            elif op == "$in":
                must.append(
                    qmodels.FieldCondition(
                        key=key, match=qmodels.MatchAny(any=list(op_val))
                    )
                )
            else:
                raise ValueError(f"Unsupported filter operator: {op!r}")
        else:
            # `{"key": value}` shorthand — equality.
            must.append(
                qmodels.FieldCondition(key=key, match=qmodels.MatchValue(value=val))
            )

    return qmodels.Filter(
        must=must or None,
        must_not=must_not or None,
        should=should or None,
    )


class QdrantStore:
    """Implements `VectorStore` against Qdrant."""

    def __init__(self) -> None:
        try:
            self._client = QdrantClient(
                host=settings.QDRANT_HOST,
                port=settings.QDRANT_PORT,
                api_key=_api_key(),
                # Default 5s; we don't want a slow Qdrant to stall scans.
                timeout=10,
            )
            # Collection bootstrap: create with the right vector params
            # if absent. Idempotent — safe to call on every init.
            self._ensure_collection(SECURITY_GUIDELINES_COLLECTION)
            self._ensure_collection(CWE_COLLECTION_NAME)
            logger.info(
                "QdrantStore initialised against %s:%s",
                settings.QDRANT_HOST,
                settings.QDRANT_PORT,
            )
        except Exception as e:
            logger.critical("Failed to initialise QdrantStore: %s", e)
            _log_init_error_env()
            raise

    def _ensure_collection(self, name: str) -> None:
        existing = {c.name for c in self._client.get_collections().collections}
        if name in existing:
            return
        self._client.create_collection(
            collection_name=name,
            vectors_config=qmodels.VectorParams(size=VECTOR_SIZE, distance=DISTANCE),
        )
        logger.info("Created Qdrant collection %s", name)

    # ------------------------------------------------------------------
    # VectorStore protocol
    # ------------------------------------------------------------------

    def add(
        self,
        documents: List[str],
        metadatas: List[Dict[str, Any]],
        ids: List[str],
    ) -> None:
        embeddings = embed(documents)
        points = [
            qmodels.PointStruct(
                id=_qdrant_id(doc_id),
                vector=vec,
                payload={**meta, "_chroma_id": doc_id, "document": doc},
            )
            for doc_id, doc, meta, vec in zip(ids, documents, metadatas, embeddings)
        ]
        self._client.upsert(
            collection_name=SECURITY_GUIDELINES_COLLECTION, points=points
        )

    def query_guidelines(
        self,
        query_texts: List[str],
        n_results: int = 5,
        where: Optional[Dict[str, Any]] = None,
    ) -> RAGQueryResult:
        query_embeddings = embed(query_texts)
        flt = _translate_filter(where)
        ids_out: List[List[str]] = []
        docs_out: List[List[str]] = []
        metas_out: List[List[Dict[str, Any]]] = []
        dists_out: List[List[float]] = []
        for vec in query_embeddings:
            hits = self._client.search(
                collection_name=SECURITY_GUIDELINES_COLLECTION,
                query_vector=vec,
                query_filter=flt,
                limit=n_results,
                with_payload=True,
            )
            ids_out.append([str(h.payload.get("_chroma_id", h.id)) for h in hits])
            docs_out.append([str(h.payload.get("document", "")) for h in hits])
            metas_out.append(
                [
                    {
                        k: v
                        for k, v in (h.payload or {}).items()
                        if k not in ("_chroma_id", "document")
                    }
                    for h in hits
                ]
            )
            # Qdrant returns similarity scores (cosine: higher = closer);
            # Chroma returns distances. We expose distance = 1 - score.
            dists_out.append([float(1.0 - (h.score or 0.0)) for h in hits])
        return {
            "ids": ids_out,
            "documents": docs_out,
            "metadatas": metas_out,
            "distances": dists_out,
        }

    def query_cwe_collection(
        self, query_texts: List[str], n_results: int = 3
    ) -> RAGQueryResult:
        query_embeddings = embed(query_texts)
        ids_out: List[List[str]] = []
        docs_out: List[List[str]] = []
        metas_out: List[List[Dict[str, Any]]] = []
        dists_out: List[List[float]] = []
        for vec in query_embeddings:
            hits = self._client.search(
                collection_name=CWE_COLLECTION_NAME,
                query_vector=vec,
                limit=n_results,
                with_payload=True,
            )
            ids_out.append([str(h.payload.get("_chroma_id", h.id)) for h in hits])
            docs_out.append([str(h.payload.get("document", "")) for h in hits])
            metas_out.append(
                [
                    {
                        k: v
                        for k, v in (h.payload or {}).items()
                        if k not in ("_chroma_id", "document")
                    }
                    for h in hits
                ]
            )
            dists_out.append([float(1.0 - (h.score or 0.0)) for h in hits])
        return {
            "ids": ids_out,
            "documents": docs_out,
            "metadatas": metas_out,
            "distances": dists_out,
        }

    def get_by_framework(self, framework_name: str) -> Dict[str, Any]:
        flt = _translate_filter({"framework_name": {"$eq": framework_name}})
        # Scroll until the framework is fully fetched; expected size is
        # in the low thousands per framework.
        hits, _ = self._client.scroll(
            collection_name=SECURITY_GUIDELINES_COLLECTION,
            scroll_filter=flt,
            limit=10_000,
            with_payload=True,
        )
        return {
            "ids": [str(h.payload.get("_chroma_id", h.id)) for h in hits],
            "documents": [str(h.payload.get("document", "")) for h in hits],
            "metadatas": [
                {
                    k: v
                    for k, v in (h.payload or {}).items()
                    if k not in ("_chroma_id", "document")
                }
                for h in hits
            ],
        }

    def get_framework_stats(self) -> Dict[str, int]:
        stats: Dict[str, int] = {}
        for fw in ["asvs", "proactive_controls", "cheatsheets"]:
            stats[fw] = len(self.get_by_framework(fw).get("ids", []))
        return stats

    def delete_by_framework(self, framework_name: str) -> int:
        docs = self.get_by_framework(framework_name)
        ids_to_delete = docs.get("ids", [])
        if not ids_to_delete:
            return 0
        self.delete(ids=ids_to_delete)
        return len(ids_to_delete)

    def delete(self, ids: List[str]) -> None:
        point_ids = [_qdrant_id(i) for i in ids]
        self._client.delete(
            collection_name=SECURITY_GUIDELINES_COLLECTION,
            points_selector=qmodels.PointIdsList(points=point_ids),
        )

    def health_check(self) -> bool:
        try:
            self._client.get_collections()
            return True
        except Exception:
            return False


_QDRANT_ID_NAMESPACE = uuid.UUID("a3a3a3a3-a3a3-a3a3-a3a3-a3a3a3a3a3a3")


def _qdrant_id(chroma_id: str) -> str:
    """Map a Chroma string id to a deterministic UUID for Qdrant.

    Qdrant rejects arbitrary string ids at the wire — its point-id
    contract is `uint64` or `UUID`. Without this mapping every
    secondary write in `dual` mode would raise and `_safe_secondary`
    would silently swallow it, leaving Qdrant empty while logs filled
    with WARNs. Hashing via `uuid5` keeps the mapping deterministic
    (same Chroma id → same Qdrant point id across processes), and the
    original Chroma id rides along in `payload._chroma_id` so we can
    round-trip identifiers through the API. Security review F3.
    """
    return str(uuid.uuid5(_QDRANT_ID_NAMESPACE, chroma_id))


# Reserved for future async upgrade — see PR3 follow-ups. The current
# qdrant-client `QdrantClient` is sync; calls happen inside the async
# graph but the upstream lib runs them on a thread under the hood
# (httpx). If profiling shows event-loop stalls we'll swap to
# `AsyncQdrantClient` here.
_ASYNC_CLIENT_PLACEHOLDER: Optional[Any] = None
asyncio  # silence unused-import warning; imported for the PR2/3 swap.
