"""Threat-model G4 — dual-write fail-open on Qdrant.

If Qdrant raises during a write, Chroma's write must still succeed
and the API caller must NOT see an error. The failure is logged at
WARN with the current `correlation_id` attached so an operator can
correlate against the scan that triggered it.
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List

import pytest

from app.config.logging_config import correlation_id_var
from app.infrastructure.rag.factory import DualWriteStore


class _StubChroma:
    def __init__(self) -> None:
        self.adds: List[tuple] = []
        self.deletes: List[List[str]] = []

    def add(
        self,
        documents: List[str],
        metadatas: List[Dict[str, Any]],
        ids: List[str],
    ) -> None:
        self.adds.append((documents, metadatas, ids))

    def delete(self, ids: List[str]) -> None:
        self.deletes.append(ids)

    def delete_by_framework(self, framework_name: str) -> int:
        return 0

    # Read methods (unused in this test but satisfy the Protocol):
    def query_guidelines(self, *a: Any, **k: Any):  # noqa: ANN
        return {"ids": [[]], "documents": [[]], "metadatas": [[]], "distances": [[]]}

    def query_cwe_collection(self, *a: Any, **k: Any):  # noqa: ANN
        return {"ids": [[]], "documents": [[]], "metadatas": [[]], "distances": [[]]}

    def get_by_framework(self, *a: Any, **k: Any):  # noqa: ANN
        return {"ids": [], "documents": [], "metadatas": []}

    def get_framework_stats(self):
        return {}

    def health_check(self) -> bool:
        return True


class _BoomQdrant(_StubChroma):
    def add(self, *_a: Any, **_k: Any) -> None:
        raise RuntimeError("simulated qdrant down")


def test_dual_write_continues_on_qdrant_failure(
    caplog: pytest.LogCaptureFixture,
) -> None:
    primary = _StubChroma()
    secondary = _BoomQdrant()
    store = DualWriteStore(primary=primary, secondary=secondary)  # type: ignore[arg-type]

    expected_corr = "test-corr-id-abc123"
    correlation_id_var.set(expected_corr)

    caplog.set_level(logging.WARNING, logger="app.infrastructure.rag.factory")

    # Must not raise.
    store.add(["doc1"], [{"k": "v"}], ["id1"])

    # Chroma side received the write.
    assert primary.adds == [(["doc1"], [{"k": "v"}], ["id1"])]
    # WARN log fired with the correlation id.
    warn_records = [r for r in caplog.records if r.levelname == "WARNING"]
    assert any("Qdrant write failed" in r.getMessage() for r in warn_records)
    assert any(
        getattr(r, "correlation_id", None) == expected_corr for r in warn_records
    )


def test_dual_write_with_no_secondary_skips_silently() -> None:
    """If Qdrant init failed at boot, `secondary=None` and writes go
    to Chroma alone. No noisy WARN per call."""
    primary = _StubChroma()
    store = DualWriteStore(primary=primary, secondary=None)
    store.add(["doc"], [{"k": "v"}], ["id"])
    assert primary.adds == [(["doc"], [{"k": "v"}], ["id"])]


def test_dual_write_chroma_failure_propagates() -> None:
    """Chroma is the read source in PR1; a write failure there must NOT
    be swallowed."""
    primary = _BoomQdrant()  # reuse the boom stub on the primary side
    secondary = _StubChroma()
    store = DualWriteStore(primary=primary, secondary=secondary)  # type: ignore[arg-type]
    with pytest.raises(RuntimeError, match="simulated qdrant down"):
        store.add(["doc"], [{"k": "v"}], ["id"])
