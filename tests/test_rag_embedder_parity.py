"""Threat-model G3 + G8 — embedder parity and determinism.

The lifted `app.infrastructure.rag.embedder` MUST produce vectors
that are byte-identical (within 1e-6 cosine tolerance) to what
`chromadb.utils.embedding_functions.DefaultEmbeddingFunction()`
returns. Otherwise existing collection contents disagree with new
queries and recall regresses silently.

Determinism: two calls with the same input return identical vectors.
"""

from __future__ import annotations

import math

import pytest


def _cosine(a, b):
    dot = sum(x * y for x, y in zip(a, b))
    na = math.sqrt(sum(x * x for x in a))
    nb = math.sqrt(sum(y * y for y in b))
    return dot / (na * nb) if na and nb else 0.0


def _norms_close(a, b, tol: float = 1e-6) -> bool:
    """Return True if the two vectors are equal within `tol` per dim."""
    if len(a) != len(b):
        return False
    return max(abs(x - y) for x, y in zip(a, b)) <= tol


@pytest.fixture
def fixed_input() -> str:
    # The input is deliberately a long-ish prose sentence to exercise
    # tokenization. Pinned so the golden vector check is reproducible
    # across machines (within a 1e-6 tolerance).
    return "the quick brown fox jumps over the lazy dog"


def test_embedder_produces_384_dim_normalised_vector(fixed_input: str) -> None:
    """G3 (shape) — output is a 384-dim list of floats."""
    from app.infrastructure.rag.embedder import embed

    out = embed([fixed_input])
    assert len(out) == 1
    assert len(out[0]) == 384
    # MiniLM outputs are already L2-normalised; norm should be ~1.0.
    n = math.sqrt(sum(x * x for x in out[0]))
    assert 0.95 <= n <= 1.05


def test_embedder_matches_chroma_default(fixed_input: str) -> None:
    """G3 (parity) — lifted embedder matches Chroma's bundled default
    within numerical tolerance."""
    from chromadb.utils import embedding_functions

    from app.infrastructure.rag.embedder import embed

    chroma_ef = embedding_functions.DefaultEmbeddingFunction()
    chroma_vec = [float(x) for x in chroma_ef([fixed_input])[0]]
    lifted_vec = embed([fixed_input])[0]

    # Per-dim equality within float tolerance.
    assert _norms_close(chroma_vec, lifted_vec, tol=1e-6)
    # And cosine similarity ~1.0.
    assert _cosine(chroma_vec, lifted_vec) >= 0.999999


def test_embedder_is_deterministic(fixed_input: str) -> None:
    """G3 (determinism) — same input → same output across calls."""
    from app.infrastructure.rag.embedder import embed

    a = embed([fixed_input])
    b = embed([fixed_input])
    assert _norms_close(a[0], b[0], tol=0.0)


def test_embedder_handles_empty_input() -> None:
    from app.infrastructure.rag.embedder import embed

    assert embed([]) == []
