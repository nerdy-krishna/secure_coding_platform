"""Process-local ONNX embedder via fastembed (ADR-008).

`fastembed.TextEmbedding("sentence-transformers/all-MiniLM-L6-v2")`
loads the same MiniLM-L6-v2 ONNX bundle the chromadb-bundled
DefaultEmbeddingFunction used pre-PR3 — we measured byte-equivalent
output (max per-dim diff ~6e-9, cosine = 1.0) against the chromadb
path on three fixed inputs, so existing Qdrant collections seeded
under PR1 are still recall-compatible.

The model file is downloaded once at Docker-build time
(`Dockerfile` final stages run a warm-up `embed(["warmup"])` after
copying the venv) and cached at `FASTEMBED_CACHE_PATH`
(`/opt/fastembed-cache` per the base stage). Runtime never reaches
out to HuggingFace, which keeps air-gapped / restricted-egress
deployments working (threat-model row 6 / mitigation 7).
"""

from __future__ import annotations

import threading
from typing import List, Optional

from fastembed import TextEmbedding

# Same model name across PR1 and PR3 — see ADR-008.
_MODEL_NAME = "sentence-transformers/all-MiniLM-L6-v2"

# V02.4.1 — hard caps to prevent hostile callers from pinning ONNX CPU.
MAX_BATCH = 256
MAX_CHARS_PER_TEXT = 8192

_lock = threading.Lock()
_embedder: Optional[TextEmbedding] = None


def _get_embedder() -> TextEmbedding:
    """Return the singleton TextEmbedding instance, loading on first use."""
    global _embedder
    if _embedder is not None:
        return _embedder
    with _lock:
        if _embedder is None:
            _embedder = TextEmbedding(_MODEL_NAME)
    return _embedder


def embed(texts: List[str]) -> List[List[float]]:
    """Embed a batch of texts to 384-dim cosine-normalised float vectors."""
    if not texts:
        return []
    if len(texts) > MAX_BATCH:
        raise ValueError(f"embed batch exceeds {MAX_BATCH}")
    if any(len(t) > MAX_CHARS_PER_TEXT for t in texts):
        raise ValueError("embed input text too long")
    fn = _get_embedder()
    out: List[List[float]] = []
    for vec in fn.embed(texts):
        out.append([float(x) for x in vec])
    return out


def reset_for_tests() -> None:
    """Test-only: drop the singleton."""
    global _embedder
    with _lock:
        _embedder = None
