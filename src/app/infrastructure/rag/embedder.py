"""Process-local ONNX embedder (lifted out of Chroma's auto-embed path).

Both `ChromaStore` and `QdrantStore` share this single embedder so they
write byte-identical 384-dim vectors. Without lifting, Chroma embeds
server-side and Qdrant has no embedder at all — dual-write would
produce divergent vectors and PR2's read-flip would silently regress
recall.

The model file is the same `all-MiniLM-L6-v2` ONNX bundle that
`chromadb` ships transitively (no separate download, no
sentence-transformers / torch dependency). We construct one
`DefaultEmbeddingFunction` at module import; subsequent calls reuse
the same model weights and tokenizer.

Threat-model gate G3 (golden parity) is enforced by
`tests/test_rag_embedder_parity.py`. Gate G8 (model file integrity) is
satisfied by loading via the `chromadb` package — no out-of-band
download path is introduced.
"""

from __future__ import annotations

import threading
from typing import List, Optional

from chromadb.utils import embedding_functions

_lock = threading.Lock()
_embedder: Optional[embedding_functions.DefaultEmbeddingFunction] = None  # type: ignore[assignment]


def _get_embedder():  # type: ignore[no-untyped-def]
    """Return the singleton `DefaultEmbeddingFunction`.

    Lazily constructed on first use so importing this module is cheap;
    the heavy ONNX runtime + model file load happen on the first
    embed() call from each process.
    """
    global _embedder
    if _embedder is not None:
        return _embedder
    with _lock:
        if _embedder is None:
            _embedder = embedding_functions.DefaultEmbeddingFunction()
    return _embedder


def embed(texts: List[str]) -> List[List[float]]:
    """Embed a batch of texts into 384-dim cosine-normalised vectors.

    The return shape matches what `DefaultEmbeddingFunction(input)`
    returns today: a `list[list[float]]` of length `len(texts)`, each
    inner list of length 384.
    """
    if not texts:
        return []
    fn = _get_embedder()
    # `DefaultEmbeddingFunction` is callable with a list of strings.
    # `EmbeddingFunction` returns numpy arrays; coerce to plain Python
    # floats so the output is JSON-serialisable for downstream callers.
    raw = fn(texts)
    out: List[List[float]] = []
    for vec in raw:
        out.append([float(x) for x in vec])
    return out


def reset_for_tests() -> None:
    """Test-only: drop the singleton so a new instance is built on next call."""
    global _embedder
    with _lock:
        _embedder = None
