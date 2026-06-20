"""Embeddings interface for Layer 2 (Semantic Memory).

Default backend: sentence-transformers/all-MiniLM-L6-v2 — a small, fast,
offline-capable model (384 dims, ~90MB). No API key required.

The embedder is loaded once and cached; subsequent calls are cheap. If the
heavy ML dependency is unavailable at runtime, we fall back to a deterministic
hash-based pseudo-embedding so the rest of the platform still runs (clearly
labelled via the returned `backend` field).
"""
from __future__ import annotations

import hashlib
import logging
import threading
from typing import Any

import numpy as np

from .config import get_settings

log = logging.getLogger(__name__)
_settings = get_settings()

_lock = threading.Lock()
_embedder: Any = None
_backend_name: str | None = None


def _load_model():
    """Lazily load the sentence-transformers model (or a deterministic fallback)."""
    global _embedder, _backend_name
    if _embedder is not None:
        return
    with _lock:
        if _embedder is not None:
            return
        try:
            from sentence_transformers import SentenceTransformer

            _embedder = SentenceTransformer(
                _settings.embeddings.model_name,
                cache_folder=_settings.embeddings.cache_dir,
            )
            _backend_name = "sentence-transformers"
            log.info("Embedder loaded: %s", _settings.embeddings.model_name)
        except Exception as e:
            log.warning(
                "sentence-transformers unavailable (%s); using hash fallback. "
                "Install requirements.memory.txt for real embeddings.",
                e,
            )
            _embedder = "hash_fallback"
            _backend_name = "hash_fallback"


def _hash_embed(text: str) -> list[float]:
    """Deterministic fallback embedding (NOT semantically meaningful)."""
    dim = _settings.embeddings.dim
    vec = np.zeros(dim, dtype=np.float32)
    # Hash overlapping n-grams of the text into the vector space.
    cleaned = (text or "").lower().encode("utf-8")
    for n in (1, 2, 3):
        for i in range(max(1, len(cleaned) - n + 1)):
            gram = cleaned[i : i + n]
            h = hashlib.md5(gram).digest()
            idx = int.from_bytes(h[:2], "little") % dim
            sign = 1.0 if (h[2] & 1) else -1.0
            vec[idx] += sign
    norm = np.linalg.norm(vec)
    if norm > 0:
        vec /= norm
    return vec.tolist()


def embed(text: str) -> list[float]:
    """Return the embedding vector for a single text string."""
    _load_model()
    if _embedder == "hash_fallback":
        return _hash_embed(text)
    return _embedder.encode(text, normalize_embeddings=True).tolist()


def embed_batch(texts: list[str]) -> list[list[float]]:
    """Embed a batch of texts in one call (much faster for many documents)."""
    _load_model()
    if _embedder == "hash_fallback":
        return [_hash_embed(t) for t in texts]
    vecs = _embedder.encode(texts, normalize_embeddings=True, show_progress_bar=False)
    return [v.tolist() for v in vecs]


def backend_name() -> str:
    """Name of the active embedding backend (for health/diagnostics)."""
    _load_model()
    return _backend_name or "unloaded"
