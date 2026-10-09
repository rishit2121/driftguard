"""Shared feature logic for the DriftGuard ranker (used by train_ranker.py and app.py)."""
import os

import numpy as np

DEFAULT_EMBED_MODEL = "sentence-transformers/all-MiniLM-L6-v2"
EXPLICIT_FEATURES = ["provider_match", "symbol_match", "version_applicable", "semgrep_match", "test_failure"]
FEATURE_NAMES = ["cosine"] + EXPLICIT_FEATURES


def embed_model_name() -> str:
    return os.environ.get("EMBED_MODEL", DEFAULT_EMBED_MODEL)


def load_embedder(name: str | None = None):
    from sentence_transformers import SentenceTransformer

    return SentenceTransformer(name or embed_model_name(), device="cpu")


def embedding_dim(model) -> int:
    fn = getattr(model, "get_embedding_dimension", None) or model.get_sentence_embedding_dimension
    return int(fn())


def embed(model, texts: list[str]) -> np.ndarray:
    """L2-normalized float32 embeddings, shape (n, dim)."""
    return model.encode(texts, batch_size=32, normalize_embeddings=True, convert_to_numpy=True).astype(np.float32)


def pair_cosines(model, change_texts: list[str], code_contexts: list[str]) -> np.ndarray:
    vecs = embed(model, list(change_texts) + list(code_contexts))
    a, b = vecs[: len(change_texts)], vecs[len(change_texts):]
    return np.sum(a * b, axis=1)


def feature_matrix(cosines: np.ndarray, explicit: list[dict], drop: tuple[str, ...] = ()) -> np.ndarray:
    """Columns follow FEATURE_NAMES minus `drop`. Missing explicit features default to 0."""
    rows = [[float(c)] + [float((e or {}).get(k, 0) or 0) for k in EXPLICIT_FEATURES] for c, e in zip(cosines, explicit)]
    X = np.asarray(rows, dtype=np.float64).reshape(-1, len(FEATURE_NAMES))
    keep = [i for i, n in enumerate(FEATURE_NAMES) if n not in drop]
    return X[:, keep]
