"""Embedding interface used by both ingestion and query layers.

Both sides MUST share the same model — that's why this is one module
imported by both. Models are loaded lazily and cached as a process-level
singleton so we don't reload weights per call.
"""

from __future__ import annotations

from functools import lru_cache
from typing import Iterable

from config import settings


class _SentenceTransformerBackend:
    def __init__(self, model_name: str) -> None:
        from sentence_transformers import SentenceTransformer

        self._model = SentenceTransformer(model_name)

    def embed(self, texts: list[str]) -> list[list[float]]:
        # convert_to_numpy=True is the SBERT default; .tolist() converts cleanly.
        vectors = self._model.encode(texts, show_progress_bar=False)
        return [v.tolist() for v in vectors]


class _OpenAIBackend:
    def __init__(self, model_name: str) -> None:
        from openai import OpenAI

        if not settings.OPENAI_API_KEY:
            raise RuntimeError(
                "OPENAI_API_KEY is required for the OpenAI embedding backend"
            )
        self._client = OpenAI(api_key=settings.OPENAI_API_KEY)
        self._model = model_name

    def embed(self, texts: list[str]) -> list[list[float]]:
        # OpenAI accepts batched input; one call covers all chunks of a doc.
        resp = self._client.embeddings.create(model=self._model, input=texts)
        return [d.embedding for d in resp.data]


@lru_cache(maxsize=1)
def _get_backend():
    name = settings.EMBEDDING_MODEL
    if name.startswith("openai:"):
        return _OpenAIBackend(name.split(":", 1)[1])
    return _SentenceTransformerBackend(name)


def embed_texts(texts: Iterable[str]) -> list[list[float]]:
    items = [t for t in texts]
    if not items:
        return []
    return _get_backend().embed(items)


def embed_text(text: str) -> list[float]:
    return embed_texts([text])[0]
