"""ChromaDB-backed vector store.

The store is intentionally thin: it owns persistence and CRUD against a
single Chroma collection. Higher-level concerns (filtering, threshold
checks, prompt assembly) live in retriever / knowledge_base / response.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass
from typing import Any, Iterable

import chromadb
from chromadb.config import Settings as ChromaSettings

from config import settings


@dataclass
class RetrievedChunk:
    content: str
    metadata: dict[str, Any]
    similarity_score: float
    chunk_id: str


class VectorStore:
    """Wraps a single ChromaDB collection."""

    def __init__(
        self,
        persist_dir: str | None = None,
        collection_name: str | None = None,
    ) -> None:
        self._client = chromadb.PersistentClient(
            path=persist_dir or settings.CHROMA_PERSIST_DIR,
            settings=ChromaSettings(anonymized_telemetry=False),
        )
        self._collection = self._client.get_or_create_collection(
            name=collection_name or settings.CHROMA_COLLECTION,
            # Cosine distance ⇒ similarity = 1 - distance, matching the spec.
            metadata={"hnsw:space": "cosine"},
        )

    # ---------- writes ----------

    def add(
        self,
        contents: list[str],
        embeddings: list[list[float]],
        metadatas: list[dict[str, Any]],
        ids: list[str] | None = None,
    ) -> list[str]:
        if not (len(contents) == len(embeddings) == len(metadatas)):
            raise ValueError("contents, embeddings, metadatas must align")
        if ids is None:
            ids = [str(uuid.uuid4()) for _ in contents]
        # Chroma rejects empty-list metadata values; sanitize defensively.
        cleaned = [_sanitize_metadata(m) for m in metadatas]
        self._collection.add(
            documents=contents,
            embeddings=embeddings,
            metadatas=cleaned,
            ids=ids,
        )
        return ids

    def delete(self, ids: Iterable[str]) -> None:
        self._collection.delete(ids=list(ids))

    def reset(self) -> None:
        """Drop the collection — useful for tests and reindexing."""
        name = self._collection.name
        self._client.delete_collection(name)
        self._collection = self._client.get_or_create_collection(
            name=name,
            metadata={"hnsw:space": "cosine"},
        )

    # ---------- reads ----------

    def query(
        self,
        embedding: list[float],
        top_k: int,
        where: dict[str, Any] | None = None,
    ) -> list[RetrievedChunk]:
        result = self._collection.query(
            query_embeddings=[embedding],
            n_results=top_k,
            where=where,
        )
        # Chroma returns parallel lists keyed by query index; we only sent one.
        ids = (result.get("ids") or [[]])[0]
        docs = (result.get("documents") or [[]])[0]
        metas = (result.get("metadatas") or [[]])[0]
        dists = (result.get("distances") or [[]])[0]

        chunks: list[RetrievedChunk] = []
        for chunk_id, doc, meta, dist in zip(ids, docs, metas, dists):
            chunks.append(
                RetrievedChunk(
                    chunk_id=chunk_id,
                    content=doc or "",
                    metadata=dict(meta or {}),
                    similarity_score=_distance_to_similarity(dist),
                )
            )
        return chunks

    def count(self) -> int:
        return self._collection.count()


def _distance_to_similarity(distance: float | None) -> float:
    if distance is None:
        return 0.0
    # Cosine distance in Chroma is in [0, 2]; clamp the similarity to [0, 1].
    sim = 1.0 - float(distance)
    if sim < 0.0:
        sim = 0.0
    if sim > 1.0:
        sim = 1.0
    return sim


def _sanitize_metadata(meta: dict[str, Any]) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for k, v in meta.items():
        if v is None:
            continue
        if isinstance(v, (str, int, float, bool)):
            out[k] = v
        else:
            out[k] = str(v)
    return out
