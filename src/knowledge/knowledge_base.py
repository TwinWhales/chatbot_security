"""Logical knowledge layer above the vector store.

Owns metadata-driven filters (file type, date range, ...) so callers don't
build raw Chroma `where` clauses themselves.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from src.knowledge.vector_store import RetrievedChunk, VectorStore


@dataclass
class Filter:
    file_types: list[str] | None = None
    source_files: list[str] | None = None
    created_after: str | None = None  # ISO-8601 string

    def to_where(self) -> dict[str, Any] | None:
        clauses: list[dict[str, Any]] = []
        if self.file_types:
            clauses.append({"file_type": {"$in": list(self.file_types)}})
        if self.source_files:
            clauses.append({"source_file": {"$in": list(self.source_files)}})
        if self.created_after:
            clauses.append({"created_at": {"$gte": self.created_after}})

        if not clauses:
            return None
        if len(clauses) == 1:
            return clauses[0]
        return {"$and": clauses}


class KnowledgeBase:
    def __init__(self, store: VectorStore | None = None) -> None:
        self.store = store or VectorStore()

    def search(
        self,
        embedding: list[float],
        top_k: int,
        filt: Filter | None = None,
    ) -> list[RetrievedChunk]:
        return self.store.query(
            embedding=embedding,
            top_k=top_k,
            where=filt.to_where() if filt else None,
        )

    def size(self) -> int:
        return self.store.count()
