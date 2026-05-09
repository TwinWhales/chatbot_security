"""Logical knowledge layer above the vector store.

명세 3.2 — 직접 구현해보세요.
호출자가 raw Chroma `where` 절을 직접 다루지 않게 한다.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from src.knowledge.vector_store import RetrievedChunk, VectorStore


@dataclass
class Filter:
    file_types: list[str] | None = None
    source_files: list[str] | None = None
    created_after: str | None = None  # ISO-8601 문자열

    def to_where(self) -> dict[str, Any] | None:
        """필터 조건을 ChromaDB where 절로 변환.

        TODO:
          - file_types: {"file_type": {"$in": [...]}}
          - source_files: {"source_file": {"$in": [...]}}
          - created_after: {"created_at": {"$gte": ...}}
          - 빈 조건이면 None
          - 한 절이면 그대로, 여러 절이면 {"$and": [절1, 절2, ...]}
        """
        raise NotImplementedError("Filter.to_where")


class KnowledgeBase:
    def __init__(self, store: VectorStore | None = None) -> None:
        self.store = store or VectorStore()

    def search(
        self,
        embedding: list[float],
        top_k: int,
        filt: Filter | None = None,
    ) -> list[RetrievedChunk]:
        """필터를 적용해 vector_store 에 위임.

        TODO:
          - where = filt.to_where() if filt else None
          - return self.store.query(embedding, top_k, where=where)
        """
        raise NotImplementedError("KnowledgeBase.search")

    def size(self) -> int:
        """TODO: self.store.count()"""
        raise NotImplementedError("KnowledgeBase.size")
