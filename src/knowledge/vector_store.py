"""ChromaDB-backed vector store.

명세 3.1 / 1.10 — 직접 구현해보세요.

설계 원칙: **저장은 storage 가, 정책은 retrieval 이.**
이 모듈은 CRUD 만, threshold 같은 정책 판정은 retriever.py 에 둠.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Iterable

from config import settings


@dataclass
class RetrievedChunk:
    content: str
    metadata: dict[str, Any]
    similarity_score: float
    chunk_id: str


class VectorStore:
    """ChromaDB 단일 컬렉션 위의 thin wrapper."""

    def __init__(
        self,
        persist_dir: str | None = None,
        collection_name: str | None = None,
    ) -> None:
        """ChromaDB PersistentClient + get_or_create_collection.

        TODO:
          - chromadb.PersistentClient(path=persist_dir or settings.CHROMA_PERSIST_DIR)
          - chromadb.config.Settings(anonymized_telemetry=False) 권장
          - collection 의 metadata 에 {"hnsw:space": "cosine"} 지정 (명세의 cosine similarity)
          - self._client, self._collection 에 보관
        """
        raise NotImplementedError("VectorStore.__init__")

    # ---------- writes ----------

    def add(
        self,
        contents: list[str],
        embeddings: list[list[float]],
        metadatas: list[dict[str, Any]],
        ids: list[str] | None = None,
    ) -> list[str]:
        """청크 N 개를 한 번에 저장. ids 없으면 UUID 로 생성.

        TODO:
          - len 일치 검증
          - ids = ids or [str(uuid.uuid4()) for _ in contents]
          - metadata 의 None / list / dict 값은 Chroma 가 거부하니 sanitize
            (str, int, float, bool 만 통과시키고 나머지는 str() 로 변환)
          - self._collection.add(documents, embeddings, metadatas, ids)
          - ids 반환
        """
        raise NotImplementedError("VectorStore.add")

    def delete(self, ids: Iterable[str]) -> None:
        """ID 목록으로 청크 삭제.

        TODO: self._collection.delete(ids=list(ids))
        """
        raise NotImplementedError("VectorStore.delete")

    def reset(self) -> None:
        """컬렉션을 완전히 비운다 (테스트/재인덱싱용).

        TODO:
          - 컬렉션 이름 백업 → delete_collection → get_or_create_collection
        """
        raise NotImplementedError("VectorStore.reset")

    # ---------- reads ----------

    def query(
        self,
        embedding: list[float],
        top_k: int,
        where: dict[str, Any] | None = None,
    ) -> list[RetrievedChunk]:
        """질문 벡터로 Top-K 검색.

        TODO:
          - self._collection.query(query_embeddings=[embedding], n_results=top_k, where=where)
          - 결과의 ids/documents/metadatas/distances 를 zip
          - 거리 → 유사도 변환: 1 - distance, [0, 1] 로 clamp
          - RetrievedChunk 의 list 로 변환해 반환
        """
        raise NotImplementedError("VectorStore.query")

    def count(self) -> int:
        """컬렉션 안의 청크 수.

        TODO: self._collection.count()
        """
        raise NotImplementedError("VectorStore.count")
