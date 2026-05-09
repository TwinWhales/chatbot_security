"""Top-K semantic retrieval with similarity-threshold gating.

명세 3.3 + 2.4 — 직접 구현해보세요.

Threshold 판정 (RAG/Web 분기) 의 단일 출처. query_graph 의 conditional edge
가 RetrievalResult.threshold_met 만 보고 분기한다.
"""

from __future__ import annotations

from dataclasses import dataclass

from config import settings
from src.knowledge.knowledge_base import Filter, KnowledgeBase
from src.knowledge.vector_store import RetrievedChunk


@dataclass
class RetrievalResult:
    chunks: list[RetrievedChunk]
    threshold_met: bool
    top_score: float


class Retriever:
    def __init__(
        self,
        kb: KnowledgeBase | None = None,
        top_k: int | None = None,
        threshold: float | None = None,
    ) -> None:
        self.kb = kb or KnowledgeBase()
        self.top_k = top_k or settings.TOP_K
        self.threshold = (
            threshold if threshold is not None else settings.SIMILARITY_THRESHOLD
        )

    def retrieve(
        self,
        query_embedding: list[float],
        filt: Filter | None = None,
    ) -> RetrievalResult:
        """Top-K 검색 후 임계치 충족 여부를 판정해 반환.

        TODO:
          1. self.kb.search(embedding, top_k, filt) 로 청크 가져오기
          2. 빈 결과면 RetrievalResult([], False, 0.0) 반환
          3. top_score = max(c.similarity_score for c in chunks)
          4. threshold_met = top_score >= self.threshold
          5. RetrievalResult(chunks, threshold_met, top_score) 반환
        """
        raise NotImplementedError("Retriever.retrieve")
