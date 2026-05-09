"""Top-K semantic retrieval with similarity-threshold gating.

The threshold check happens here (not inside the vector store) because
"is this good enough to use as RAG context?" is a retrieval-policy
question, not a storage question.
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
        chunks = self.kb.search(query_embedding, top_k=self.top_k, filt=filt)

        if not chunks:
            return RetrievalResult(chunks=[], threshold_met=False, top_score=0.0)

        top_score = max(c.similarity_score for c in chunks)
        return RetrievalResult(
            chunks=chunks,
            threshold_met=top_score >= self.threshold,
            top_score=top_score,
        )
