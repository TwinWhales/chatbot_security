"""Runtime RAG retrieval over the tool-metadata collection — fully fallback-safe.

Selector 와 Analyzer 가 공유하는 얇은 검색 계층. 절대 원칙:

  * 의존성(chromadb / sentence-transformers / 모델) 부재, 인덱스 없음/비어있음,
    질의 예외 — 어떤 실패든 **None 을 돌려주고 조용히 폴백**한다. 예외를
    호출자에게 던지지 않는다. RAG 가 없어도 파이프라인은 항상 동작한다.
  * settings.USE_RAG=False 면 즉시 None.

반환:
  * None      → RAG 를 쓸 수 없음 (호출자는 결정론/LLM 경로로 폴백).
  * list[]    → RAG 는 동작했으나 (필터 후) 관련 히트 없음 (재정렬 안 함, 정상).
  * list[...] → tool_id 별 관련도 히트.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass

from forensicagent import config as settings

logger = logging.getLogger(__name__)


@dataclass
class ToolHit:
    tool_id: str
    score: float          # cosine similarity ∈ [0, 1]
    snippet: str          # 임베딩된 도구 문서 본문 (LLM 컨텍스트 주입용)


def retrieve_tools(
    query: str,
    *,
    top_k: int | None = None,
    tool_ids: set[str] | None = None,
) -> list[ToolHit] | None:
    """query 로 TOOL_COLLECTION 을 검색해 tool_id 별 히트를 돌려준다.

    Args:
        query: 자연어 질의 (증거 요약 + scenario 등).
        top_k: 가져올 최대 개수. None 이면 settings.RAG_TOP_K.
        tool_ids: 주어지면 이 집합 안의 tool_id 만 통과시킨다 (Selector 의
            Stage1 자격 게이트를 RAG 가 절대 우회하지 못하게 하는 안전장치).

    Returns:
        None(폴백 신호) 또는 ToolHit 리스트.
    """
    if not settings.USE_RAG:
        return None
    if not query or not query.strip():
        return None

    want = top_k or settings.RAG_TOP_K
    # eligible 집합이 있으면 그 크기만큼은 받아와야 전부 점수화된다.
    n_results = max(want, len(tool_ids)) if tool_ids else want

    try:
        from forensicagent.rag.embedder import embed_text
        from forensicagent.rag.vector_store import VectorStore

        store = VectorStore(
            persist_dir=settings.CHROMA_PERSIST_DIR,
            collection_name=settings.TOOL_COLLECTION,
        )
        if store.count() == 0:
            logger.info("tool collection empty; RAG disabled for this run")
            return None
        vec = embed_text(query)
        chunks = store.query(vec, top_k=n_results)
    except Exception as e:  # noqa: BLE001 — deps/model/index/query 모든 실패 폴백.
        logger.info("RAG retrieval unavailable, falling back: %s", e)
        return None

    hits: list[ToolHit] = []
    seen: set[str] = set()
    for ch in chunks:
        tid = ch.metadata.get("tool_id")
        if not tid or tid in seen:
            continue
        if tool_ids is not None and tid not in tool_ids:
            continue          # Stage1 밖의 도구는 절대 승격시키지 않는다.
        seen.add(tid)
        hits.append(
            ToolHit(tool_id=tid, score=ch.similarity_score, snippet=ch.content)
        )
    return hits
