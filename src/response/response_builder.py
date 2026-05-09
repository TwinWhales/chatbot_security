"""Top-level response orchestration (legacy, 절차적).

명세 4.3 — 직접 구현해보세요.

LangGraph 도입 후 일반적 호출 경로는 query_graph 의 build_response 노드이며,
이 모듈은 자료형 (Citation, FinalResponse) 정의 + 절차적 진입점으로 남는다.
자료형은 그래프 노드들도 그대로 재사용한다.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Sequence

from src.knowledge.retriever import RetrievalResult
from src.knowledge.vector_store import RetrievedChunk
from src.observability.metrics import QueryMetrics
from src.response.web_search_agent import WebResult


@dataclass
class Citation:
    kind: str           # "doc" | "web"
    label: str          # 사람이 읽을 라벨 (예: "report.pdf p.12" 또는 페이지 제목)
    locator: str        # 경로/페이지 또는 URL


@dataclass
class FinalResponse:
    answer: str
    retrieval_source: str          # "rag" | "web"
    citations: list[Citation]
    chunks: list[RetrievedChunk] = field(default_factory=list)
    web_results: list[WebResult] = field(default_factory=list)
    similarity_scores: list[float] = field(default_factory=list)
    response_time_ms: int = 0
    model: str = ""
    provider: str = ""
    metrics: QueryMetrics = field(default_factory=QueryMetrics)


def _doc_citations(chunks: Sequence[RetrievedChunk]) -> list[Citation]:
    """청크들에서 (source_file, page_number) 튜플로 중복 제거된 Citation 생성.

    TODO:
      - kind="doc"
      - label = f"{source_file} p.{page_number}"
      - locator = source_path (없으면 source_file)
    """
    raise NotImplementedError("_doc_citations")


def _web_citations(results: Sequence[WebResult]) -> list[Citation]:
    """웹 결과 → Citation.

    TODO:
      - kind="web"
      - label = title or url
      - locator = url
    """
    raise NotImplementedError("_web_citations")


def _format_web_context(results: Sequence[WebResult]) -> list[RetrievedChunk]:
    """WebResult 를 RetrievedChunk 모양으로 변환해 build_prompt 가 재사용할 수 있게 한다.

    TODO:
      - 각 result 마다 RetrievedChunk(
          chunk_id=f"web-{i}",
          content=snippet,
          metadata={"source_file": title or url, "page_number": "web", "source_path": url},
          similarity_score=score)
    """
    raise NotImplementedError("_format_web_context")


def build(
    user_query: str,
    retrieval: RetrievalResult,
    metrics: QueryMetrics | None = None,
) -> FinalResponse:
    """절차적 진입점: threshold 보고 RAG/Web 분기, 답변 + citation + metrics 반환.

    TODO:
      - retrieval.threshold_met 면 RAG 경로:
          rag_generator.generate(query, retrieval.chunks)
          citations = _doc_citations(retrieval.chunks)
      - 아니면 Web 경로:
          web_search_agent.search → web_filter.filter_results → _format_web_context
          → rag_generator.generate
          citations = _web_citations(filtered)
      - metrics 의 stage_ms / similarity / answer_chars 등을 채우고
        FinalResponse 반환
    """
    raise NotImplementedError("build")
