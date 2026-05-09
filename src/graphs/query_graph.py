"""Layer 2 ~ 5 (Query / Knowledge / Response / Logging) 를 LangGraph 로 구현.

명세 2.1 ~ 5.1 의 모든 단계가 그래프 노드로 1:1 매핑되며, 핵심 분기점인
"유사도 Threshold 충족 여부 (2.4)" 는 conditional edge 로 표현된다.

그래프 구조:

    START
      │
      ▼
    [preprocess]                 # 2.1 / 2.2
      │
      ▼
    [embed_query]                # 2.3
      │
      ▼
    [retrieve]                   # 3.3 (Top-K + threshold)
      │
      │ (충족? → rag_generate / 미충족 → web_search)
      ├──────────────┐
      ▼              ▼
    [rag_generate] [web_search]  # 4.1 / 4.2-1
                     │
                     ▼
                  [web_filter]   # 4.2-2
                     │
                     ▼
                  [web_generate] # 4.2-3
                     │
      ┌──────────────┘
      ▼
    [build_response]             # 4.3
      │
      ▼
    [log]                        # 5.1
      │
      ▼
     END

build_graph() wiring 은 그대로 두고 노드 함수만 채워보세요.
"""

from __future__ import annotations

import time
from typing import Any, TypedDict

from langgraph.graph import END, START, StateGraph

from src.knowledge.knowledge_base import KnowledgeBase
from src.knowledge.retriever import RetrievalResult, Retriever
from src.knowledge.vector_store import RetrievedChunk, VectorStore
from src.logging.log_store import LogStore
from src.observability.metrics import QueryMetrics
from src.query import query_embedder, query_preprocessor
from src.response import rag_generator, web_filter, web_search_agent
from src.response.response_builder import Citation, FinalResponse
from src.response.web_search_agent import WebResult


class QueryState(TypedDict, total=False):
    # --- input ---
    user_query: str
    rewrite: bool
    retriever: Retriever
    log_store: LogStore

    # --- per-stage outputs ---
    pre: query_preprocessor.PreprocessedQuery
    embedding: list[float]
    retrieval: RetrievalResult
    chunks_for_prompt: list[RetrievedChunk]
    web_raw: list[WebResult]
    web_filtered: list[WebResult]
    answer_text: str
    answer_provider: str
    answer_model: str

    response: FinalResponse
    log_id: str

    # --- observability ---
    metrics: QueryMetrics
    started_at: float


# ---------- helpers ----------

def _stage(state: QueryState, name: str, fn) -> Any:
    """노드 안에서 단일 작업을 측정해 metrics.stage_ms 에 누적."""
    metrics = state["metrics"]
    t0 = time.perf_counter()
    try:
        return fn()
    finally:
        elapsed = int((time.perf_counter() - t0) * 1000)
        metrics.stage_ms[name] = metrics.stage_ms.get(name, 0) + elapsed


def _format_web_context(results: list[WebResult]) -> list[RetrievedChunk]:
    """WebResult → RetrievedChunk 모양 변환 (build_prompt 재사용용).

    TODO: response_builder._format_web_context 와 같은 동작.
    """
    raise NotImplementedError("_format_web_context (query_graph)")


def _doc_citations(chunks: list[RetrievedChunk]) -> list[Citation]:
    """TODO: response_builder._doc_citations 와 같은 동작."""
    raise NotImplementedError("_doc_citations (query_graph)")


def _web_citations(results: list[WebResult]) -> list[Citation]:
    """TODO: response_builder._web_citations 와 같은 동작."""
    raise NotImplementedError("_web_citations (query_graph)")


# ---------- nodes (TODO: 구현 채우기) ----------

def node_preprocess(state: QueryState) -> dict[str, Any]:
    """2.1 / 2.2.

    TODO:
      - _stage(state, "preprocess", lambda: query_preprocessor.preprocess(query, rewrite=...))
      - metrics.query_chars / processed_chars / rewritten 갱신
      - return {"pre": pre}
    """
    raise NotImplementedError("node_preprocess")


def node_embed_query(state: QueryState) -> dict[str, Any]:
    """2.3.

    TODO:
      - _stage(state, "query_embed", lambda: query_embedder.embed_query(pre.processed))
      - metrics.embedding_dimension 갱신
      - return {"embedding": embedding}
    """
    raise NotImplementedError("node_embed_query")


def node_retrieve(state: QueryState) -> dict[str, Any]:
    """3.3 + 2.4 (검색 + threshold 판정).

    TODO:
      - _stage(state, "retrieve", lambda: retriever.retrieve(embedding))
      - metrics.threshold/top_k/chunks_retrieved/threshold_met/similarity/retrieved_chunk_lengths 갱신
      - return {"retrieval": retrieval}
    """
    raise NotImplementedError("node_retrieve")


def node_rag_generate(state: QueryState) -> dict[str, Any]:
    """4.1 — RAG context injection 으로 LLM 답변 생성.

    TODO:
      - rag_generator.build_prompt → metrics.prompt_chars / retrieval_source="rag"
      - _stage(state, "llm_generate", lambda: rag_generator.generate(query, chunks))
      - return {"chunks_for_prompt": chunks, "answer_text", "answer_provider", "answer_model"}
    """
    raise NotImplementedError("node_rag_generate")


def node_web_search(state: QueryState) -> dict[str, Any]:
    """4.2-1 — Tavily/SerpAPI 호출.

    TODO:
      - _stage(state, "web_search", lambda: web_search_agent.search(query))
      - metrics.web_results_raw / retrieval_source="web" 갱신
      - return {"web_raw": raw}
    """
    raise NotImplementedError("node_web_search")


def node_web_filter(state: QueryState) -> dict[str, Any]:
    """4.2-2.

    TODO:
      - _stage(state, "web_filter", lambda: web_filter.filter_results(state["web_raw"]))
      - metrics.web_results_kept 갱신
      - return {"web_filtered": filtered}
    """
    raise NotImplementedError("node_web_filter")


def node_web_generate(state: QueryState) -> dict[str, Any]:
    """4.2-3.

    TODO:
      - _format_web_context → build_prompt → _stage("llm_generate", generate)
      - metrics.prompt_chars 갱신
      - return {"chunks_for_prompt", "answer_text", "answer_provider", "answer_model"}
    """
    raise NotImplementedError("node_web_generate")


def node_build_response(state: QueryState) -> dict[str, Any]:
    """4.3 — citations + FinalResponse 패키징, metrics.total_ms 마감.

    TODO:
      - metrics.answer_chars / llm_provider / llm_model 채우기
      - retrieval_source 에 따라 citation 종류 결정
      - metrics.total_ms = perf_counter() - state["started_at"] 변환
      - FinalResponse 생성 후 return {"response": response}
    """
    raise NotImplementedError("node_build_response")


def node_log(state: QueryState) -> dict[str, Any]:
    """5.1 — log_store.record 로 한 사이클 영속화.

    TODO: payload dict 구성 후
      - log_id = log_store.record(payload)
      - return {"log_id": log_id}
    payload 구성은 명세 5.1 의 스키마 참고.
    """
    raise NotImplementedError("node_log")


# ---------- conditional edges (TODO) ----------

def _route_by_threshold(state: QueryState) -> str:
    """2.4 분기.

    TODO:
      - retrieval.threshold_met 이고 chunks 가 비어있지 않으면 "rag_generate"
      - 아니면 "web_search"
    """
    raise NotImplementedError("_route_by_threshold")


# ---------- graph factory (frame 으로 유지) ----------

def build_graph():
    """Layer 2 ~ 5 의 LangGraph wiring — 그대로 두고 노드만 채우면 동작."""
    g: StateGraph = StateGraph(QueryState)

    g.add_node("preprocess", node_preprocess)
    g.add_node("embed_query", node_embed_query)
    g.add_node("retrieve", node_retrieve)
    g.add_node("rag_generate", node_rag_generate)
    g.add_node("web_search", node_web_search)
    g.add_node("web_filter", node_web_filter)
    g.add_node("web_generate", node_web_generate)
    g.add_node("build_response", node_build_response)
    g.add_node("log", node_log)

    g.add_edge(START, "preprocess")
    g.add_edge("preprocess", "embed_query")
    g.add_edge("embed_query", "retrieve")

    g.add_conditional_edges(
        "retrieve", _route_by_threshold,
        {"rag_generate": "rag_generate", "web_search": "web_search"},
    )

    g.add_edge("web_search", "web_filter")
    g.add_edge("web_filter", "web_generate")

    g.add_edge("rag_generate", "build_response")
    g.add_edge("web_generate", "build_response")

    g.add_edge("build_response", "log")
    g.add_edge("log", END)

    return g.compile()


_GRAPH = None


def get_graph():
    global _GRAPH
    if _GRAPH is None:
        _GRAPH = build_graph()
    return _GRAPH


# ---------- public entrypoint ----------

def run(
    user_query: str,
    *,
    rewrite: bool = False,
    store: VectorStore | None = None,
    retriever: Retriever | None = None,
    log_store: LogStore | None = None,
) -> QueryState:
    """그래프 invoke. 노드들이 채워지면 그대로 동작.

    TODO:
      - 의존성 default 채우기 (store, retriever, log_store)
      - initial state (user_query, rewrite, retriever, log_store, metrics, started_at)
      - get_graph().invoke(initial) 결과 반환
    """
    raise NotImplementedError("query_graph.run")
