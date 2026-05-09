"""Layer 2 ~ 5 (Query / Knowledge / Response / Logging) 를 LangGraph 로 구현.

명세 2.1 ~ 5.1 의 모든 단계가 그래프 노드로 1:1 매핑되며, 핵심 분기점인
"유사도 Threshold 충족 여부 (2.4)" 는 conditional edge 로 표현된다.

그래프 구조:

    START
      |
      v
    [preprocess]                  # 2.1 / 2.2
      |
      v
    [embed_query]                 # 2.3
      |
      v
    [retrieve]                    # 3.3 (Top-K + threshold check)
      |
      | (threshold 충족? -> rag_generate / 미충족 -> web_search)
      +----------------+
      |                |
      v                v
    [rag_generate]   [web_search] # 4.1A / 4.2-1
                       |
                       v
                    [web_filter]  # 4.2-2
                       |
                       v
                    [web_generate]# 4.2-3
                       |
      +----------------+
      |
      v
    [build_response]              # 4.3 (citations / final shape)
      |
      v
    [log]                         # 5.1
      |
      v
     END
"""

from __future__ import annotations

import time
from dataclasses import asdict
from datetime import datetime, timezone
from typing import Any, TypedDict

from langgraph.graph import END, START, StateGraph

from config import settings
from src.knowledge.knowledge_base import KnowledgeBase
from src.knowledge.retriever import RetrievalResult, Retriever
from src.knowledge.vector_store import RetrievedChunk, VectorStore
from src.logging.log_store import LogStore
from src.observability.metrics import LengthStats, QueryMetrics, ScoreStats
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
    chunks_for_prompt: list[RetrievedChunk]    # rag_chunks 또는 web_chunks
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
    metrics = state["metrics"]
    t0 = time.perf_counter()
    try:
        return fn()
    finally:
        elapsed = int((time.perf_counter() - t0) * 1000)
        metrics.stage_ms[name] = metrics.stage_ms.get(name, 0) + elapsed


def _format_web_context(results: list[WebResult]) -> list[RetrievedChunk]:
    out: list[RetrievedChunk] = []
    for i, r in enumerate(results):
        out.append(
            RetrievedChunk(
                chunk_id=f"web-{i}",
                content=r.snippet,
                metadata={
                    "source_file": r.title or r.url,
                    "page_number": "web",
                    "source_path": r.url,
                },
                similarity_score=r.score,
            )
        )
    return out


def _doc_citations(chunks: list[RetrievedChunk]) -> list[Citation]:
    cites: list[Citation] = []
    seen: set[tuple[str, Any]] = set()
    for c in chunks:
        src = str(c.metadata.get("source_file", "unknown"))
        page = c.metadata.get("page_number", "?")
        key = (src, page)
        if key in seen:
            continue
        seen.add(key)
        cites.append(
            Citation(
                kind="doc",
                label=f"{src} p.{page}",
                locator=str(c.metadata.get("source_path", src)),
            )
        )
    return cites


def _web_citations(results: list[WebResult]) -> list[Citation]:
    return [Citation(kind="web", label=r.title or r.url, locator=r.url) for r in results]


# ---------- nodes ----------

def node_preprocess(state: QueryState) -> dict[str, Any]:
    """2.1 / 2.2 — 정규화 + (선택) LLM 기반 Query Rewriting."""
    query = state["user_query"]
    rewrite = state.get("rewrite", False)
    pre = _stage(state, "preprocess",
                 lambda: query_preprocessor.preprocess(query, rewrite=rewrite))
    metrics = state["metrics"]
    metrics.query_chars = len(query)
    metrics.processed_chars = len(pre.processed)
    metrics.rewritten = pre.rewritten
    return {"pre": pre}


def node_embed_query(state: QueryState) -> dict[str, Any]:
    """2.3 — 문서와 동일한 임베딩 모델로 질문을 벡터화."""
    pre = state["pre"]
    embedding = _stage(state, "query_embed", lambda: query_embedder.embed_query(pre.processed))
    state["metrics"].embedding_dimension = len(embedding)
    return {"embedding": embedding}


def node_retrieve(state: QueryState) -> dict[str, Any]:
    """3.3 — Top-K Semantic Retrieval + 2.4 threshold check."""
    retriever = state["retriever"]
    embedding = state["embedding"]
    retrieval: RetrievalResult = _stage(state, "retrieve", lambda: retriever.retrieve(embedding))

    metrics = state["metrics"]
    metrics.threshold = retriever.threshold
    metrics.top_k = retriever.top_k
    metrics.chunks_retrieved = len(retrieval.chunks)
    metrics.threshold_met = retrieval.threshold_met
    metrics.similarity = ScoreStats.from_values([c.similarity_score for c in retrieval.chunks])
    metrics.retrieved_chunk_lengths = LengthStats.from_strings(
        [c.content for c in retrieval.chunks]
    )
    return {"retrieval": retrieval}


def node_rag_generate(state: QueryState) -> dict[str, Any]:
    """4.1 — RAG Context Injection 으로 LLM 답변 생성."""
    retrieval = state["retrieval"]
    chunks = list(retrieval.chunks)
    prompt = rag_generator.build_prompt(state["user_query"], chunks)
    state["metrics"].prompt_chars = len(prompt)
    state["metrics"].retrieval_source = "rag"

    ans = _stage(state, "llm_generate",
                 lambda: rag_generator.generate(state["user_query"], chunks))
    return {
        "chunks_for_prompt": chunks,
        "answer_text": ans.text,
        "answer_provider": ans.provider,
        "answer_model": ans.model,
    }


def node_web_search(state: QueryState) -> dict[str, Any]:
    """4.2-1 — Tavily / SerpAPI 호출."""
    raw = _stage(state, "web_search",
                 lambda: web_search_agent.search(
                     state["user_query"], top_k=settings.WEB_SEARCH_TOP_K))
    state["metrics"].web_results_raw = len(raw)
    state["metrics"].retrieval_source = "web"
    return {"web_raw": raw}


def node_web_filter(state: QueryState) -> dict[str, Any]:
    """4.2-2 — 스팸/광고/짧은 스니펫 제거."""
    filtered = _stage(state, "web_filter",
                      lambda: web_filter.filter_results(state["web_raw"]))
    state["metrics"].web_results_kept = len(filtered)
    return {"web_filtered": filtered}


def node_web_generate(state: QueryState) -> dict[str, Any]:
    """4.2-3 — 웹 컨텍스트로 LLM 답변 생성."""
    web_chunks = _format_web_context(state["web_filtered"])
    prompt = rag_generator.build_prompt(state["user_query"], web_chunks)
    state["metrics"].prompt_chars = len(prompt)

    ans = _stage(state, "llm_generate",
                 lambda: rag_generator.generate(state["user_query"], web_chunks))
    return {
        "chunks_for_prompt": web_chunks,
        "answer_text": ans.text,
        "answer_provider": ans.provider,
        "answer_model": ans.model,
    }


def node_build_response(state: QueryState) -> dict[str, Any]:
    """4.3 — 답변 + 출처를 FinalResponse 로 패키징."""
    metrics = state["metrics"]
    metrics.answer_chars = len(state["answer_text"])
    metrics.llm_provider = state["answer_provider"]
    metrics.llm_model = state["answer_model"]

    retrieval = state["retrieval"]
    if metrics.retrieval_source == "rag":
        citations = _doc_citations(state["chunks_for_prompt"])
        chunks = list(retrieval.chunks)
        web_results: list[WebResult] = []
    else:
        citations = _web_citations(state.get("web_filtered", []))
        chunks = list(retrieval.chunks)   # 임계 미만이지만 참고용으로 보존
        web_results = state.get("web_filtered", [])

    metrics.total_ms = int((time.perf_counter() - state["started_at"]) * 1000)

    response = FinalResponse(
        answer=state["answer_text"],
        retrieval_source=metrics.retrieval_source,
        citations=citations,
        chunks=chunks,
        web_results=web_results,
        similarity_scores=[c.similarity_score for c in retrieval.chunks],
        response_time_ms=metrics.total_ms,
        model=state["answer_model"],
        provider=state["answer_provider"],
        metrics=metrics,
    )
    return {"response": response}


def node_log(state: QueryState) -> dict[str, Any]:
    """5.1 — 한 사이클 전체를 로그 DB 에 기록."""
    response = state["response"]
    pre = state["pre"]
    log_store = state["log_store"]

    payload = {
        "timestamp": datetime.now(timezone.utc),
        "user_query": pre.original,
        "processed_query": pre.processed,
        "retrieval_source": response.retrieval_source,
        "retrieved_chunks": [
            {
                "chunk_id": c.chunk_id,
                "content": c.content,
                "metadata": c.metadata,
                "similarity_score": c.similarity_score,
            }
            for c in response.chunks
        ],
        "similarity_scores": response.similarity_scores,
        "generated_answer": response.answer,
        "sources_cited": [asdict(c) for c in response.citations],
        "response_time_ms": response.response_time_ms,
        "top_score": state["retrieval"].top_score,
        "metrics": response.metrics.to_dict(),
    }
    log_id = log_store.record(payload)
    return {"log_id": log_id}


# ---------- conditional edges ----------

def _route_by_threshold(state: QueryState) -> str:
    """2.4 분기: 임계치 충족 -> rag / 미충족 -> web."""
    retrieval = state["retrieval"]
    if retrieval.threshold_met and retrieval.chunks:
        return "rag_generate"
    return "web_search"


# ---------- graph factory ----------

def build_graph():
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

    # 2.4 threshold 분기
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
    """그래프를 invoke 해 Layer 2 ~ 5 전체를 실행한다."""
    store = store or VectorStore()
    retriever = retriever or Retriever(kb=KnowledgeBase(store=store))
    log_store = log_store or LogStore()

    initial: QueryState = {
        "user_query": user_query,
        "rewrite": rewrite,
        "retriever": retriever,
        "log_store": log_store,
        "metrics": QueryMetrics(),
        "started_at": time.perf_counter(),
    }
    return get_graph().invoke(initial)
