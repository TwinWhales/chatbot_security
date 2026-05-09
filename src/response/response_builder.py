"""Top-level response orchestration.

Decides between RAG (Path A) and Web (Path B) based on the retriever's
threshold judgement, builds the prompt, calls the LLM, and packages the
final response with citations.

Every stage is timed and counted; the resulting QueryMetrics is attached
to FinalResponse so the logging layer can persist it.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Sequence

from config import settings
from src.knowledge.retriever import RetrievalResult
from src.knowledge.vector_store import RetrievedChunk
from src.observability.metrics import (
    LengthStats,
    QueryMetrics,
    ScoreStats,
    Stopwatch,
)
from src.response import rag_generator, web_filter, web_search_agent
from src.response.web_search_agent import WebResult


@dataclass
class Citation:
    kind: str           # "doc" | "web"
    label: str          # human-readable label
    locator: str        # path/page or URL


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


def _web_citations(results: Sequence[WebResult]) -> list[Citation]:
    return [
        Citation(kind="web", label=r.title or r.url, locator=r.url)
        for r in results
    ]


def _format_web_context(results: Sequence[WebResult]) -> list[RetrievedChunk]:
    """Adapt web results to RetrievedChunk shape so the prompt builder reuses them."""
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


def build(
    user_query: str,
    retrieval: RetrievalResult,
    metrics: QueryMetrics | None = None,
) -> FinalResponse:
    """Run Path A or Path B and return a FinalResponse with metrics attached.

    The caller (main.py) builds a QueryMetrics that already records the
    preprocess/embed/retrieve timings; this function only fills in the
    response-side fields. If `metrics` is None, a fresh one is created
    so the function still works in isolation (e.g. tests).
    """
    m = metrics or QueryMetrics()
    m.threshold = m.threshold or settings.SIMILARITY_THRESHOLD
    m.top_k = m.top_k or settings.TOP_K
    m.chunks_retrieved = len(retrieval.chunks)
    m.threshold_met = retrieval.threshold_met
    m.similarity = ScoreStats.from_values([c.similarity_score for c in retrieval.chunks])
    m.retrieved_chunk_lengths = LengthStats.from_strings([c.content for c in retrieval.chunks])

    with Stopwatch() as total_sw:
        if retrieval.threshold_met and retrieval.chunks:
            m.retrieval_source = "rag"
            prompt = rag_generator.build_prompt(user_query, retrieval.chunks)
            m.prompt_chars = len(prompt)
            with m.stage_ms.time("llm_generate"):
                ans = rag_generator.generate(user_query, retrieval.chunks)

            m.answer_chars = len(ans.text)
            m.llm_provider = ans.provider
            m.llm_model = ans.model
            m.total_ms = total_sw.elapsed_ms

            return FinalResponse(
                answer=ans.text,
                retrieval_source="rag",
                citations=_doc_citations(retrieval.chunks),
                chunks=list(retrieval.chunks),
                similarity_scores=[c.similarity_score for c in retrieval.chunks],
                response_time_ms=total_sw.elapsed_ms,
                model=ans.model,
                provider=ans.provider,
                metrics=m,
            )

        # Path B — web fallback.
        m.retrieval_source = "web"
        with m.stage_ms.time("web_search"):
            raw = web_search_agent.search(user_query, top_k=settings.WEB_SEARCH_TOP_K)
        m.web_results_raw = len(raw)

        with m.stage_ms.time("web_filter"):
            filtered = web_filter.filter_results(raw)
        m.web_results_kept = len(filtered)

        web_chunks = _format_web_context(filtered)
        prompt = rag_generator.build_prompt(user_query, web_chunks)
        m.prompt_chars = len(prompt)
        with m.stage_ms.time("llm_generate"):
            ans = rag_generator.generate(user_query, web_chunks)

        m.answer_chars = len(ans.text)
        m.llm_provider = ans.provider
        m.llm_model = ans.model

    m.total_ms = total_sw.elapsed_ms

    return FinalResponse(
        answer=ans.text,
        retrieval_source="web",
        citations=_web_citations(filtered),
        chunks=list(retrieval.chunks),
        web_results=filtered,
        similarity_scores=[c.similarity_score for c in retrieval.chunks],
        response_time_ms=total_sw.elapsed_ms,
        model=ans.model,
        provider=ans.provider,
        metrics=m,
    )
