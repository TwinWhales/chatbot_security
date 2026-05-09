"""Layer 1 (Data Ingestion) as a LangGraph StateGraph.

명세 1.1 ~ 1.10 을 그래프 노드로 1:1 매핑하고, 분기점은 conditional edge 로 표현.

그래프 구조:

    START
      │
      ▼
    [load_file]                 # 1.1
      │
      ▼
    [classify]                  # 1.2  (PDF? → pdf_extract / 그 외 → text_read)
      ├─────────────────┐
      ▼                 ▼
    [pdf_extract]    [text_read]
      │  (텍스트 비었나? → ocr / 충분 → clean)
      ├──→ [ocr] ──┐
      │            │
      └────────────┴──→ [clean] → [chunk] → [embed] → [tag] → [store] → END

build_graph() 의 wiring 은 학습 frame 으로 그대로 유지. 노드 함수 본문만
직접 채워보세요.
"""

from __future__ import annotations

import time
from pathlib import Path
from typing import Any, TypedDict

from langgraph.graph import END, START, StateGraph

from src.ingestion import (
    chunker,
    embedder,
    file_loader,
    metadata_tagger,
    pdf_extractor,
    text_cleaner,
    text_reader,
)
from src.ingestion.pdf_extractor import PageText
from src.knowledge.vector_store import VectorStore
from src.observability.metrics import IngestMetrics


class IngestState(TypedDict, total=False):
    # --- input ---
    source: str
    store: VectorStore

    # --- per-stage outputs ---
    loaded: file_loader.LoadedFile
    file_type: str
    pages: list[PageText]
    cleaned: list[PageText]
    chunks: list[chunker.Chunk]
    texts: list[str]
    embeddings: list[list[float]]
    metadatas: list[dict[str, Any]]
    chunk_ids: list[str]
    used_ocr: bool

    # --- observability ---
    metrics: IngestMetrics
    started_at: float


# ---------- helpers (frame 으로 유지) ----------

def _stage(state: IngestState, name: str, fn) -> Any:
    """노드 안에서 단일 작업을 측정해 metrics.stage_ms 에 누적."""
    metrics = state["metrics"]
    t0 = time.perf_counter()
    try:
        return fn()
    finally:
        elapsed = int((time.perf_counter() - t0) * 1000)
        metrics.stage_ms[name] = metrics.stage_ms.get(name, 0) + elapsed


# ---------- nodes (TODO: 구현 채우기) ----------

def node_load_file(state: IngestState) -> dict[str, Any]:
    """1.1 — file_loader.load 호출, metrics 의 file_type / file_size_bytes 채우기.

    TODO:
      - _stage(state, "file_load", lambda: file_loader.load(state["source"]))
      - metrics.source_file / file_type / file_size_bytes 갱신
      - return {"loaded": loaded, "file_type": loaded.file_type}
    """
    raise NotImplementedError("node_load_file")


def node_classify(state: IngestState) -> dict[str, Any]:
    """1.2 — 단순 통과 노드 (실제 분기는 conditional edge 가 처리).

    TODO: return {}
    """
    raise NotImplementedError("node_classify")


def node_pdf_extract(state: IngestState) -> dict[str, Any]:
    """1.3 — pdf_extractor.extract.

    TODO:
      - _stage(state, "pdf_extract", lambda: pdf_extractor.extract(loaded.path))
      - return {"pages": pages, "used_ocr": False}
    """
    raise NotImplementedError("node_pdf_extract")


def node_ocr(state: IngestState) -> dict[str, Any]:
    """1.4 — ocr_processor.extract.

    TODO:
      - lazy import: from src.ingestion import ocr_processor
      - _stage(state, "ocr", lambda: ocr_processor.extract(loaded.path))
      - return {"pages": pages, "used_ocr": True}
    """
    raise NotImplementedError("node_ocr")


def node_text_read(state: IngestState) -> dict[str, Any]:
    """1.5 — text_reader.read.

    TODO:
      - _stage(state, "text_read", lambda: text_reader.read(loaded.path, loaded.file_type))
      - return {"pages": pages, "used_ocr": False}
    """
    raise NotImplementedError("node_text_read")


def node_clean(state: IngestState) -> dict[str, Any]:
    """1.6 — text_cleaner.clean_pages, metrics.pages_extracted/after_clean 갱신.

    TODO: return {"cleaned": cleaned}
    """
    raise NotImplementedError("node_clean")


def node_chunk(state: IngestState) -> dict[str, Any]:
    """1.7 — chunker.split, metrics.chunks_written / chunk_lengths 갱신.

    TODO:
      - LengthStats.from_strings(texts) 도 채우기
      - return {"chunks": chunks, "texts": texts}
    """
    raise NotImplementedError("node_chunk")


def node_embed(state: IngestState) -> dict[str, Any]:
    """1.8 — embedder.embed_texts, metrics.embedding_dimension 갱신.

    TODO:
      - texts 가 비어있으면 return {"embeddings": []}
      - return {"embeddings": embeddings}
    """
    raise NotImplementedError("node_embed")


def node_tag(state: IngestState) -> dict[str, Any]:
    """1.9 — metadata_tagger.tag.

    TODO: return {"metadatas": metas}
    """
    raise NotImplementedError("node_tag")


def node_store(state: IngestState) -> dict[str, Any]:
    """1.10 — VectorStore.add.

    TODO:
      - texts 비어있으면 return {"chunk_ids": []}
      - 그 외엔 store.add(contents=texts, embeddings=..., metadatas=...)
      - return {"chunk_ids": ids}
    """
    raise NotImplementedError("node_store")


# ---------- conditional edges (TODO: 구현 채우기) ----------

def _route_by_type(state: IngestState) -> str:
    """1.2 분기.

    TODO: file_type 이 "pdf" 면 "pdf_extract", 아니면 "text_read"
    """
    raise NotImplementedError("_route_by_type")


def _route_by_extract_success(state: IngestState) -> str:
    """1.3 분기.

    TODO:
      - pdf_extractor.looks_empty(state["pages"]) 가 True 면 "ocr"
      - 아니면 "clean"
    """
    raise NotImplementedError("_route_by_extract_success")


# ---------- graph factory (frame 으로 유지) ----------

def build_graph():
    """Layer 1 의 LangGraph wiring — 그대로 두고 노드 함수만 채우면 동작."""
    g: StateGraph = StateGraph(IngestState)

    g.add_node("load_file", node_load_file)
    g.add_node("classify", node_classify)
    g.add_node("pdf_extract", node_pdf_extract)
    g.add_node("ocr", node_ocr)
    g.add_node("text_read", node_text_read)
    g.add_node("clean", node_clean)
    g.add_node("chunk", node_chunk)
    g.add_node("embed", node_embed)
    g.add_node("tag", node_tag)
    g.add_node("store", node_store)

    g.add_edge(START, "load_file")
    g.add_edge("load_file", "classify")

    g.add_conditional_edges(
        "classify", _route_by_type,
        {"pdf_extract": "pdf_extract", "text_read": "text_read"},
    )

    g.add_conditional_edges(
        "pdf_extract", _route_by_extract_success,
        {"clean": "clean", "ocr": "ocr"},
    )

    g.add_edge("ocr", "clean")
    g.add_edge("text_read", "clean")
    g.add_edge("clean", "chunk")
    g.add_edge("chunk", "embed")
    g.add_edge("embed", "tag")
    g.add_edge("tag", "store")
    g.add_edge("store", END)

    return g.compile()


_GRAPH = None


def get_graph():
    global _GRAPH
    if _GRAPH is None:
        _GRAPH = build_graph()
    return _GRAPH


# ---------- public entrypoint ----------

def run(source: str | Path, store: VectorStore | None = None) -> IngestState:
    """그래프 invoke. 노드들이 채워지면 그대로 동작한다.

    TODO: 노드 구현 완료 후 다음을 채워보세요.
      - metrics = IngestMetrics()
      - initial state 구성 (source, store, metrics, started_at=time.perf_counter())
      - get_graph().invoke(initial)
      - metrics.total_ms 에 perf_counter 차이 기록 후 final state 반환
    """
    raise NotImplementedError("ingestion_graph.run")
