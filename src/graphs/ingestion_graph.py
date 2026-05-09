"""Layer 1 (Data Ingestion) as a LangGraph StateGraph.

명세 1.1 ~ 1.10 을 그대로 노드로 매핑하고, 분기점(1.2 PDF 여부, 1.3 추출 성공 여부)
을 conditional edge 로 표현한다. 각 노드는 IngestState 의 일부를 갱신하고,
모든 노드의 stage_ms 를 누적해 IngestMetrics 로 반환한다.

그래프 구조:

    START
      |
      v
    [load_file]                 # 1.1 파일 업로드 (raw 디렉토리에 저장)
      |
      v
    [classify]                  # 1.2 파일 타입 분류
      |  (PDF? -> pdf_extract / 그 외 -> text_read)
      +-----------------+
      |                 |
      v                 v
    [pdf_extract]    [text_read]
      |                 |
      |  (텍스트 비었나? -> ocr / 충분 -> clean)
      +---> [ocr] -----+
      |                 |
      +-----------------+
                        v
                     [clean]    # 1.6 텍스트 정제
                        |
                        v
                     [chunk]    # 1.7 Chunk Split
                        |
                        v
                     [embed]    # 1.8 Embedding
                        |
                        v
                     [tag]      # 1.9 Metadata Tagging
                        |
                        v
                     [store]    # 1.10 VectorDB 저장
                        |
                        v
                       END
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
from src.observability.metrics import IngestMetrics, LengthStats


class IngestState(TypedDict, total=False):
    # --- input ---
    source: str                       # 입력 경로
    store: VectorStore                # 의존성 주입

    # --- per-stage outputs ---
    loaded: file_loader.LoadedFile    # 1.1 결과
    file_type: str                    # 1.2 결과
    pages: list[PageText]             # 1.3 / 1.4 / 1.5 결과 (정제 전)
    cleaned: list[PageText]           # 1.6 결과
    chunks: list[chunker.Chunk]       # 1.7 결과
    texts: list[str]                  # chunk.text 만 추출
    embeddings: list[list[float]]     # 1.8 결과
    metadatas: list[dict[str, Any]]   # 1.9 결과
    chunk_ids: list[str]              # 1.10 결과

    used_ocr: bool

    # --- observability ---
    metrics: IngestMetrics
    started_at: float                 # perf_counter 시작 시각


# ---------- helpers ----------

def _stage(state: IngestState, name: str, fn) -> Any:
    """노드 내부에서 단일 작업을 측정해 metrics.stage_ms 에 누적한다."""
    metrics = state["metrics"]
    t0 = time.perf_counter()
    try:
        return fn()
    finally:
        elapsed = int((time.perf_counter() - t0) * 1000)
        metrics.stage_ms[name] = metrics.stage_ms.get(name, 0) + elapsed


# ---------- nodes ----------

def node_load_file(state: IngestState) -> dict[str, Any]:
    """1.1 파일 업로드 — 원본을 ./data/raw/ 로 카피하고 LoadedFile 을 만든다."""
    loaded = _stage(state, "file_load", lambda: file_loader.load(state["source"]))
    metrics = state["metrics"]
    metrics.source_file = loaded.path.name
    metrics.file_type = loaded.file_type
    try:
        metrics.file_size_bytes = Path(loaded.path).stat().st_size
    except OSError:
        metrics.file_size_bytes = 0
    return {"loaded": loaded, "file_type": loaded.file_type}


def node_classify(state: IngestState) -> dict[str, Any]:
    """1.2 분류 — 분기는 conditional edge 가 처리하므로 여기서는 통과시킨다."""
    return {}


def node_pdf_extract(state: IngestState) -> dict[str, Any]:
    """1.3 PDF 텍스트 추출 (pdfplumber)."""
    loaded = state["loaded"]
    pages = _stage(state, "pdf_extract", lambda: pdf_extractor.extract(loaded.path))
    return {"pages": pages, "used_ocr": False}


def node_ocr(state: IngestState) -> dict[str, Any]:
    """1.4 OCR 폴백 — pdf_extract 가 사실상 비어 있을 때만 호출된다."""
    from src.ingestion import ocr_processor   # 무거운 의존성 lazy import

    loaded = state["loaded"]
    pages = _stage(state, "ocr", lambda: ocr_processor.extract(loaded.path))
    return {"pages": pages, "used_ocr": True}


def node_text_read(state: IngestState) -> dict[str, Any]:
    """1.5 비-PDF 직접 읽기 (TXT/MD/DOCX)."""
    loaded = state["loaded"]
    pages = _stage(
        state, "text_read", lambda: text_reader.read(loaded.path, loaded.file_type)
    )
    return {"pages": pages, "used_ocr": False}


def node_clean(state: IngestState) -> dict[str, Any]:
    """1.6 텍스트 정제."""
    pages = state["pages"]
    cleaned = _stage(state, "clean", lambda: text_cleaner.clean_pages(pages))
    metrics = state["metrics"]
    metrics.pages_extracted = len(pages)
    metrics.pages_after_clean = len(cleaned)
    return {"cleaned": cleaned}


def node_chunk(state: IngestState) -> dict[str, Any]:
    """1.7 Chunk Split."""
    cleaned = state["cleaned"]
    chunks = _stage(state, "chunk", lambda: chunker.split(cleaned))
    texts = [c.text for c in chunks]
    metrics = state["metrics"]
    metrics.chunks_written = len(chunks)
    metrics.chunk_lengths = LengthStats.from_strings(texts)
    return {"chunks": chunks, "texts": texts}


def node_embed(state: IngestState) -> dict[str, Any]:
    """1.8 Embedding 생성."""
    texts = state["texts"]
    if not texts:
        return {"embeddings": []}
    embeddings = _stage(state, "embed", lambda: embedder.embed_texts(texts))
    state["metrics"].embedding_dimension = len(embeddings[0]) if embeddings else 0
    return {"embeddings": embeddings}


def node_tag(state: IngestState) -> dict[str, Any]:
    """1.9 Metadata Tagging."""
    chunks = state["chunks"]
    loaded = state["loaded"]
    metas = _stage(
        state,
        "tag",
        lambda: metadata_tagger.tag(chunks, loaded.path, loaded.file_type),
    )
    return {"metadatas": metas}


def node_store(state: IngestState) -> dict[str, Any]:
    """1.10 VectorDB 저장."""
    if not state.get("texts"):
        return {"chunk_ids": []}

    store = state["store"]
    ids = _stage(
        state,
        "store_write",
        lambda: store.add(
            contents=state["texts"],
            embeddings=state["embeddings"],
            metadatas=state["metadatas"],
        ),
    )
    return {"chunk_ids": ids}


# ---------- conditional edges ----------

def _route_by_type(state: IngestState) -> str:
    """1.2 분기: PDF -> pdf_extract / 그 외 -> text_read."""
    return "pdf_extract" if state["file_type"] == "pdf" else "text_read"


def _route_by_extract_success(state: IngestState) -> str:
    """1.3 분기: 추출 성공 -> clean / 빈 결과 -> ocr."""
    pages = state.get("pages", [])
    return "clean" if not pdf_extractor.looks_empty(pages) else "ocr"


# ---------- graph factory ----------

def build_graph():
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

    # 1.2 분기
    g.add_conditional_edges(
        "classify", _route_by_type,
        {"pdf_extract": "pdf_extract", "text_read": "text_read"},
    )

    # 1.3 분기
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


# 모듈 레벨 싱글턴 — main.py / smoke test 에서 재컴파일하지 않고 재사용한다.
_GRAPH = None


def get_graph():
    global _GRAPH
    if _GRAPH is None:
        _GRAPH = build_graph()
    return _GRAPH


# ---------- public entrypoint ----------

def run(source: str | Path, store: VectorStore | None = None) -> IngestState:
    """그래프를 invoke 해 Layer 1 전체를 실행한다."""
    metrics = IngestMetrics()
    initial: IngestState = {
        "source": str(source),
        "store": store or VectorStore(),
        "metrics": metrics,
        "started_at": time.perf_counter(),
    }
    final_state = get_graph().invoke(initial)
    metrics.total_ms = int((time.perf_counter() - initial["started_at"]) * 1000)
    final_state["metrics"] = metrics
    return final_state
