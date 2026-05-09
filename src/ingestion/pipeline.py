"""Layer 1 의 절차적 진입점 (legacy).

LangGraph 도입 전부터 있던 순차 호출 버전. 일반적으로는
`src/graphs/ingestion_graph.run()` 을 사용하지만, 같은 모듈을 그래프 없이
호출해보고 싶을 때를 위해 시그니처만 남겨둔다.

직접 구현해보세요.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

from src.ingestion import file_loader
from src.ingestion.pdf_extractor import PageText
from src.knowledge.vector_store import VectorStore
from src.observability.metrics import IngestMetrics, StageTimings


@dataclass
class IngestResult:
    source_file: str
    file_type: str
    pages_extracted: int
    chunks_written: int
    used_ocr: bool
    chunk_ids: list[str]
    metrics: IngestMetrics = field(default_factory=IngestMetrics)


def _extract_pages(
    loaded: file_loader.LoadedFile,
    timings: StageTimings,
) -> tuple[list[PageText], bool]:
    """파일 타입에 따라 PDF/OCR/텍스트 추출 중 하나를 호출한다.

    TODO:
      - file_type == "pdf": pdf_extractor.extract → looks_empty 면 ocr_processor.extract
      - file_type in ("txt","md","docx"): text_reader.read
      - 외에는 ValueError
      - timings.time(stage_name) 컨텍스트로 각 단계 시간 누적
      - (pages, used_ocr) 튜플 반환
    """
    raise NotImplementedError("_extract_pages — 절차적 분기 구현하기")


def ingest(
    source: str | Path,
    store: VectorStore | None = None,
) -> IngestResult:
    """Layer 1 전체를 한 함수로 실행한다.

    TODO: 다음 순서대로 호출
      1. file_loader.load(source)
      2. _extract_pages(loaded, timings)
      3. text_cleaner.clean_pages(pages)
      4. chunker.split(cleaned)
      5. embedder.embed_texts(texts)
      6. metadata_tagger.tag(chunks, path, file_type)
      7. store.add(contents, embeddings, metadatas)
      각 단계 시간을 metrics.stage_ms 에 기록하고
      bytes/pages/chunks/dim 등의 카운트도 채운다.
    """
    raise NotImplementedError("ingest — Layer 1 절차적 파이프라인 구현하기")
