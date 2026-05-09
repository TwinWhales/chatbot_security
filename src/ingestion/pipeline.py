"""Orchestrates the full ingestion path described in Layer 1 of the spec.

    upload -> classify -> extract (PDF/OCR/text) -> clean -> chunk ->
    embed -> tag -> write to vector store

Every stage is timed and counted; the resulting IngestMetrics is attached
to the returned IngestResult so callers (CLI, tests, future schedulers)
can persist or display it.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

from config import settings
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
from src.observability.metrics import (
    IngestMetrics,
    LengthStats,
    StageTimings,
    Stopwatch,
)


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
    """Returns (pages, used_ocr). OCR is only attempted for PDFs."""
    if loaded.file_type == "pdf":
        with timings.time("pdf_extract"):
            pages = pdf_extractor.extract(loaded.path)
        if pdf_extractor.looks_empty(pages):
            from src.ingestion import ocr_processor

            with timings.time("ocr"):
                pages = ocr_processor.extract(loaded.path)
            return pages, True
        return pages, False

    if loaded.file_type in ("txt", "md", "docx"):
        with timings.time("text_read"):
            pages = text_reader.read(loaded.path, loaded.file_type)
        return pages, False

    raise ValueError(f"Unsupported file type: {loaded.file_type}")


def ingest(
    source: str | Path,
    store: VectorStore | None = None,
) -> IngestResult:
    store = store or VectorStore()
    metrics = IngestMetrics()
    timings = metrics.stage_ms

    with Stopwatch() as total_sw:
        with timings.time("file_load"):
            loaded = file_loader.load(source)
        metrics.source_file = loaded.path.name
        metrics.file_type = loaded.file_type
        try:
            metrics.file_size_bytes = loaded.path.stat().st_size
        except OSError:
            metrics.file_size_bytes = 0

        pages, used_ocr = _extract_pages(loaded, timings)
        metrics.used_ocr = used_ocr
        metrics.pages_extracted = len(pages)

        with timings.time("clean"):
            cleaned = text_cleaner.clean_pages(pages)
        metrics.pages_after_clean = len(cleaned)

        with timings.time("chunk"):
            chunks = chunker.split(cleaned)
        metrics.chunks_written = len(chunks)

        if not chunks:
            metrics.total_ms = total_sw.elapsed_ms
            # close stopwatch context value before assignment via __exit__:
            # `total_ms` will be set after the `with` block exits below.
            return IngestResult(
                source_file=loaded.path.name,
                file_type=loaded.file_type,
                pages_extracted=metrics.pages_after_clean,
                chunks_written=0,
                used_ocr=used_ocr,
                chunk_ids=[],
                metrics=metrics,
            )

        texts = [c.text for c in chunks]
        metrics.chunk_lengths = LengthStats.from_strings(texts)

        with timings.time("embed"):
            embeddings = embedder.embed_texts(texts)
        metrics.embedding_dimension = len(embeddings[0]) if embeddings else 0

        with timings.time("tag"):
            metadatas = metadata_tagger.tag(chunks, loaded.path, loaded.file_type)

        with timings.time("store_write"):
            chunk_ids = store.add(
                contents=texts,
                embeddings=embeddings,
                metadatas=metadatas,
            )

    metrics.total_ms = total_sw.elapsed_ms

    return IngestResult(
        source_file=loaded.path.name,
        file_type=loaded.file_type,
        pages_extracted=metrics.pages_after_clean,
        chunks_written=len(chunks),
        used_ocr=used_ocr,
        chunk_ids=chunk_ids,
        metrics=metrics,
    )


# Make the imported settings symbol observable for callers that want the
# active embedding model / dimension without a separate import.
_ = settings  # silence unused-import warnings if any tooling complains
