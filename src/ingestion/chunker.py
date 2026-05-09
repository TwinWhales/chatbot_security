"""Split cleaned page text into overlapping chunks for embedding.

Uses LangChain's RecursiveCharacterTextSplitter, which prefers paragraph and
sentence boundaries before falling back to character splits — this matches
the spec's "재귀적 분할" option while still honoring CHUNK_SIZE/OVERLAP.
"""

from __future__ import annotations

from dataclasses import dataclass

from langchain_text_splitters import RecursiveCharacterTextSplitter

from config import settings
from src.ingestion.pdf_extractor import PageText


@dataclass
class Chunk:
    text: str
    page_number: int
    chunk_index: int   # ordinal within the source document


def _make_splitter(chunk_size: int, chunk_overlap: int) -> RecursiveCharacterTextSplitter:
    return RecursiveCharacterTextSplitter(
        chunk_size=chunk_size,
        chunk_overlap=chunk_overlap,
        # English + Korean friendly separators.
        separators=["\n\n", "\n", "。", ".", "?", "!", " ", ""],
    )


def split(
    pages: list[PageText],
    chunk_size: int | None = None,
    chunk_overlap: int | None = None,
) -> list[Chunk]:
    splitter = _make_splitter(
        chunk_size or settings.CHUNK_SIZE,
        chunk_overlap or settings.CHUNK_OVERLAP,
    )

    chunks: list[Chunk] = []
    running_index = 0
    for page in pages:
        if not page.text.strip():
            continue
        for piece in splitter.split_text(page.text):
            piece = piece.strip()
            if not piece:
                continue
            chunks.append(
                Chunk(
                    text=piece,
                    page_number=page.page_number,
                    chunk_index=running_index,
                )
            )
            running_index += 1
    return chunks
