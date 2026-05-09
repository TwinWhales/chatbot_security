"""Attach search/filter metadata to each chunk."""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from src.ingestion.chunker import Chunk


def tag(
    chunks: list[Chunk],
    source_path: str | Path,
    file_type: str,
) -> list[dict[str, Any]]:
    source = Path(source_path)
    now = datetime.now(timezone.utc).isoformat()

    metas: list[dict[str, Any]] = []
    for chunk in chunks:
        preview = chunk.text[:100].replace("\n", " ")
        metas.append(
            {
                "source_file": source.name,
                "source_path": str(source),
                "page_number": chunk.page_number,
                "chunk_index": chunk.chunk_index,
                "created_at": now,
                "file_type": file_type,
                "content_preview": preview,
            }
        )
    return metas
