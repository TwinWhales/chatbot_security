"""Attach search/filter metadata to each chunk.

명세 1.9 — 직접 구현해보세요.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from src.ingestion.chunker import Chunk


def tag(
    chunks: list[Chunk],
    source_path: str | Path,
    file_type: str,
) -> list[dict[str, Any]]:
    """각 청크에 검색/필터링용 메타데이터를 부착한다.

    TODO: 청크마다 다음 dict 를 만들어 list 로 반환
      - source_file: Path(source_path).name
      - source_path: str(source_path)
      - page_number: chunk.page_number
      - chunk_index: chunk.chunk_index
      - created_at: 현재 UTC ISO-8601 문자열 (datetime.now(timezone.utc).isoformat())
      - file_type: file_type
      - content_preview: chunk.text 의 앞 100자, 줄바꿈은 공백으로 치환
    """
    raise NotImplementedError("tag(chunks, source_path, file_type) — 메타데이터 부착 구현하기")
