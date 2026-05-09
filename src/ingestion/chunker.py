"""Split cleaned page text into overlapping chunks for embedding.

명세 1.7 — 직접 구현해보세요. RecursiveCharacterTextSplitter 권장.
"""

from __future__ import annotations

from dataclasses import dataclass

from config import settings
from src.ingestion.pdf_extractor import PageText


@dataclass
class Chunk:
    text: str
    page_number: int
    chunk_index: int   # 문서 전역 순번


def split(
    pages: list[PageText],
    chunk_size: int | None = None,
    chunk_overlap: int | None = None,
) -> list[Chunk]:
    """페이지들을 chunk_size / chunk_overlap 기준으로 분할한다.

    TODO:
      1. langchain_text_splitters.RecursiveCharacterTextSplitter 사용
         - separators 우선순위: ["\\n\\n", "\\n", "。", ".", "?", "!", " ", ""]
         - chunk_size, chunk_overlap 은 인자 또는 settings 의 값
      2. 각 page.text 를 splitter.split_text 로 잘라
         Chunk(text, page_number, chunk_index) 로 감싸기
      3. chunk_index 는 문서 전체에서 0 부터 증가하는 순번
      4. 빈 청크 (strip 후 빈 문자열) 는 결과에서 제외
    """
    raise NotImplementedError("split(pages) — chunk 분할 구현하기")
