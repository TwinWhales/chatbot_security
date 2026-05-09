"""pdfplumber-based PDF text extractor.

명세 1.3 — 직접 구현해보세요.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path


@dataclass
class PageText:
    page_number: int   # 1-indexed
    text: str


def extract(path: str | Path) -> list[PageText]:
    """PDF 의 각 페이지에서 텍스트를 추출한다.

    TODO:
      - pdfplumber 를 함수 내부에서 lazy import
      - pdfplumber.open(path) 로 PDF 열기
      - pdf.pages 를 enumerate(start=1) 로 순회
      - page.extract_text() 결과를 PageText 로 감싸 list 로 반환
      - 페이지별 try/except 로 파손된 페이지가 전체를 막지 않게 처리
    """
    raise NotImplementedError("extract(path) — pdfplumber 페이지별 텍스트 추출 구현하기")


def looks_empty(pages: list[PageText]) -> bool:
    """추출 결과가 사실상 비어있는지 판정한다.

    그래프의 conditional edge 가 이 결과로 OCR 분기 여부를 결정한다.

    TODO:
      - 모든 페이지의 text.strip() 길이 합이 임계값(예: 20) 미만이면 True
    """
    raise NotImplementedError("looks_empty(pages) — 빈 추출 판정 구현하기")
