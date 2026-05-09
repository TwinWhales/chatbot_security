"""Reader for non-PDF formats: TXT, MD, DOCX.

명세 1.5 — 직접 구현해보세요.
"""

from __future__ import annotations

from pathlib import Path

from src.ingestion.pdf_extractor import PageText


def read_txt(path: Path) -> str:
    """TXT/MD 파일을 UTF-8 로 읽고 문자열을 반환한다.

    TODO:
      - path.read_text(encoding="utf-8", errors="replace")
    """
    raise NotImplementedError("read_txt — TXT/MD 읽기 구현하기")


def read_docx(path: Path) -> str:
    """DOCX 의 paragraph 와 table 셀을 평문 텍스트로 풀어낸다.

    TODO:
      - python-docx 의 Document 를 함수 내부에서 lazy import
      - doc.paragraphs 의 text 를 모음
      - doc.tables 의 각 row.cells 텍스트도 \\t join 해서 추가
      - 전체를 \\n 으로 join
    """
    raise NotImplementedError("read_docx — DOCX paragraph/table 읽기 구현하기")


def read(path: str | Path, file_type: str) -> list[PageText]:
    """비-PDF 입력을 PDF 와 같은 PageText[] 자료형으로 통일한다.

    TODO:
      - file_type 이 "txt"/"md" → read_txt
      - file_type 이 "docx" → read_docx
      - 그 외엔 ValueError
      - 결과 텍스트를 PageText(page_number=1, text=...) 로 감싼 단일-요소 리스트로 반환
    """
    raise NotImplementedError("read(path, file_type) — 통합 read 함수 구현하기")
