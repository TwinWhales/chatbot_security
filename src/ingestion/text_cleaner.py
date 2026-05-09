"""Strip noise from extracted text before chunking.

명세 1.6 — 직접 구현해보세요.
"""

from __future__ import annotations

from src.ingestion.pdf_extractor import PageText


def clean_pages(pages: list[PageText]) -> list[PageText]:
    """페이지별로 정제하고, 정제 후 빈 페이지는 제거한다.

    처리 항목 (명세 1.6):
      1. 유니코드 NFKC 정규화
      2. 제어문자 제거 (form-feed, BEL 등)
      3. (선택) 페이지 수가 충분할 때 첫/끝 N 줄에서 반복되는 라인을
         header/footer 로 보고 제거
      4. 연속 공백/탭 → 단일 스페이스
      5. 3줄 이상 연속된 빈 줄 → 2줄로 축약

    TODO:
      - re.compile, unicodedata.normalize, collections.Counter 활용
      - 정제 결과 길이가 0 인 페이지는 출력에서 제외
    """
    raise NotImplementedError("clean_pages — 텍스트 정제 구현하기")
