"""OCR fallback for scanned PDFs.

명세 1.4 — 직접 구현해보세요. pdf_extractor 가 실패한 PDF 에 대해서만 호출됨.
"""

from __future__ import annotations

from pathlib import Path

from config import settings
from src.ingestion.pdf_extractor import PageText


def _configure_tesseract(pytesseract) -> None:
    """settings.TESSERACT_CMD 가 설정돼 있으면 pytesseract 에 경로를 주입한다.

    TODO:
      - settings.TESSERACT_CMD 가 truthy 일 때
        pytesseract.pytesseract.tesseract_cmd = settings.TESSERACT_CMD
    """
    raise NotImplementedError("_configure_tesseract — tesseract 바이너리 경로 주입")


def extract(path: str | Path, dpi: int = 200) -> list[PageText]:
    """스캔된 PDF 를 OCR 로 텍스트화한다.

    TODO:
      1. pytesseract / pdf2image 를 함수 내부 lazy import
      2. _configure_tesseract(pytesseract) 호출
      3. pdf2image.convert_from_path(path, dpi=dpi) 로 페이지 → 이미지
      4. 이미지마다 pytesseract.image_to_string(img, lang=settings.OCR_LANGUAGES)
      5. PageText(page_number, text) 의 list 로 반환
    """
    raise NotImplementedError("extract(path, dpi) — OCR 추출 구현하기")
