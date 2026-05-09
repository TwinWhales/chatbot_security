"""OCR fallback for scanned PDFs.

pdf2image rasterizes each page; pytesseract runs OCR on the raster.
The Tesseract binary must be installed separately (see TESSERACT_CMD).
"""

from __future__ import annotations

from pathlib import Path

from config import settings
from src.ingestion.pdf_extractor import PageText


def _configure_tesseract(pytesseract) -> None:
    if settings.TESSERACT_CMD:
        pytesseract.pytesseract.tesseract_cmd = settings.TESSERACT_CMD


def extract(path: str | Path, dpi: int = 200) -> list[PageText]:
    # Lazy imports — OCR is rarely needed and the deps are heavy.
    import pytesseract
    from pdf2image import convert_from_path

    _configure_tesseract(pytesseract)
    images = convert_from_path(str(path), dpi=dpi)
    pages: list[PageText] = []
    for i, image in enumerate(images, start=1):
        text = pytesseract.image_to_string(image, lang=settings.OCR_LANGUAGES)
        pages.append(PageText(page_number=i, text=text or ""))
    return pages
