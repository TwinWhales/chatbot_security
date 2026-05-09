"""pdfplumber-based PDF text extractor.

Returns one entry per page so we can preserve page numbers in metadata
and decide per-page whether OCR is needed (some PDFs are partly scanned).
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path


@dataclass
class PageText:
    page_number: int   # 1-indexed
    text: str


def extract(path: str | Path) -> list[PageText]:
    # Lazy import so non-PDF code paths (and tests) don't require pdfplumber.
    import pdfplumber

    pages: list[PageText] = []
    with pdfplumber.open(str(path)) as pdf:
        for i, page in enumerate(pdf.pages, start=1):
            try:
                text = page.extract_text() or ""
            except Exception:
                text = ""
            pages.append(PageText(page_number=i, text=text))
    return pages


def looks_empty(pages: list[PageText]) -> bool:
    """True when extraction yielded essentially nothing — caller should OCR."""
    total = sum(len(p.text.strip()) for p in pages)
    return total < 20
