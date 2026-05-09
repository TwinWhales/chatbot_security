"""Strip noise from extracted text before chunking."""

from __future__ import annotations

import re
import unicodedata
from collections import Counter

from src.ingestion.pdf_extractor import PageText


_WS_RUN = re.compile(r"[ \t]+")
_BLANKLINES = re.compile(r"\n{3,}")
# Common form-feed and PDF artifacts.
_CTRL = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f]")


def _normalize_unicode(text: str) -> str:
    return unicodedata.normalize("NFKC", text)


def _detect_repeating_lines(pages: list[PageText], min_repeats: int) -> set[str]:
    """Lines that appear on a majority of pages are likely headers/footers."""
    if len(pages) < 3:
        return set()
    counter: Counter[str] = Counter()
    for page in pages:
        # Look at first/last few lines only — body content rarely repeats verbatim.
        lines = [ln.strip() for ln in page.text.splitlines() if ln.strip()]
        for ln in lines[:3] + lines[-3:]:
            counter[ln] += 1
    return {line for line, n in counter.items() if n >= min_repeats}


def clean_pages(pages: list[PageText]) -> list[PageText]:
    if not pages:
        return pages
    repeating = _detect_repeating_lines(
        pages, min_repeats=max(3, int(len(pages) * 0.6))
    )

    cleaned: list[PageText] = []
    for page in pages:
        text = _normalize_unicode(page.text)
        text = _CTRL.sub("", text)

        if repeating:
            kept = [
                ln for ln in text.splitlines()
                if ln.strip() not in repeating
            ]
            text = "\n".join(kept)

        # Collapse runs of intra-line whitespace and excess blank lines.
        text = _WS_RUN.sub(" ", text)
        text = _BLANKLINES.sub("\n\n", text)
        text = text.strip()

        if len(text) >= 1:
            cleaned.append(PageText(page_number=page.page_number, text=text))

    return cleaned
