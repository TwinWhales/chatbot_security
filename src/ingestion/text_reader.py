"""Reader for non-PDF formats: TXT, MD, DOCX."""

from __future__ import annotations

from pathlib import Path

from src.ingestion.pdf_extractor import PageText


def read_txt(path: Path) -> str:
    return path.read_text(encoding="utf-8", errors="replace")


def read_docx(path: Path) -> str:
    # python-docx flattens to paragraphs; we join with newlines so the
    # cleaner can collapse them later.
    from docx import Document  # imported lazily so docx is optional at import time

    doc = Document(str(path))
    parts: list[str] = []
    for para in doc.paragraphs:
        if para.text:
            parts.append(para.text)
    for table in doc.tables:
        for row in table.rows:
            cells = [c.text.strip() for c in row.cells if c.text]
            if cells:
                parts.append("\t".join(cells))
    return "\n".join(parts)


def read(path: str | Path, file_type: str) -> list[PageText]:
    """Return a single 'page' for non-paginated formats."""
    p = Path(path)
    if file_type in ("txt", "md"):
        text = read_txt(p)
    elif file_type == "docx":
        text = read_docx(p)
    else:
        raise ValueError(f"Unsupported file_type for text_reader: {file_type}")
    return [PageText(page_number=1, text=text)]
