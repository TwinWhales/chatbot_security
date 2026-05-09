"""File ingestion entrypoint: copy upload to ./data/raw and classify it."""

from __future__ import annotations

import shutil
from dataclasses import dataclass
from pathlib import Path

from config import settings


PDF_EXTS = {".pdf"}
TEXT_EXTS = {".txt", ".md", ".markdown"}
DOCX_EXTS = {".docx"}


@dataclass
class LoadedFile:
    path: Path        # canonical location under ./data/raw
    file_type: str    # "pdf" | "txt" | "md" | "docx" | "unknown"


def classify(path: Path) -> str:
    ext = path.suffix.lower()
    if ext in PDF_EXTS:
        return "pdf"
    if ext == ".docx":
        return "docx"
    if ext == ".md" or ext == ".markdown":
        return "md"
    if ext == ".txt":
        return "txt"
    return "unknown"


def load(source: str | Path) -> LoadedFile:
    """Copy a file into ./data/raw (if it isn't already there) and classify."""
    src = Path(source).expanduser().resolve()
    if not src.is_file():
        raise FileNotFoundError(f"Not a file: {src}")

    raw_dir = Path(settings.RAW_DIR).resolve()
    if src.parent == raw_dir:
        dest = src
    else:
        dest = raw_dir / src.name
        if dest.resolve() != src:
            shutil.copy2(src, dest)

    return LoadedFile(path=dest, file_type=classify(dest))
