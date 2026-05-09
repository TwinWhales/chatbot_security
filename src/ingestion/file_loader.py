"""File ingestion entrypoint: copy upload to ./data/raw and classify it.

명세 1.1 / 1.2 — 직접 구현해보세요.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from config import settings


PDF_EXTS = {".pdf"}
TEXT_EXTS = {".txt", ".md", ".markdown"}
DOCX_EXTS = {".docx"}


@dataclass
class LoadedFile:
    path: Path        # data/raw 안의 정규화된 위치
    file_type: str    # "pdf" | "txt" | "md" | "docx" | "unknown"


def classify(path: Path) -> str:
    """확장자로 file_type 을 결정한다.

    TODO:
      - path.suffix.lower() 를 PDF_EXTS / TEXT_EXTS / DOCX_EXTS 와 비교
      - 매칭되지 않으면 "unknown"
    """
    raise NotImplementedError("classify(path) — 확장자 기반 분류 구현하기")


def load(source: str | Path) -> LoadedFile:
    """파일을 ./data/raw 로 복사하고 LoadedFile 로 감싼다.

    TODO:
      1. Path(source).resolve() — 절대 경로화
      2. 존재하지 않으면 FileNotFoundError
      3. settings.RAW_DIR 안에 이미 있으면 복사 생략
      4. 그 외엔 shutil.copy2 로 복사
      5. classify(dest) 로 file_type 결정 후 LoadedFile 반환
    """
    raise NotImplementedError("load(source) — raw 디렉토리 복사 + classify 구현하기")
