"""CWD recursive scanner.

명세 2.1 의 구현 주의사항을 그대로 코드로:
  - 깊이 제한 (기본 5)
  - 심볼릭 링크 따라가지 않음
  - 큰 파일도 헤더만 읽음 (detectors 가 32 바이트만 읽도록 설계됨)
  - 식별 불가는 unknown 으로 두되 인벤토리에 포함시켜 사용자가 인지하게.
"""

from __future__ import annotations

import logging
import os
from pathlib import Path

from forensicagent.observability import Stopwatch
from forensicagent.scanner.detectors import detect
from forensicagent.scanner.types import Evidence, Inventory

logger = logging.getLogger(__name__)

DEFAULT_MAX_DEPTH = 5
# Skip files larger than this when reading magic bytes (we already read only
# the first 32 bytes, so this is mostly a safety net for weird FS reports).
# A 0 means no upper bound — we still header-read regardless of size.
MAX_FILE_SIZE_BYTES = 0

# Directories to never descend into.
_IGNORE_DIRS = {".git", ".hg", ".svn", "__pycache__", "node_modules", ".venv", "venv"}


def _walk(root: Path, max_depth: int) -> list[Path]:
    """심볼릭 링크 무시 + 깊이 제한 BFS."""
    files: list[Path] = []
    root = root.resolve()

    stack: list[tuple[Path, int]] = [(root, 0)]
    while stack:
        cur, depth = stack.pop()
        try:
            entries = list(os.scandir(cur))
        except (OSError, PermissionError) as e:
            logger.debug("skip %s: %s", cur, e)
            continue

        for entry in entries:
            try:
                # Reject symlinks — both files and dirs — to avoid loops.
                if entry.is_symlink():
                    continue
                p = Path(entry.path)
                if entry.is_dir(follow_symlinks=False):
                    if entry.name in _IGNORE_DIRS:
                        continue
                    if depth + 1 <= max_depth:
                        stack.append((p, depth + 1))
                elif entry.is_file(follow_symlinks=False):
                    files.append(p)
            except OSError:
                continue
    return files


def scan(
    root: str | Path,
    *,
    max_depth: int = DEFAULT_MAX_DEPTH,
    include_unknown: bool = True,
    stage_ms: dict[str, int] | None = None,
) -> Inventory:
    """CWD 또는 지정 디렉토리를 스캔해 Evidence 인벤토리 반환.

    Args:
        root: 스캔 시작점.
        max_depth: 디렉토리 재귀 깊이 제한 (root 자체는 depth 0).
        include_unknown: 식별 실패한 파일도 인벤토리에 unknown 으로 남길지.
        stage_ms: observability 누적 dict 가 있으면 "scan_walk", "scan_detect" 기록.

    Returns:
        Inventory.
    """
    root_path = Path(root).resolve()
    inv = Inventory(scan_root=str(root_path))

    if not root_path.exists():
        logger.warning("scan root does not exist: %s", root_path)
        return inv

    with Stopwatch() as sw_walk:
        files = _walk(root_path, max_depth)
    if stage_ms is not None:
        stage_ms["scan_walk"] = stage_ms.get("scan_walk", 0) + sw_walk.elapsed_ms

    with Stopwatch() as sw_detect:
        for p in files:
            try:
                size = p.stat().st_size
            except OSError:
                inv.skipped_files += 1
                continue
            inv.scanned_files += 1

            hit = detect(p)
            if hit is None:
                if include_unknown:
                    inv.evidence_list.append(
                        Evidence(
                            path=str(p),
                            filename=p.name,
                            size_bytes=size,
                            evidence_type="unknown",
                            detected_by="extension",
                            platform_hint="unknown",
                            confidence=0.0,
                        )
                    )
                continue
            etype, plat, conf, method = hit
            inv.evidence_list.append(
                Evidence(
                    path=str(p),
                    filename=p.name,
                    size_bytes=size,
                    evidence_type=etype,
                    detected_by=method,
                    platform_hint=plat,
                    confidence=conf,
                )
            )
    if stage_ms is not None:
        stage_ms["scan_detect"] = stage_ms.get("scan_detect", 0) + sw_detect.elapsed_ms

    return inv
