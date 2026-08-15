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
from typing import Iterable

from forensicagent.observability import Stopwatch
from forensicagent.scanner.detectors import detect
from forensicagent.scanner.types import Evidence, Inventory

logger = logging.getLogger(__name__)

DEFAULT_MAX_DEPTH = 5
# scan() 의 크기 상한 게이트. 이 값을 넘는 파일은 검사하지 않고 skipped_files
# 로만 집계한다 (거대 파일이 스캔을 느리게 만드는 경우 방어). 0 = 무제한.
MAX_FILE_SIZE_BYTES = 0

# Directories to never descend into.
_IGNORE_DIRS = {
    ".git",
    ".hg",
    ".svn",
    ".pytest_cache",
    "__pycache__",
    "node_modules",
    ".venv",
    "venv",
    "build",
    "dist",
    "forensicagent_output",
}


def _is_excluded(path: Path, excludes: tuple[Path, ...]) -> bool:
    """Whether path is an explicitly excluded path or one of its descendants."""
    # Scandir paths are already absolute.  abspath normalizes ``..`` without
    # touching the filesystem, unlike resolve() which is costly for every file
    # (especially on OneDrive/network-backed evidence trees).
    normalized = Path(os.path.abspath(path))
    return any(normalized == base or normalized.is_relative_to(base) for base in excludes)


def _walk(
    root: Path,
    max_depth: int,
    exclude_paths: tuple[Path, ...] = (),
) -> tuple[list[Path], bool]:
    """심볼릭 링크 무시 + 깊이 제한 BFS.

    Returns:
        (files, depth_limit_hit).
        depth_limit_hit 은 max_depth 때문에 실제로 하위 디렉토리 하강을
        끊은 적이 있으면 True — 이 경우 더 깊은 증거를 놓쳤을 수 있다.
        (_IGNORE_DIRS 로 의도적으로 건너뛴 디렉토리는 여기 포함하지 않는다.)
    """
    files: list[Path] = []
    depth_limit_hit = False
    root = root.resolve()

    stack: list[tuple[Path, int]] = [(root, 0)]
    while stack:
        cur, depth = stack.pop()
        if _is_excluded(cur, exclude_paths):
            continue
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
                if _is_excluded(p, exclude_paths):
                    continue
                if entry.is_dir(follow_symlinks=False):
                    if entry.name.casefold() in _IGNORE_DIRS:
                        continue
                    if depth + 1 <= max_depth:
                        stack.append((p, depth + 1))
                    else:
                        # max_depth 초과로 이 디렉토리를 하강하지 못함.
                        depth_limit_hit = True
                elif entry.is_file(follow_symlinks=False):
                    files.append(p)
            except OSError:
                continue
    return files, depth_limit_hit


def scan(
    root: str | Path,
    *,
    max_depth: int = DEFAULT_MAX_DEPTH,
    include_unknown: bool = True,
    exclude_paths: Iterable[str | Path] | None = None,
    stage_ms: dict[str, int] | None = None,
) -> Inventory:
    """CWD 또는 지정 디렉토리를 스캔해 Evidence 인벤토리 반환.

    Args:
        root: 스캔 시작점.
        max_depth: 디렉토리 재귀 깊이 제한 (root 자체는 depth 0).
        include_unknown: 식별 실패한 파일도 인벤토리에 unknown 으로 남길지.
        exclude_paths: 스캔하지 않을 파일/디렉터리. 상대 경로는 root 기준이며,
            디렉터리를 지정하면 모든 하위 경로를 탐색 단계에서 제외한다.
        stage_ms: observability 누적 dict 가 있으면 "scan_walk", "scan_detect" 기록.

    Returns:
        Inventory.
    """
    root_path = Path(root).resolve()
    inv = Inventory(scan_root=str(root_path))

    if not root_path.exists():
        logger.warning("scan root does not exist: %s", root_path)
        return inv

    exclude_base = root_path if root_path.is_dir() else root_path.parent
    normalized_excludes: list[Path] = []
    for raw in exclude_paths or ():
        candidate = Path(raw)
        if not candidate.is_absolute():
            candidate = exclude_base / candidate
        normalized_excludes.append(Path(os.path.abspath(candidate)))
    excludes = tuple(normalized_excludes)

    with Stopwatch() as sw_walk:
        if root_path.is_file():
            files = [] if _is_excluded(root_path, excludes) else [root_path]
            depth_limit_hit = False
        else:
            files, depth_limit_hit = _walk(root_path, max_depth, excludes)
    inv.depth_limit_hit = depth_limit_hit
    if stage_ms is not None:
        stage_ms["scan_walk"] = stage_ms.get("scan_walk", 0) + sw_walk.elapsed_ms

    with Stopwatch() as sw_detect:
        for p in files:
            try:
                size = p.stat().st_size
            except OSError:
                inv.skipped_files += 1
                continue
            # 크기 상한 게이트 (0 = 무제한). 초과 파일은 검사하지 않고 skip 로 집계.
            if MAX_FILE_SIZE_BYTES > 0 and size > MAX_FILE_SIZE_BYTES:
                logger.debug("skip oversized %s (%d bytes)", p, size)
                inv.skipped_files += 1
                continue
            inv.scanned_files += 1

            hit = detect(p)
            if hit is None:
                inv.unidentified_files += 1
                if include_unknown:
                    inv.evidence_list.append(
                        Evidence(
                            path=str(p),
                            filename=p.name,
                            size_bytes=size,
                            evidence_type="unknown",
                            detected_by="unclassified",
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
