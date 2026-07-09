"""Scanner scan() — 깊이 제한 추적 + 크기 게이트 테스트.

LLM / 네트워크 없이 임시 디렉토리 트리로만 결정론 검증.
  * depth_limit_hit: max_depth 로 하위 디렉토리 하강을 끊으면 True,
    아니면 False (이전엔 항상 False 로 거짓 보고하던 버그).
  * MAX_FILE_SIZE_BYTES: 상한 초과 파일은 scanned 가 아니라 skipped 로 집계.
"""

from __future__ import annotations

from pathlib import Path

from forensicagent.scanner import scanner
from forensicagent.scanner.scanner import scan


def _write(p: Path, content: bytes = b"hello") -> None:
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_bytes(content)


# ---- depth_limit_hit ----

def test_depth_limit_hit_true_when_tree_deeper_than_max_depth(tmp_path):
    # root(0) -> sub1(1) -> sub2(2)/deep.txt.  max_depth=1 이면 sub2 하강 불가.
    _write(tmp_path / "sub1" / "sub2" / "deep.txt")
    inv = scan(tmp_path, max_depth=1)
    assert inv.depth_limit_hit is True
    assert inv.to_dict()["depth_limit_hit"] is True


def test_depth_limit_hit_false_when_within_max_depth(tmp_path):
    _write(tmp_path / "sub1" / "sub2" / "deep.txt")
    inv = scan(tmp_path, max_depth=5)
    assert inv.depth_limit_hit is False
    # 깊은 파일이 실제로 스캔됐는지 (하강이 안 끊겼다는 증거).
    names = {Path(e.path).name for e in inv.evidence_list}
    assert "deep.txt" in names


def test_depth_limit_hit_false_on_flat_dir(tmp_path):
    _write(tmp_path / "a.txt")
    _write(tmp_path / "b.txt")
    inv = scan(tmp_path, max_depth=3)
    assert inv.depth_limit_hit is False


def test_ignored_dirs_do_not_trigger_depth_limit(tmp_path):
    # __pycache__ 는 _IGNORE_DIRS 라 의도적 skip — depth 초과와 무관해야 한다.
    _write(tmp_path / "__pycache__" / "x.pyc")
    _write(tmp_path / "top.txt")
    inv = scan(tmp_path, max_depth=1)
    assert inv.depth_limit_hit is False


# ---- MAX_FILE_SIZE_BYTES 크기 게이트 ----

def test_oversized_file_counted_as_skipped(tmp_path, monkeypatch):
    monkeypatch.setattr(scanner, "MAX_FILE_SIZE_BYTES", 10)
    _write(tmp_path / "small.txt", b"tiny")          # 4 bytes → scanned
    _write(tmp_path / "big.bin", b"x" * 100)         # 100 bytes → skipped
    inv = scan(tmp_path, max_depth=2)
    assert inv.skipped_files >= 1
    names = {Path(e.path).name for e in inv.evidence_list}
    assert "big.bin" not in names
    assert "small.txt" in names


def test_zero_limit_means_no_size_gate(tmp_path, monkeypatch):
    monkeypatch.setattr(scanner, "MAX_FILE_SIZE_BYTES", 0)
    _write(tmp_path / "big.bin", b"x" * 100_000)
    inv = scan(tmp_path, max_depth=2)
    names = {Path(e.path).name for e in inv.evidence_list}
    assert "big.bin" in names
