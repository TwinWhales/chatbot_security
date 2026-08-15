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


def test_scan_accepts_a_file_root(tmp_path):
    target = tmp_path / "Security.evtx"
    _write(target, b"ElfFile\x00" + b"\x00" * 32)

    inv = scan(target)

    assert inv.scanned_files == 1
    assert len(inv.evidence_list) == 1
    assert inv.evidence_list[0].path == str(target.resolve())
    assert inv.evidence_list[0].evidence_type == "evtx_log"


def test_unknown_provenance_is_unclassified(tmp_path):
    _write(tmp_path / "unknown.xyz", b"not a known format")

    inv = scan(tmp_path)

    assert len(inv.evidence_list) == 1
    assert inv.unidentified_files == 1
    assert inv.evidence_list[0].evidence_type == "unknown"
    assert inv.evidence_list[0].detected_by == "unclassified"
    assert inv.to_dict()["unidentified_files"] == 1


def test_unidentified_count_survives_unknown_inventory_filter(tmp_path):
    _write(tmp_path / "unknown.xyz", b"not a known format")

    inv = scan(tmp_path, include_unknown=False)

    assert inv.scanned_files == 1
    assert inv.unidentified_files == 1
    assert inv.evidence_list == []


def test_exclude_paths_prunes_directory_descendants(tmp_path):
    _write(tmp_path / "case" / "Security.evtx", b"ElfFile\x00" + b"\x00" * 8)
    _write(tmp_path / "output" / "copied.evtx", b"ElfFile\x00" + b"\x00" * 8)

    inv = scan(tmp_path, exclude_paths=["output"])
    names = {Path(e.path).name for e in inv.evidence_list}

    assert names == {"Security.evtx"}


def test_exclude_paths_can_skip_a_file(tmp_path):
    _write(tmp_path / "keep.txt")
    _write(tmp_path / "skip.txt")

    inv = scan(tmp_path, exclude_paths=[tmp_path / "skip.txt"])
    names = {Path(e.path).name for e in inv.evidence_list}

    assert names == {"keep.txt"}


def test_default_generated_directories_are_ignored(tmp_path):
    for dirname in (".pytest_cache", "build", "dist", "forensicagent_output"):
        _write(tmp_path / dirname / f"{dirname.strip('.')}.txt")
    _write(tmp_path / "case.txt")

    inv = scan(tmp_path)
    names = {Path(e.path).name for e in inv.evidence_list}

    assert names == {"case.txt"}
