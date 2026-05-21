"""Scanner output types.

Evidence 인벤토리는 Scanner → Selector 의 유일한 인터페이스이므로
필드를 함부로 바꾸면 안 된다. 명세 2.1 의 출력 스키마를 그대로 따른다.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Literal

EvidenceType = Literal[
    "memory_dump",
    "evtx_log",
    "registry_hive",
    "pcap",
    "disk_image",
    "browser_artifact",
    "prefetch",
    "text_log",
    # 코드 보안 (정적 분석 도구가 소비)
    "source_code_python",
    "source_code_javascript",
    "source_code_generic",
    "unknown",
]

DetectionMethod = Literal["magic_bytes", "extension", "filename_pattern", "parent_dir"]
Platform = Literal["windows", "linux", "macos", "unknown"]


@dataclass
class Evidence:
    path: str
    filename: str
    size_bytes: int
    evidence_type: EvidenceType
    detected_by: DetectionMethod
    platform_hint: Platform = "unknown"
    confidence: float = 0.5

    def to_dict(self) -> dict[str, Any]:
        return {
            "path": self.path,
            "filename": self.filename,
            "size_bytes": self.size_bytes,
            "evidence_type": self.evidence_type,
            "detected_by": self.detected_by,
            "platform_hint": self.platform_hint,
            "confidence": self.confidence,
        }


@dataclass
class Inventory:
    evidence_list: list[Evidence] = field(default_factory=list)
    scanned_files: int = 0
    skipped_files: int = 0
    scan_root: str = ""
    depth_limit_hit: bool = False

    def to_dict(self) -> dict[str, Any]:
        return {
            "scan_root": self.scan_root,
            "scanned_files": self.scanned_files,
            "skipped_files": self.skipped_files,
            "depth_limit_hit": self.depth_limit_hit,
            "evidence_list": [e.to_dict() for e in self.evidence_list],
        }

    def by_type(self) -> dict[str, list[Evidence]]:
        out: dict[str, list[Evidence]] = {}
        for e in self.evidence_list:
            out.setdefault(e.evidence_type, []).append(e)
        return out
