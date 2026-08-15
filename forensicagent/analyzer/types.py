"""Analyzer types — 명세 2.4 의 발견사항 스키마."""

from __future__ import annotations

import hashlib
import json
import re
import uuid
from dataclasses import dataclass, field
from typing import Any, Literal

Severity = Literal["info", "low", "medium", "high", "critical"]
SEVERITY_RANK: dict[str, int] = {
    "info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4,
}


@dataclass
class EvidenceRef:
    source_file: str = ""
    event_id: int | None = None
    timestamp: str = ""
    raw_excerpt: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "source_file": self.source_file,
            "event_id": self.event_id,
            "timestamp": self.timestamp,
            "raw_excerpt": self.raw_excerpt,
        }


@dataclass
class Finding:
    finding_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    severity: Severity = "low"
    category: str = "anomaly"
    title: str = ""
    description: str = ""
    evidence_ref: EvidenceRef = field(default_factory=EvidenceRef)
    suggested_followup: str = ""
    source: str = "rule"                  # "rule" | "llm" — 추적용
    # Stable rule identity is separate from the presentation title. Empty
    # defaults keep construction/deserialization of legacy reports compatible.
    rule_id: str = ""
    fingerprint: str = ""
    confidence: float = 1.0

    def __post_init__(self) -> None:
        try:
            self.confidence = max(0.0, min(1.0, float(self.confidence)))
        except (TypeError, ValueError):
            self.confidence = 0.0
        if not self.fingerprint:
            self.refresh_fingerprint()

    def refresh_fingerprint(self) -> str:
        """Recompute the deterministic identity after evidence enrichment."""
        excerpt = re.sub(r"\s+", " ", self.evidence_ref.raw_excerpt).strip()
        canonical = {
            "rule_id": (self.rule_id or self.title).strip().casefold(),
            "source_file": self.evidence_ref.source_file.strip().casefold(),
            "event_id": self.evidence_ref.event_id,
            "timestamp": self.evidence_ref.timestamp.strip(),
            "excerpt": excerpt[:800],
        }
        payload = json.dumps(
            canonical, ensure_ascii=False, sort_keys=True, separators=(",", ":")
        )
        self.fingerprint = hashlib.sha256(payload.encode("utf-8")).hexdigest()
        return self.fingerprint

    def to_dict(self) -> dict[str, Any]:
        return {
            "finding_id": self.finding_id,
            "severity": self.severity,
            "category": self.category,
            "title": self.title,
            "description": self.description,
            "evidence_ref": self.evidence_ref.to_dict(),
            "suggested_followup": self.suggested_followup,
            "source": self.source,
            "rule_id": self.rule_id,
            "fingerprint": self.fingerprint,
            "confidence": self.confidence,
        }


@dataclass
class ToolAnalysis:
    tool_id: str
    findings: list[Finding] = field(default_factory=list)
    summary: str = ""
    case_used: str = "A"                  # "A" small | "B" filtered | "C" chunked
    llm_invoked: bool = False
    llm_failed: bool = False

    def to_dict(self) -> dict[str, Any]:
        return {
            "tool_id": self.tool_id,
            "case_used": self.case_used,
            "llm_invoked": self.llm_invoked,
            "llm_failed": self.llm_failed,
            "summary": self.summary,
            "findings": [f.to_dict() for f in self.findings],
        }


def by_severity_count(findings: list[Finding]) -> dict[str, int]:
    out: dict[str, int] = {k: 0 for k in SEVERITY_RANK}
    for f in findings:
        out[f.severity] = out.get(f.severity, 0) + 1
    return out
