"""Reporter types — 명세 2.5 의 리포트 스키마."""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

from forensicagent.analyzer.types import Finding, ToolAnalysis, by_severity_count
from forensicagent.executor.types import ExecutionResult
from forensicagent.scanner.types import Inventory
from forensicagent.selector.types import Plan


@dataclass
class ReportMeta:
    version: str = "0.0.1"
    run_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    started_at: str = ""
    finished_at: str = ""
    working_directory: str = ""
    host_info: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "version": self.version,
            "run_id": self.run_id,
            "started_at": self.started_at,
            "finished_at": self.finished_at,
            "working_directory": self.working_directory,
            "host_info": dict(self.host_info),
        }


@dataclass
class ToolBundle:
    tool_id: str
    execution: list[ExecutionResult] = field(default_factory=list)
    analysis: ToolAnalysis | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "tool_id": self.tool_id,
            "execution": [e.to_dict() for e in self.execution],
            "analysis": self.analysis.to_dict() if self.analysis else None,
        }


@dataclass
class Summary:
    total_findings: int = 0
    by_severity: dict[str, int] = field(default_factory=dict)
    by_category: dict[str, int] = field(default_factory=dict)
    tools_run: int = 0
    tools_failed: int = 0
    tools_skipped: int = 0
    total_ms: int = 0
    finding_limit_reached: bool = False
    coverage_truncated: bool = False
    depth_limit_hit: bool = False
    unreadable_paths: int = 0
    reparse_paths: int = 0

    def to_dict(self) -> dict[str, Any]:
        return {
            "total_findings": self.total_findings,
            "by_severity": dict(self.by_severity),
            "by_category": dict(self.by_category),
            "tools_run": self.tools_run,
            "tools_failed": self.tools_failed,
            "tools_skipped": self.tools_skipped,
            "total_ms": self.total_ms,
            "finding_limit_reached": self.finding_limit_reached,
            "coverage_truncated": self.coverage_truncated,
            "depth_limit_hit": self.depth_limit_hit,
            "unreadable_paths": self.unreadable_paths,
            "reparse_paths": self.reparse_paths,
        }


@dataclass
class Report:
    meta: ReportMeta = field(default_factory=ReportMeta)
    evidence_inventory: Inventory | None = None
    execution_plan: Plan | None = None
    tool_bundles: list[ToolBundle] = field(default_factory=list)
    summary: Summary = field(default_factory=Summary)
    stage_ms: dict[str, int] = field(default_factory=dict)

    def all_findings(self) -> list[Finding]:
        out: list[Finding] = []
        for b in self.tool_bundles:
            if b.analysis:
                out.extend(b.analysis.findings)
        return out

    def to_dict(self) -> dict[str, Any]:
        return {
            "meta": self.meta.to_dict(),
            "evidence_inventory": self.evidence_inventory.to_dict()
            if self.evidence_inventory
            else None,
            "execution_plan": self.execution_plan.to_dict()
            if self.execution_plan
            else None,
            "tool_results": [b.to_dict() for b in self.tool_bundles],
            "summary": self.summary.to_dict(),
            "stage_ms": dict(self.stage_ms),
        }


def now_iso() -> str:
    return datetime.now(tz=timezone.utc).isoformat(timespec="seconds")
