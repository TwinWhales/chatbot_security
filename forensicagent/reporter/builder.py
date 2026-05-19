"""Report builder — Scanner / Selector / Executor / Analyzer 결과를 한 묶음으로."""

from __future__ import annotations

import platform
from collections import defaultdict

from forensicagent import __version__
from forensicagent.analyzer.types import ToolAnalysis
from forensicagent.executor.types import ExecutionBundle
from forensicagent.reporter.types import (
    Report,
    ReportMeta,
    Summary,
    ToolBundle,
    now_iso,
)
from forensicagent.scanner.types import Inventory
from forensicagent.selector.types import Plan


def _host_info() -> dict[str, str]:
    return {
        "system": platform.system(),
        "release": platform.release(),
        "machine": platform.machine(),
        "python": platform.python_version(),
    }


def build(
    *,
    inventory: Inventory,
    plan: Plan,
    execution: ExecutionBundle,
    analyses: list[ToolAnalysis],
    started_at: str,
    working_directory: str,
    stage_ms: dict[str, int] | None = None,
) -> Report:
    """모든 단계 결과를 하나의 Report 로 묶는다."""
    finished_at = now_iso()
    meta = ReportMeta(
        version=__version__,
        started_at=started_at,
        finished_at=finished_at,
        working_directory=working_directory,
        host_info=_host_info(),
    )

    # tool_id → bundle 누적.
    bundle_map: dict[str, ToolBundle] = {}
    for r in execution.results:
        b = bundle_map.setdefault(r.tool_id, ToolBundle(tool_id=r.tool_id))
        b.execution.append(r)
    for a in analyses:
        b = bundle_map.setdefault(a.tool_id, ToolBundle(tool_id=a.tool_id))
        b.analysis = a

    # plan 의 순서를 유지하면서 정렬, 미등장 도구는 뒤에 append.
    ordered: list[ToolBundle] = []
    seen: set[str] = set()
    for sel in plan.selected_tools:
        b = bundle_map.get(sel.tool_id)
        if b is not None:
            ordered.append(b)
            seen.add(sel.tool_id)
    for tid, b in bundle_map.items():
        if tid not in seen:
            ordered.append(b)

    # ---- summary aggregation ----
    by_sev: dict[str, int] = defaultdict(int)
    by_cat: dict[str, int] = defaultdict(int)
    total = 0
    for b in ordered:
        if b.analysis is None:
            continue
        for f in b.analysis.findings:
            by_sev[f.severity] += 1
            by_cat[f.category] += 1
            total += 1

    tools_run = sum(1 for b in ordered if any(e.status == "success" for e in b.execution))
    tools_failed = sum(
        1 for b in ordered if any(e.status in ("failed", "timeout") for e in b.execution)
    )
    tools_skipped = sum(
        1 for b in ordered if all(e.status == "skipped" for e in b.execution)
    )
    total_ms = sum((stage_ms or {}).values())

    summary = Summary(
        total_findings=total,
        by_severity=dict(by_sev),
        by_category=dict(by_cat),
        tools_run=tools_run,
        tools_failed=tools_failed,
        tools_skipped=tools_skipped,
        total_ms=total_ms,
    )

    return Report(
        meta=meta,
        evidence_inventory=inventory,
        execution_plan=plan,
        tool_bundles=ordered,
        summary=summary,
        stage_ms=dict(stage_ms or {}),
    )
