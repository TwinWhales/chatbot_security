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

    # 같은 tool_id 의 여러 ToolAnalysis 를 하나로 머지 (도구가 여러 evidence
    # 파일에 호출되면 analysis 도 N개씩 옴 — 단순히 마지막을 쓰면 다른 결과를
    # 덮어쓰게 됨). findings 는 누적, case/llm 플래그는 가장 상위 결과 유지.
    merged_analyses: dict[str, ToolAnalysis] = {}
    for a in analyses:
        existing = merged_analyses.get(a.tool_id)
        if existing is None:
            merged_analyses[a.tool_id] = ToolAnalysis(
                tool_id=a.tool_id,
                findings=list(a.findings),
                summary=a.summary,
                case_used=a.case_used,
                llm_invoked=a.llm_invoked,
                llm_failed=a.llm_failed,
            )
        else:
            existing.findings.extend(a.findings)
            existing.llm_invoked = existing.llm_invoked or a.llm_invoked
            existing.llm_failed = existing.llm_failed or a.llm_failed
            # case 는 더 보수적인 쪽 (A < B < C) 유지.
            order = {"A": 0, "B": 1, "C": 2}
            if order.get(a.case_used, 0) > order.get(existing.case_used, 0):
                existing.case_used = a.case_used

    # summary 재생성 (머지 후 정확한 카운트).
    for a in merged_analyses.values():
        from forensicagent.analyzer.types import by_severity_count
        cnt = by_severity_count(a.findings)
        sev = (
            f"critical={cnt['critical']} high={cnt['high']} "
            f"medium={cnt['medium']} low={cnt['low']} info={cnt['info']}"
        )
        cat: dict[str, int] = {}
        for f in a.findings:
            cat[f.category] = cat.get(f.category, 0) + 1
        top = ", ".join(f"{k}({v})" for k, v in sorted(cat.items(), key=lambda x: -x[1])[:3]) or "n/a"
        a.summary = f"{len(a.findings)} findings ({sev}); top: {top}"

    for a in merged_analyses.values():
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
