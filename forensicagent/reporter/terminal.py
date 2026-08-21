"""Rich terminal renderer for Report."""

from __future__ import annotations

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from forensicagent.analyzer.types import SEVERITY_RANK, Finding
from forensicagent.reporter.types import Report
from forensicagent.ui_text import safe_text as _safe_text

_SEV_COLORS = {
    "critical": "bright_red",
    "high": "red",
    "medium": "yellow",
    "low": "blue",
    "info": "dim",
}


def _sev_text(sev: str) -> Text:
    return Text(sev, style=_SEV_COLORS.get(sev, "white"))


def render_summary(
    report: Report,
    console: Console,
    *,
    max_findings: int = 5,
    include_finding_details: bool = True,
) -> None:
    """Render a compact, deterministic view of an already-built report."""
    s = report.summary
    evidence_count = len(report.evidence_inventory.evidence_list) if report.evidence_inventory else 0
    severity_line = ", ".join(
        f"{severity}={s.by_severity.get(severity, 0)}"
        for severity in reversed(SEVERITY_RANK)
    )
    body = Text()
    body.append("증거: ", style="bold")
    body.append(f"{evidence_count}개\n")
    body.append("탐지: ", style="bold")
    body.append(f"{s.total_findings}건 ({severity_line})\n")
    body.append("도구: ", style="bold")
    body.append(
        f"성공 {s.tools_run}, 실패 {s.tools_failed}, 건너뜀 {s.tools_skipped}\n"
    )
    body.append("분석 범위: ", style="bold")
    if (
        s.coverage_truncated
        or s.finding_limit_reached
        or s.depth_limit_hit
        or s.unreadable_paths
        or s.reparse_paths
        or s.oversized_files
    ):
        body.append(
            "제한 있음 - 원본 아티팩트와 누락 경로를 검토하세요",
            style="bold yellow",
        )
    else:
        body.append("기록된 coverage 경고 없음")
    console.print(Panel(body, title="리포트 요약", border_style="cyan"))

    if not include_finding_details:
        return

    findings: list[tuple[str, Finding]] = []
    for bundle in report.tool_bundles:
        if bundle.analysis:
            findings.extend((bundle.tool_id, item) for item in bundle.analysis.findings)
    findings.sort(
        key=lambda item: (SEVERITY_RANK[item[1].severity], item[1].confidence),
        reverse=True,
    )
    if not findings:
        console.print(
            "[yellow]탐지 항목이 없습니다. 이는 침해가 없다는 증명은 아닙니다.[/]"
        )
        return

    table = Table(title=f"우선 확인 항목 (최대 {max_findings}건)", show_lines=False)
    table.add_column("severity")
    table.add_column("status")
    table.add_column("ref")
    table.add_column("tool")
    table.add_column("category")
    table.add_column("title", overflow="fold")
    for tool_id, finding in findings[:max_findings]:
        table.add_row(
            _sev_text(finding.severity),
            _safe_text(report.annotation_for(finding.fingerprint)["status"]),
            _safe_text(finding.fingerprint[:12]),
            _safe_text(tool_id),
            _safe_text(finding.category),
            _safe_text(finding.title),
        )
    console.print(table)


def render_summary_narrative(text: str, console: Console) -> None:
    """Render model output literally so it cannot inject terminal markup/control."""
    console.print(Panel(_safe_text(text), title="LLM 요약", border_style="blue"))


def _render_timeline(report: Report, console: Console) -> None:
    timeline = report.timeline()
    if timeline["events"]:
        table = Table(title="Finding timeline", show_lines=False)
        table.add_column("time (UTC)")
        table.add_column("original timestamp")
        table.add_column("sev")
        table.add_column("status")
        table.add_column("ref")
        table.add_column("tool")
        table.add_column("event")
        table.add_column("title", overflow="fold")
        for item in timeline["events"]:
            timestamp = str(item["timestamp_utc"])
            if item["timezone_assumed"]:
                timestamp += " (assumed)"
            event_id = item["event_id"] if item["event_id"] is not None else "-"
            table.add_row(
                _safe_text(timestamp),
                _safe_text(item["timestamp_original"]),
                _sev_text(str(item["severity"])),
                _safe_text(item["annotation_status"]),
                _safe_text(str(item["fingerprint"])[:12]),
                _safe_text(item["tool_id"]),
                _safe_text(event_id),
                _safe_text(item["title"]),
            )
        console.print(table)
    if timeline["undated"]:
        table = Table(title="Findings without a usable timestamp", show_lines=False)
        table.add_column("reason")
        table.add_column("original timestamp")
        table.add_column("sev")
        table.add_column("status")
        table.add_column("ref")
        table.add_column("tool")
        table.add_column("event")
        table.add_column("title", overflow="fold")
        for item in timeline["undated"]:
            event_id = item["event_id"] if item["event_id"] is not None else "-"
            table.add_row(
                _safe_text(item["reason"]),
                _safe_text(item["timestamp_original"]),
                _sev_text(str(item["severity"])),
                _safe_text(item["annotation_status"]),
                _safe_text(str(item["fingerprint"])[:12]),
                _safe_text(item["tool_id"]),
                _safe_text(event_id),
                _safe_text(item["title"]),
            )
        console.print(table)


def _render_correlations(report: Report, console: Console) -> None:
    correlations = report.correlations()
    if not correlations:
        return
    console.print(
        "[dim]Shared entities are pivots only; they do not establish causation.[/]"
    )
    table = Table(title="Related findings sharing an entity", show_lines=False)
    table.add_column("type")
    table.add_column("entity", overflow="fold")
    table.add_column("finding refs / status", overflow="fold")
    for correlation in correlations[:30]:
        references = ", ".join(
            f"{item['fingerprint'][:12]} ({item['annotation_status']})"
            for item in correlation["findings"]
        )
        table.add_row(
            _safe_text(correlation["entity_type"]),
            _safe_text(correlation["entity_value"]),
            _safe_text(references),
        )
    console.print(table)
    if len(correlations) > 30:
        console.print(
            _safe_text(
                f"Correlation table truncated in terminal: "
                f"{len(correlations) - 30} more rows are in JSON/Markdown."
            )
        )


def _render_artifact_ledger(report: Report, console: Console) -> None:
    if not report.artifact_ledger:
        return
    table = Table(title="Artifact coverage ledger", show_lines=False)
    table.add_column("artifact", overflow="fold")
    table.add_column("discovery")
    table.add_column("selected")
    table.add_column("preflight")
    table.add_column("execution")
    table.add_column("analysis")
    table.add_column("findings", justify="right")
    for item in report.artifact_ledger[:30]:
        findings = item.get("finding_count")
        table.add_row(
            _safe_text(item.get("path", "")),
            _safe_text(item.get("discovery_status", "")),
            _safe_text(item.get("selected_tool_id") or "-"),
            _safe_text(item.get("preflight_status", "")),
            _safe_text(item.get("execution_status", "")),
            _safe_text(item.get("analysis_status", "")),
            _safe_text(findings if findings is not None else "n/a"),
        )
    console.print(table)
    if len(report.artifact_ledger) > 30:
        console.print(
            _safe_text(
                f"Artifact coverage table truncated in terminal: "
                f"{len(report.artifact_ledger) - 30} more rows are in JSON/Markdown."
            )
        )


def render(report: Report, console: Console) -> None:
    s = report.summary
    sev_line = " ".join(
        f"{k}={s.by_severity.get(k, 0)}" for k in SEVERITY_RANK
    )
    cat_line = ", ".join(f"{c}={n}" for c, n in s.by_category.items()) or "(none)"
    summary = Text()
    summary.append("Total findings:", style="bold")
    summary.append(f" {s.total_findings}    ")
    summary.append("Tools run:", style="bold")
    summary.append(f" {s.tools_run}  ")
    summary.append("failed:", style="red")
    summary.append(f" {s.tools_failed}  ")
    summary.append("skipped:", style="dim")
    summary.append(f" {s.tools_skipped}\n")
    summary.append("By severity:", style="bold")
    summary.append(f" {sev_line}\n")
    summary.append("By category:", style="bold")
    summary.append_text(_safe_text(f" {cat_line}\n"))
    summary.append("Total time:", style="bold")
    summary.append(f" {s.total_ms} ms")
    if s.coverage_truncated:
        summary.append("\nCoverage truncated:", style="bold yellow")
        summary.append(" yes - review raw artifacts")
    if s.finding_limit_reached:
        summary.append("\nFinding limit reached:", style="bold yellow")
        summary.append(" yes - result set may be incomplete")
    if s.depth_limit_hit or s.unreadable_paths or s.reparse_paths or s.oversized_files:
        summary.append("\nScan coverage incomplete:", style="bold yellow")
        summary.append(
            f" depth_limit_hit={str(s.depth_limit_hit).lower()}, "
            f"unreadable_paths={s.unreadable_paths}, "
            f"reparse_paths={s.reparse_paths}, oversized_files={s.oversized_files}"
        )
    console.print(
        Panel(
            summary,
            title="Analysis report",
            border_style="cyan",
        )
    )
    _render_timeline(report, console)
    _render_correlations(report, console)
    _render_artifact_ledger(report, console)

    # severity 내림차순으로 모든 finding 모음 (도구별 그룹은 다음 섹션).
    findings: list[tuple[str, Finding]] = []
    for b in report.tool_bundles:
        if b.analysis is None:
            continue
        for f in b.analysis.findings:
            findings.append((b.tool_id, f))
    findings.sort(key=lambda x: SEVERITY_RANK[x[1].severity], reverse=True)

    if findings:
        top = Table(title="Findings by severity", show_lines=False)
        top.add_column("sev", justify="center")
        top.add_column("status")
        top.add_column("ref")
        top.add_column("tool")
        top.add_column("category")
        top.add_column("source/conf")
        top.add_column("title", overflow="fold")
        for tid, f in findings:
            top.add_row(
                _sev_text(f.severity),
                _safe_text(report.annotation_for(f.fingerprint)["status"]),
                _safe_text(f.fingerprint[:12]),
                _safe_text(tid),
                _safe_text(f.category),
                _safe_text(f"{f.source}/{f.confidence:.2f}"),
                _safe_text(f.title),
            )
        console.print(top)

    # 도구별 섹션.
    for b in report.tool_bundles:
        title = f"[{b.tool_id}]"
        if b.analysis is None or not b.analysis.findings:
            detail = b.analysis.summary if b.analysis else "no execution"
            line = Text("\n")
            line.append_text(_safe_text(title, style="bold"))
            line.append(" ")
            line.append_text(_safe_text(detail, style="dim"))
            console.print(line)
            continue
        heading = Text("\n")
        heading.append_text(_safe_text(title, style="bold cyan"))
        heading.append(" ")
        heading.append_text(_safe_text(b.analysis.summary))
        console.print(heading)
        for f in b.analysis.findings:
            annotation = report.annotation_for(f.fingerprint)
            line = Text("  - ")
            line.append_text(_sev_text(f.severity))
            line.append(" ")
            line.append_text(_safe_text(f.title, style="bold"))
            line.append_text(_safe_text(f" ({f.source}, {f.confidence:.2f})", style="dim"))
            line.append_text(
                _safe_text(
                    f" [{annotation['status']}; {f.fingerprint[:12]}]", style="dim"
                )
            )
            console.print(line)
            if f.description:
                console.print(_safe_text(f"    {f.description[:300]}"))
            if f.suggested_followup:
                console.print(
                    _safe_text(f"    followup: {f.suggested_followup}", style="dim")
                )
            if annotation["notes"]:
                console.print(
                    _safe_text(f"    analyst note: {annotation['notes']}", style="dim")
                )
