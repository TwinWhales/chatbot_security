"""Rich terminal renderer for Report."""

from __future__ import annotations

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from forensicagent.analyzer.types import SEVERITY_RANK, Finding
from forensicagent.reporter.types import Report

_SEV_COLORS = {
    "critical": "bright_red",
    "high": "red",
    "medium": "yellow",
    "low": "blue",
    "info": "dim",
}


def _sev_text(sev: str) -> Text:
    return Text(sev, style=_SEV_COLORS.get(sev, "white"))


def _safe_text(value: object, *, style: str | None = None) -> Text:
    """Render untrusted evidence literally and strip terminal control bytes."""
    safe = "".join(
        "\N{REPLACEMENT CHARACTER}" if ord(char) < 32 or 127 <= ord(char) <= 159 else char
        for char in str(value)
    )
    return Text(safe, style=style)


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
    if s.depth_limit_hit or s.unreadable_paths or s.reparse_paths:
        summary.append("\nScan coverage incomplete:", style="bold yellow")
        summary.append(
            f" depth_limit_hit={str(s.depth_limit_hit).lower()}, "
            f"unreadable_paths={s.unreadable_paths}, reparse_paths={s.reparse_paths}"
        )
    console.print(
        Panel(
            summary,
            title="Analysis report",
            border_style="cyan",
        )
    )

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
        top.add_column("tool")
        top.add_column("category")
        top.add_column("source/conf")
        top.add_column("title", overflow="fold")
        for tid, f in findings:
            top.add_row(
                _sev_text(f.severity),
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
            line = Text("  - ")
            line.append_text(_sev_text(f.severity))
            line.append(" ")
            line.append_text(_safe_text(f.title, style="bold"))
            line.append_text(_safe_text(f" ({f.source}, {f.confidence:.2f})", style="dim"))
            console.print(line)
            if f.description:
                console.print(_safe_text(f"    {f.description[:300]}"))
            if f.suggested_followup:
                console.print(
                    _safe_text(f"    followup: {f.suggested_followup}", style="dim")
                )
