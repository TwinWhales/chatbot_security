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


def render(report: Report, console: Console) -> None:
    s = report.summary
    sev_line = " ".join(
        f"{k}={s.by_severity.get(k, 0)}" for k in SEVERITY_RANK
    )
    cat_line = ", ".join(f"{c}={n}" for c, n in s.by_category.items()) or "(none)"
    console.print(
        Panel(
            f"[bold]Total findings:[/] {s.total_findings}    "
            f"[bold]Tools run:[/] {s.tools_run}  "
            f"[red]failed:[/] {s.tools_failed}  "
            f"[dim]skipped:[/] {s.tools_skipped}\n"
            f"[bold]By severity:[/] {sev_line}\n"
            f"[bold]By category:[/] {cat_line}\n"
            f"[bold]Total time:[/] {s.total_ms} ms",
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
        top.add_column("title", overflow="fold")
        for tid, f in findings:
            top.add_row(
                _sev_text(f.severity),
                tid,
                f.category,
                f.title,
            )
        console.print(top)

    # 도구별 섹션.
    for b in report.tool_bundles:
        title = f"[{b.tool_id}]"
        if b.analysis is None or not b.analysis.findings:
            detail = (
                b.analysis.summary
                if b.analysis
                else "no execution"
            )
            console.print(f"\n[bold]{title}[/] [dim]{detail}[/]")
            continue
        console.print(f"\n[bold cyan]{title}[/] {b.analysis.summary}")
        for f in b.analysis.findings:
            console.print(
                f"  - [{_SEV_COLORS.get(f.severity, 'white')}]{f.severity}[/] "
                f"[bold]{f.title}[/]"
            )
            if f.description:
                console.print(f"    {f.description[:300]}")
            if f.suggested_followup:
                console.print(f"    [dim]followup: {f.suggested_followup}[/]")
