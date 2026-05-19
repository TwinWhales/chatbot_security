"""Markdown report serializer."""

from __future__ import annotations

from pathlib import Path

from forensicagent.analyzer.types import SEVERITY_RANK, Finding
from forensicagent.reporter.types import Report


def _sev_emoji(sev: str) -> str:
    return {
        "critical": "🔴",
        "high": "🟠",
        "medium": "🟡",
        "low": "🔵",
        "info": "⚪",
    }.get(sev, "·")


def _human_size(n: int) -> str:
    units = ["B", "KB", "MB", "GB", "TB"]
    size = float(n)
    for u in units:
        if size < 1024 or u == units[-1]:
            return f"{size:.1f}{u}" if u != "B" else f"{int(size)}B"
        size /= 1024
    return f"{n}B"


def write_md(report: Report, path: str | Path) -> Path:
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    lines: list[str] = []
    s = report.summary
    m = report.meta

    lines.append("# Forensic Triage Report")
    lines.append("")
    lines.append(f"- **run_id**: `{m.run_id}`")
    lines.append(f"- **started**: {m.started_at}")
    lines.append(f"- **finished**: {m.finished_at}")
    lines.append(f"- **working_directory**: `{m.working_directory}`")
    lines.append(
        f"- **host**: {m.host_info.get('system', '?')} "
        f"{m.host_info.get('release', '')} ({m.host_info.get('machine', '?')}) "
        f"python {m.host_info.get('python', '?')}"
    )
    lines.append("")

    lines.append("## Summary")
    lines.append("")
    lines.append(f"- total findings: **{s.total_findings}**")
    lines.append(
        f"- tools run: {s.tools_run}, failed: {s.tools_failed}, skipped: {s.tools_skipped}"
    )
    sev_line = ", ".join(
        f"{k}={s.by_severity.get(k, 0)}" for k in SEVERITY_RANK
    )
    lines.append(f"- by severity: {sev_line}")
    if s.by_category:
        cat_line = ", ".join(f"{c}={n}" for c, n in s.by_category.items())
        lines.append(f"- by category: {cat_line}")
    lines.append(f"- total ms: {s.total_ms}")
    lines.append("")

    # ---- Evidence inventory ----
    if report.evidence_inventory:
        inv = report.evidence_inventory
        lines.append("## Evidence inventory")
        lines.append("")
        lines.append(f"- scan root: `{inv.scan_root}`")
        lines.append(
            f"- scanned files: {inv.scanned_files}, "
            f"detected: {len(inv.evidence_list)}, "
            f"skipped: {inv.skipped_files}"
        )
        lines.append("")
        lines.append("| type | file | size | by | platform | conf |")
        lines.append("|---|---|---:|---|---|---:|")
        for e in inv.evidence_list:
            lines.append(
                f"| {e.evidence_type} | `{e.path}` | "
                f"{_human_size(e.size_bytes)} | {e.detected_by} | "
                f"{e.platform_hint} | {e.confidence:.2f} |"
            )
        lines.append("")

    # ---- Findings by severity ----
    all_findings: list[tuple[str, Finding]] = []
    for b in report.tool_bundles:
        if b.analysis is None:
            continue
        for f in b.analysis.findings:
            all_findings.append((b.tool_id, f))

    if all_findings:
        lines.append("## Findings by severity")
        lines.append("")
        for sev in ("critical", "high", "medium", "low", "info"):
            sev_items = [(t, f) for t, f in all_findings if f.severity == sev]
            if not sev_items:
                continue
            lines.append(f"### {_sev_emoji(sev)} {sev} ({len(sev_items)})")
            lines.append("")
            for tid, f in sev_items:
                lines.append(f"- **[{tid}]** {f.title}")
                if f.description:
                    lines.append(f"    - {f.description}")
                if f.evidence_ref.source_file:
                    lines.append(f"    - source: `{f.evidence_ref.source_file}`")
                if f.evidence_ref.raw_excerpt:
                    lines.append(
                        f"    - excerpt: `{f.evidence_ref.raw_excerpt[:160]}`"
                    )
                if f.suggested_followup:
                    lines.append(f"    - followup: {f.suggested_followup}")
            lines.append("")

    # ---- Tool execution details ----
    lines.append("## Tool execution details")
    lines.append("")
    for b in report.tool_bundles:
        lines.append(f"### {b.tool_id}")
        lines.append("")
        for e in b.execution:
            lines.append(f"- target: `{e.target_evidence}`")
            lines.append(f"    - status: **{e.status}** (exit={e.exit_code})")
            lines.append(f"    - command: `{e.command_executed}`")
            lines.append(
                f"    - duration: {e.duration_seconds:.2f}s, "
                f"output: {_human_size(e.output_size_bytes)}"
            )
            if e.stdout_path:
                lines.append(f"    - stdout: `{e.stdout_path}`")
            if e.error_message:
                lines.append(f"    - error: {e.error_message}")
        if b.analysis:
            lines.append(
                f"- analyzer: case={b.analysis.case_used} "
                f"llm_invoked={b.analysis.llm_invoked} "
                f"llm_failed={b.analysis.llm_failed}"
            )
            lines.append(f"- summary: {b.analysis.summary}")
        lines.append("")

    # ---- Appendix: skipped plan items ----
    if report.execution_plan and report.execution_plan.skipped_no_evidence:
        lines.append("## Appendix: tools skipped (no matching evidence)")
        lines.append("")
        for tid in report.execution_plan.skipped_no_evidence:
            lines.append(f"- {tid}")
        lines.append("")

    p.write_text("\n".join(lines), encoding="utf-8")
    return p
