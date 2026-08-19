"""Markdown report serializer."""

from __future__ import annotations

from pathlib import Path

from forensicagent.analyzer.types import SEVERITY_RANK, Finding
from forensicagent.reporter.types import Report


def _md_text(value: object) -> str:
    """Escape untrusted/tool-controlled text used outside code spans."""
    text = " ".join(str(value).splitlines())
    for char in ("\\", "`", "*", "_", "{", "}", "[", "]", "<", ">", "|", "#"):
        text = text.replace(char, f"\\{char}")
    return text


def _inline_code(value: object) -> str:
    """Create a safe inline code span even when the value contains backticks."""
    text = " ".join(str(value).splitlines())
    longest = 0
    run = 0
    for char in text:
        if char == "`":
            run += 1
            longest = max(longest, run)
        else:
            run = 0
    fence = "`" * (longest + 1)
    padding = " " if text.startswith("`") or text.endswith("`") else ""
    return f"{fence}{padding}{text}{padding}{fence}"


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
    lines.append(f"- **run_id**: {_inline_code(m.run_id)}")
    lines.append(f"- **started**: {_md_text(m.started_at)}")
    lines.append(f"- **finished**: {_md_text(m.finished_at)}")
    lines.append(f"- **working_directory**: {_inline_code(m.working_directory)}")
    lines.append(
        f"- **host**: {_md_text(m.host_info.get('system', '?'))} "
        f"{_md_text(m.host_info.get('release', ''))} "
        f"({_md_text(m.host_info.get('machine', '?'))}) "
        f"python {_md_text(m.host_info.get('python', '?'))}"
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
        cat_line = ", ".join(f"{_md_text(c)}={n}" for c, n in s.by_category.items())
        lines.append(f"- by category: {cat_line}")
    lines.append(f"- total ms: {s.total_ms}")
    scan_status = (
        "**incomplete**"
        if s.depth_limit_hit or s.unreadable_paths or s.reparse_paths
        else "complete"
    )
    lines.append(
        f"- scan coverage: {scan_status} "
        f"(depth_limit_hit={str(s.depth_limit_hit).lower()}, "
        f"unreadable_paths={s.unreadable_paths}, reparse_paths={s.reparse_paths})"
    )
    if s.finding_limit_reached:
        lines.append(
            "- finding limit reached: **yes**; retained findings are "
            "severity-prioritized and the result set may be incomplete"
        )
    if s.coverage_truncated:
        lines.append(
            "- analysis coverage truncated: **yes**; review the per-tool "
            "warnings and retained raw artifacts"
        )
    lines.append("")

    # ---- Evidence inventory ----
    if report.evidence_inventory:
        inv = report.evidence_inventory
        lines.append("## Evidence inventory")
        lines.append("")
        lines.append(f"- scan root: {_inline_code(inv.scan_root)}")
        lines.append(
            f"- scanned files: {inv.scanned_files}, "
            f"detected: {len(inv.evidence_list)}, "
            f"unidentified: {inv.unidentified_files}, skipped: {inv.skipped_files}"
        )
        lines.append("")
        lines.append("| type | file | size | by | platform | conf |")
        lines.append("|---|---|---:|---|---|---:|")
        for e in inv.evidence_list:
            lines.append(
                f"| {_md_text(e.evidence_type)} | {_md_text(e.path)} | "
                f"{_human_size(e.size_bytes)} | {_md_text(e.detected_by)} | "
                f"{_md_text(e.platform_hint)} | {e.confidence:.2f} |"
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
                lines.append(f"- **[{_md_text(tid)}]** {_md_text(f.title)}")
                lines.append(
                    f"    - rule/source/confidence: {_inline_code(f.rule_id or 'n/a')} / "
                    f"{_md_text(f.source)} / {f.confidence:.2f}"
                )
                if f.description:
                    lines.append(f"    - {_md_text(f.description)}")
                if f.evidence_ref.source_file:
                    lines.append(
                        f"    - source: {_inline_code(f.evidence_ref.source_file)}"
                    )
                if f.evidence_ref.raw_excerpt:
                    lines.append(
                        f"    - excerpt: {_inline_code(f.evidence_ref.raw_excerpt[:160])}"
                    )
                if f.suggested_followup:
                    lines.append(f"    - followup: {_md_text(f.suggested_followup)}")
            lines.append("")

    # ---- Tool execution details ----
    lines.append("## Tool execution details")
    lines.append("")
    for b in report.tool_bundles:
        lines.append(f"### {_md_text(b.tool_id)}")
        lines.append("")
        for e in b.execution:
            lines.append(f"- target: {_inline_code(e.target_evidence)}")
            lines.append(
                f"    - status: **{_md_text(e.status)}** (exit={e.exit_code})"
            )
            lines.append(f"    - command: {_inline_code(e.command_executed)}")
            lines.append(
                f"    - duration: {e.duration_seconds:.2f}s, "
                f"output: {_human_size(e.output_size_bytes)}"
            )
            if e.stdout_path:
                lines.append(f"    - stdout: {_inline_code(e.stdout_path)}")
            if e.error_message:
                lines.append(f"    - error: {_md_text(e.error_message)}")
            for warning in e.warnings:
                lines.append(f"    - warning: {_md_text(warning)}")
            for artifact in e.artifacts:
                lines.append(
                    f"    - artifact ({_md_text(artifact.role)}/"
                    f"{_md_text(artifact.format)}, {_human_size(artifact.size_bytes)}): "
                    f"{_inline_code(artifact.path)} sha256={_inline_code(artifact.sha256)}"
                )
        if b.analysis:
            lines.append(
                f"- analyzer: case={b.analysis.case_used} "
                f"llm_invoked={b.analysis.llm_invoked} "
                f"llm_failed={b.analysis.llm_failed} "
                f"finding_limit_reached={b.analysis.finding_limit_reached} "
                f"coverage_truncated={bool(b.analysis.coverage_warnings)}"
            )
            lines.append(f"- summary: {_md_text(b.analysis.summary)}")
            for warning in b.analysis.coverage_warnings:
                lines.append(f"    - coverage warning: {_md_text(warning)}")
        lines.append("")

    # ---- Appendix: skipped plan items ----
    if report.execution_plan and report.execution_plan.skipped_no_evidence:
        lines.append("## Appendix: tools skipped (no matching evidence)")
        lines.append("")
        for tid in report.execution_plan.skipped_no_evidence:
            lines.append(f"- {_md_text(tid)}")
        lines.append("")

    if report.execution_plan and report.execution_plan.unhandled_evidence:
        lines.append("## Appendix: identified evidence without a compatible tool")
        lines.append("")
        for path_value in report.execution_plan.unhandled_evidence:
            lines.append(f"- {_inline_code(path_value)}")
        lines.append("")

    p.write_text("\n".join(lines), encoding="utf-8")
    return p
