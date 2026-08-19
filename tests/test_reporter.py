from io import StringIO

from rich.console import Console

from forensicagent.analyzer.types import (
    MAX_RETAINED_FINDINGS,
    EvidenceRef,
    Finding,
    ToolAnalysis,
)
from forensicagent.executor.types import ExecutionBundle, ExecutionResult, OutputArtifact
from forensicagent.reporter.builder import build
from forensicagent.reporter.md_out import write_md
from forensicagent.reporter.terminal import render
from forensicagent.scanner.types import Inventory
from forensicagent.selector.types import Plan, ToolSelection


def _plan() -> Plan:
    return Plan(
        selected_tools=[ToolSelection(tool_id="fake", target_evidence=["evidence"])]
    )


def test_failed_execution_is_not_reported_as_clean_zero_findings(tmp_path):
    execution = ExecutionBundle(
        results=[
            ExecutionResult(
                tool_id="fake",
                status="output_missing",
                error_message="CSV output was not created",
            )
        ]
    )
    report = build(
        inventory=Inventory(),
        plan=_plan(),
        execution=execution,
        analyses=[ToolAnalysis(tool_id="fake", summary="0 findings")],
        started_at="now",
        working_directory=str(tmp_path),
    )

    assert report.summary.tools_failed == 1
    assert "not analyzed" in report.tool_bundles[0].analysis.summary
    assert "CSV output was not created" in report.tool_bundles[0].analysis.summary


def test_markdown_escapes_tool_controlled_text_and_lists_artifact(tmp_path):
    finding = Finding(
        title="# injected [link](https://bad.invalid)",
        description="| table | break |",
        evidence_ref=EvidenceRef(raw_excerpt="value `with` ticks"),
    )
    result = ExecutionResult(
        tool_id="fake",
        status="success",
        command_executed="fake --arg `unsafe`",
        artifacts=[
            OutputArtifact(
                path=str(tmp_path / "out.csv"),
                role="generated",
                format="csv",
                size_bytes=10,
                sha256="abc",
            )
        ],
    )
    report = build(
        inventory=Inventory(),
        plan=_plan(),
        execution=ExecutionBundle(results=[result]),
        analyses=[ToolAnalysis(tool_id="fake", findings=[finding])],
        started_at="now",
        working_directory=str(tmp_path),
    )

    path = write_md(report, tmp_path / "report.md")
    text = path.read_text(encoding="utf-8")
    assert "\\# injected \\[link\\]" in text
    assert "artifact (generated/csv" in text
    assert "out.csv" in text


def test_terminal_renders_untrusted_finding_text_without_control_sequences(tmp_path):
    payload = "A\x1b]52;c;UEFZTE9BRA==\x1b\\B [bold]literal[/bold]"
    report = build(
        inventory=Inventory(),
        plan=_plan(),
        execution=ExecutionBundle(
            results=[ExecutionResult(tool_id="fake", status="success")]
        ),
        analyses=[
            ToolAnalysis(
                tool_id="fake",
                findings=[
                    Finding(
                        title=payload,
                        description=payload,
                        suggested_followup=payload,
                    )
                ],
            )
        ],
        started_at="now",
        working_directory=str(tmp_path),
    )
    stream = StringIO()

    render(
        report,
        Console(file=stream, force_terminal=True, color_system=None, width=200),
    )

    terminal = stream.getvalue()
    assert "\x1b" not in terminal
    assert "[bold]literal[/bold]" in terminal


def test_merged_finding_limit_is_preserved_in_json_and_markdown(tmp_path):
    low_findings = [
        Finding(
            severity="low",
            title=f"Noisy {index}",
            rule_id=f"noise:{index}",
            evidence_ref=EvidenceRef(raw_excerpt=f"noise {index}"),
        )
        for index in range(500)
    ]
    critical = Finding(
        severity="critical",
        title="Critical tail",
        rule_id="critical:tail",
        evidence_ref=EvidenceRef(raw_excerpt="critical tail"),
    )
    report = build(
        inventory=Inventory(),
        plan=_plan(),
        execution=ExecutionBundle(
            results=[ExecutionResult(tool_id="fake", status="success")]
        ),
        analyses=[
            ToolAnalysis(tool_id="fake", findings=low_findings),
            ToolAnalysis(
                tool_id="fake",
                findings=[critical],
                finding_limit_reached=True,
            ),
        ],
        started_at="now",
        working_directory=str(tmp_path),
    )

    analysis = report.tool_bundles[0].analysis
    assert analysis is not None
    assert len(analysis.findings) == 500
    assert critical in analysis.findings
    assert analysis.finding_limit_reached is True
    assert report.to_dict()["summary"]["finding_limit_reached"] is True
    text = write_md(report, tmp_path / "report.md").read_text(encoding="utf-8")
    assert "finding limit reached: **yes**" in text
    assert "finding_limit_reached=True" in text


def test_report_limit_flag_requires_an_actually_dropped_finding(tmp_path):
    findings = [
        Finding(
            title=f"Finding {index}",
            rule_id=f"finding:{index}",
            evidence_ref=EvidenceRef(raw_excerpt=f"row {index}"),
        )
        for index in range(MAX_RETAINED_FINDINGS + 1)
    ]

    def report_for(items):
        return build(
            inventory=Inventory(),
            plan=_plan(),
            execution=ExecutionBundle(
                results=[ExecutionResult(tool_id="fake", status="success")]
            ),
            analyses=[ToolAnalysis(tool_id="fake", findings=items)],
            started_at="now",
            working_directory=str(tmp_path),
        )

    exact = report_for(findings[:MAX_RETAINED_FINDINGS])
    overflow = report_for(findings)
    exact_analysis = exact.tool_bundles[0].analysis
    overflow_analysis = overflow.tool_bundles[0].analysis

    assert exact_analysis is not None
    assert exact_analysis.finding_limit_reached is False
    assert exact.summary.finding_limit_reached is False
    assert overflow_analysis is not None
    assert len(overflow_analysis.findings) == MAX_RETAINED_FINDINGS
    assert overflow_analysis.finding_limit_reached is True
    assert overflow.summary.finding_limit_reached is True


def test_markdown_keeps_skipped_tools_in_their_own_appendix(tmp_path):
    plan = _plan()
    plan.skipped_no_evidence = ["unused-tool"]
    plan.unhandled_evidence = ["legacy.evt"]
    report = build(
        inventory=Inventory(),
        plan=plan,
        execution=ExecutionBundle(),
        analyses=[],
        started_at="now",
        working_directory=str(tmp_path),
    )

    text = write_md(report, tmp_path / "report.md").read_text(encoding="utf-8")
    skipped_heading = text.index("## Appendix: tools skipped")
    skipped_item = text.index("- unused-tool")
    unhandled_heading = text.index("## Appendix: identified evidence")
    unhandled_item = text.index("- `legacy.evt`")

    assert skipped_heading < skipped_item < unhandled_heading < unhandled_item


def test_scan_coverage_is_preserved_in_summary_and_renderers(tmp_path):
    report = build(
        inventory=Inventory(
            depth_limit_hit=True,
            unreadable_paths=2,
            reparse_paths=3,
        ),
        plan=_plan(),
        execution=ExecutionBundle(),
        analyses=[],
        started_at="now",
        working_directory=str(tmp_path),
    )

    summary = report.to_dict()["summary"]
    assert summary["depth_limit_hit"] is True
    assert summary["unreadable_paths"] == 2
    assert summary["reparse_paths"] == 3

    markdown = write_md(report, tmp_path / "report.md").read_text(encoding="utf-8")
    assert "scan coverage: **incomplete**" in markdown
    assert "depth_limit_hit=true, unreadable_paths=2, reparse_paths=3" in markdown

    console = Console(record=True, width=120)
    render(report, console)
    terminal = console.export_text()
    assert "Scan coverage incomplete" in terminal
    assert "depth_limit_hit=true, unreadable_paths=2, reparse_paths=3" in terminal
