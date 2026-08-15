from forensicagent.analyzer.types import EvidenceRef, Finding, ToolAnalysis
from forensicagent.executor.types import ExecutionBundle, ExecutionResult, OutputArtifact
from forensicagent.reporter.builder import build
from forensicagent.reporter.md_out import write_md
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
