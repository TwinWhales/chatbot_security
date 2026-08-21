from io import StringIO
from types import SimpleNamespace

from rich.console import Console

from forensicagent.analyzer.types import EvidenceRef, Finding, ToolAnalysis
from forensicagent.cli.repl import _SUMMARY_MAX_CHARS, do_summary
from forensicagent.executor.types import ExecutionBundle, ExecutionResult
from forensicagent.llm import OllamaUnavailable
from forensicagent.reporter.builder import build
from forensicagent.scanner.types import Inventory
from forensicagent.selector.types import Plan, ToolSelection


def _report(tmp_path):
    secret = "AKIAABCDEFGHIJKLMNOP"
    return build(
        inventory=Inventory(scan_root=str(tmp_path / "private-evidence")),
        plan=Plan(
            selected_tools=[ToolSelection(tool_id="fake", target_evidence=[])]
        ),
        execution=ExecutionBundle(
            results=[
                ExecutionResult(
                    tool_id="fake",
                    status="success",
                    command_executed=f"fake --token {secret}",
                    target_evidence=str(tmp_path / "private-evidence"),
                )
            ]
        ),
        analyses=[
            ToolAnalysis(
                tool_id="fake",
                findings=[
                    Finding(
                        severity="high",
                        category=f"secret-{secret}",
                        title=f"credential {secret}",
                        evidence_ref=EvidenceRef(
                            source_file=str(tmp_path / "private-evidence"),
                            raw_excerpt=f"token={secret}",
                        ),
                    )
                ],
            )
        ],
        started_at="now",
        working_directory=str(tmp_path),
    )


def _console():
    stream = StringIO()
    return stream, Console(
        file=stream,
        force_terminal=True,
        color_system=None,
        width=180,
    )


def test_summary_requires_a_report():
    stream, console = _console()
    state = SimpleNamespace(last_report=None, client=lambda: None)

    do_summary(state, console)

    assert "/report" in stream.getvalue()


def test_summary_no_llm_uses_deterministic_report_view(tmp_path):
    stream, console = _console()
    state = SimpleNamespace(last_report=_report(tmp_path), client=lambda: None)

    do_summary(state, console)

    output = stream.getvalue()
    assert "리포트 요약" in output
    assert "no_llm" in output
    assert "AKIAABCDEFGHIJKLMNOP" not in output
    assert "credential" not in output
    assert "secret-" not in output
    assert "private-evidence" not in output
    assert "--token" not in output


def test_summary_llm_context_excludes_evidence_and_secrets(tmp_path):
    class Client:
        messages = None

        def chat(self, messages, *, temperature):
            assert temperature == 0.0
            self.messages = messages
            return "A\x1b]52;c;UEFZTE9BRA==\x1b\\ [bold]literal[/bold]"

    client = Client()
    stream, console = _console()
    state = SimpleNamespace(last_report=_report(tmp_path), client=lambda: client)

    do_summary(state, console)

    prompt = "\n".join(item["content"] for item in client.messages)
    assert "AKIAABCDEFGHIJKLMNOP" not in prompt
    assert "private-evidence" not in prompt
    assert "--token" not in prompt
    assert "raw_excerpt" not in prompt
    assert "\x1b" not in stream.getvalue()
    assert "[bold]literal[/bold]" in stream.getvalue()


def test_summary_llm_failure_keeps_structured_fallback(tmp_path):
    class Client:
        def chat(self, _messages, *, temperature):
            raise OllamaUnavailable(f"offline at temperature={temperature}")

    stream, console = _console()
    state = SimpleNamespace(last_report=_report(tmp_path), client=lambda: Client())

    do_summary(state, console)

    output = stream.getvalue()
    assert "리포트 요약" in output
    assert "LLM 요약 생략" in output


def test_summary_caps_llm_narrative(tmp_path, monkeypatch):
    class Client:
        def chat(self, _messages, *, temperature):
            assert temperature == 0.0
            return "x" * (_SUMMARY_MAX_CHARS + 100) + "SECRET_TAIL"

    rendered = []
    monkeypatch.setattr(
        "forensicagent.cli.repl.render_summary_narrative",
        lambda text, _console: rendered.append(text),
    )
    _stream, console = _console()
    state = SimpleNamespace(last_report=_report(tmp_path), client=lambda: Client())

    do_summary(state, console)

    assert len(rendered) == 1
    assert len(rendered[0]) == _SUMMARY_MAX_CHARS
    assert rendered[0].endswith("…")
    assert "SECRET_TAIL" not in rendered[0]


def test_summary_sanitizes_llm_failure_text(tmp_path):
    class Client:
        def chat(self, _messages, *, temperature):
            raise OllamaUnavailable(
                f"offline at {temperature}\x1b]52;c;UEFZTE9BRA==\x1b\\ [bold]literal[/bold]"
            )

    stream, console = _console()
    state = SimpleNamespace(last_report=_report(tmp_path), client=lambda: Client())

    do_summary(state, console)

    output = stream.getvalue()
    assert "\x1b" not in output
    assert "[bold]literal[/bold]" in output
