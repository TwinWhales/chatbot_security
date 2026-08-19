from typer.testing import CliRunner

from forensicagent.cli import main as cli_main
from forensicagent.cli import tool_install
from forensicagent.scanner.types import Inventory


app = cli_main.app


runner = CliRunner()


def test_missing_target_is_nonzero(tmp_path):
    result = runner.invoke(
        app,
        ["--path", str(tmp_path / "missing"), "--dry-run", "--no-llm"],
    )

    assert result.exit_code == 2
    assert "경로가 없습니다" in result.output


def test_single_file_dry_run_is_supported(tmp_path):
    source = tmp_path / "app.py"
    source.write_text("print('ok')\n", encoding="utf-8")

    result = runner.invoke(
        app,
        [
            "--path",
            str(source),
            "--dry-run",
            "--no-llm",
            "--no-rag",
        ],
    )

    assert result.exit_code == 0
    assert "bandit" in result.output


def test_noninteractive_execution_requires_auto(tmp_path):
    source = tmp_path / "app.py"
    source.write_text("print('ok')\n", encoding="utf-8")

    result = runner.invoke(
        app,
        ["--path", str(source), "--no-llm", "--no-rag"],
    )

    assert result.exit_code == 2
    assert "--auto" in result.output


def test_scan_coverage_warning_is_shown_before_empty_inventory_exit(
    tmp_path, monkeypatch
):
    monkeypatch.setattr(
        cli_main,
        "scan",
        lambda *_args, **_kwargs: Inventory(
            depth_limit_hit=True,
            unreadable_paths=2,
            reparse_paths=3,
        ),
    )

    result = runner.invoke(
        app,
        ["--path", str(tmp_path), "--dry-run", "--no-llm", "--no-rag"],
    )

    assert result.exit_code == 0
    assert "Scan coverage incomplete" in result.output
    assert "depth_limit_hit=true" in result.output
    assert "unreadable_paths=2" in result.output
    assert "reparse_paths=3" in result.output


def test_auto_install_failure_is_nonzero_in_every_mode(monkeypatch):
    spec = tool_install.ToolSpec(
        name="test-auto",
        kind="zip",
        description="test",
        homepage="https://example.test",
    )
    monkeypatch.setattr(tool_install, "TOOL_SPECS", {"test-auto": spec})
    monkeypatch.setattr(tool_install, "_spec_installed", lambda _spec: False)
    monkeypatch.setattr(tool_install, "install_one", lambda _spec, _console: False)

    for args in (
        ["--auto", "install", "test-auto"],
        ["--auto", "install", "--all"],
        ["--auto", "install"],
    ):
        result = runner.invoke(app, args)

        assert result.exit_code == 1
        assert "설치 실패:" in result.output
