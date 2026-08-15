from typer.testing import CliRunner

from forensicagent.cli.main import app


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
