from __future__ import annotations

import hashlib
import sys
import threading
import time
from pathlib import Path
from types import SimpleNamespace

import pytest

from forensicagent import config as settings
from forensicagent.executor.adapter import GenericAdapter
from forensicagent.executor.executor import _build_jobs, execute
from forensicagent.executor.runner import collect_generated_artifacts, run_tool
from forensicagent.executor.types import MAX_INLINE_JSON_BYTES, ExecutionResult
from forensicagent.selector.types import Plan, RunSpec, ToolSelection
from forensicagent.tools.schema import CommandTemplate, InstallCheck, ToolMetadata


def _script(path: Path, *, create_output: bool = True) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    write_output = (
        "(out / 'result.csv').write_text('kind,value\\nrow,1\\n', encoding='utf-8')"
        if create_output
        else "pass"
    )
    path.write_text(
        "from pathlib import Path\n"
        "import sys\n"
        "out = Path(sys.argv[1])\n"
        "out.mkdir(parents=True, exist_ok=True)\n"
        f"{write_output}\n"
        "print('done')\n",
        encoding="utf-8",
    )
    return path


def _metadata(
    tool_id: str,
    template: str,
    *,
    parallelizable: bool = True,
    output_format: str = "csv",
) -> ToolMetadata:
    return ToolMetadata(
        tool_id=tool_id,
        display_name=tool_id,
        category="test",
        applicable_evidence_types=["text_log"],  # type: ignore[list-item]
        parallelizable=parallelizable,
        output_format=output_format,  # type: ignore[arg-type]
        install_check=InstallCheck(
            command=f"{sys.executable} --version",
            expected_pattern="Python",
        ),
        command_templates=[
            CommandTemplate(name="fake", template=template, when="test")
        ],
        usage_description="executor integration fixture",
    )


def _selection(tool_id: str, template: str, targets: list[str], priority: int = 5):
    return ToolSelection(
        tool_id=tool_id,
        target_evidence=targets,
        command_template=template,
        priority=priority,
    )


def test_generated_output_manifest_and_stdout_compatibility(tmp_path):
    fake = _script(tmp_path / "fake.py")
    template = f"{sys.executable} {{evidence_path}} {{output_dir}}"
    metadata = _metadata("fakecsv", template)
    plan = Plan(selected_tools=[_selection("fakecsv", template, [str(fake)])])

    bundle = execute(
        plan,
        {"fakecsv": metadata},
        output_dir=tmp_path / "runs",
        max_parallel=2,
    )

    assert len(bundle.results) == 1
    result = bundle.results[0]
    assert result.status == "success"
    assert Path(result.stdout_path).read_text(encoding="utf-8").strip() == "done"
    assert result.command_template_used == template
    assert {artifact.role for artifact in result.artifacts} == {
        "stdout",
        "stderr",
        "generated",
    }
    generated = next(a for a in result.artifacts if a.role == "generated")
    assert generated.format == "csv"
    assert generated.size_bytes > 0
    assert generated.sha256 == hashlib.sha256(Path(generated.path).read_bytes()).hexdigest()
    payload = result.to_dict()
    assert payload["artifacts"][0]["sha256"]
    assert payload["warnings"] == []


def test_generated_reparse_point_is_not_followed(tmp_path, monkeypatch):
    generated = tmp_path / "generated"
    generated.mkdir()

    class ReparseEntry:
        path = str(generated / "junction")

        def stat(self, *, follow_symlinks):
            assert follow_symlinks is False
            return SimpleNamespace(st_file_attributes=0x400)

        def is_symlink(self):
            return False

    monkeypatch.setattr(
        "forensicagent.executor.runner.os.scandir",
        lambda directory: [ReparseEntry()],
    )

    artifacts, warnings = collect_generated_artifacts(
        generated,
        default_format="text",
    )

    assert artifacts == []
    assert any("link/reparse point" in warning for warning in warnings)


def test_large_json_stdout_stays_artifact_and_is_not_embedded(tmp_path):
    script = tmp_path / "large_json.py"
    script.write_text(
        "import json\n"
        "print(json.dumps({'items': [{'EventID': 4624, "
        f"'padding': 'x' * {MAX_INLINE_JSON_BYTES}}}]}}))\n",
        encoding="utf-8",
    )
    template = f"{sys.executable} {{evidence_path}}"
    metadata = _metadata("largejson", template, output_format="json")

    result = execute(
        Plan(selected_tools=[_selection("largejson", template, [str(script)])]),
        {"largejson": metadata},
        output_dir=tmp_path / "runs",
    ).results[0]

    assert result.status == "success"
    assert result.output_size_bytes > MAX_INLINE_JSON_BYTES
    assert result.parsed_output is None
    assert any("eager parse/report embedding skipped" in item for item in result.warnings)
    stdout = next(item for item in result.artifacts if item.role == "stdout")
    assert Path(stdout.path).is_file()
    assert stdout.size_bytes == result.output_size_bytes
    assert result.to_dict()["parsed_output"] is None


def test_same_evidence_filename_jobs_are_isolated(tmp_path):
    first = _script(tmp_path / "one" / "same.py")
    second = _script(tmp_path / "two" / "same.py")
    template = f"{sys.executable} {{evidence_path}} {{output_dir}}"
    metadata = _metadata("isolated", template)
    plan = Plan(
        selected_tools=[
            _selection("isolated", template, [str(first), str(second)])
        ]
    )

    results = execute(
        plan,
        {"isolated": metadata},
        output_dir=tmp_path / "runs",
        max_parallel=2,
    ).results

    assert [r.status for r in results] == ["success", "success"]
    job_dirs = {Path(r.stdout_path).parent for r in results}
    assert len(job_dirs) == 2
    generated_paths = {
        a.path for r in results for a in r.artifacts if a.role == "generated"
    }
    assert len(generated_paths) == 2


def test_run_specs_expand_one_target_into_multiple_isolated_jobs(tmp_path):
    fake = _script(tmp_path / "multi.py")
    first = f"{sys.executable} {{evidence_path}} {{output_dir}} first"
    second = f"{sys.executable} {{evidence_path}} {{output_dir}} second"
    metadata = _metadata("multi", first)
    metadata.command_templates.append(
        CommandTemplate(name="second", template=second, when="second pass")
    )
    selection = _selection("multi", first, [str(fake)])
    selection.run_specs = [
        RunSpec(str(fake), first, label="first"),
        RunSpec(str(fake), second, label="second"),
    ]

    results = execute(
        Plan(selected_tools=[selection]),
        {"multi": metadata},
        output_dir=tmp_path / "runs",
        max_parallel=2,
    ).results

    assert [result.command_template_used for result in results] == [first, second]
    assert all(result.status == "success" for result in results)
    assert len({Path(result.stdout_path).parent for result in results}) == 2


def test_expected_generated_output_missing_is_explicit(tmp_path):
    fake = _script(tmp_path / "no_output.py", create_output=False)
    template = f"{sys.executable} {{evidence_path}} {{output_dir}}"
    metadata = _metadata("missing", template)
    plan = Plan(selected_tools=[_selection("missing", template, [str(fake)])])

    result = execute(
        plan,
        {"missing": metadata},
        output_dir=tmp_path / "runs",
    ).results[0]

    assert result.status == "output_missing"
    assert "no files were produced" in result.error_message
    assert result.warnings
    assert not [a for a in result.artifacts if a.role == "generated"]


def test_generic_adapter_honors_preferred_template():
    preferred = "preferred {evidence_path}"
    metadata = ToolMetadata(
        tool_id="chooser",
        display_name="chooser",
        category="test",
        applicable_evidence_types=["text_log"],  # type: ignore[list-item]
        command_templates=[
            CommandTemplate(
                name="default", template="default {evidence_path}", when="default"
            ),
            CommandTemplate(name="preferred", template=preferred, when="preferred"),
        ],
        usage_description="template chooser",
    )
    adapter = GenericAdapter(metadata)

    argv = adapter.build_command("evidence.txt", preferred_template=preferred)

    assert argv == ["preferred", "evidence.txt"]
    assert adapter.selected_template == preferred


def test_prerequisite_validation_runs_once_per_tool(tmp_path, monkeypatch):
    calls = 0
    original = GenericAdapter.validate_prerequisites

    def counted(self):
        nonlocal calls
        calls += 1
        return original(self)

    monkeypatch.setattr(GenericAdapter, "validate_prerequisites", counted)
    first = _script(tmp_path / "one.py")
    second = _script(tmp_path / "two.py")
    template = f"{sys.executable} {{evidence_path}} {{output_dir}}"
    metadata = _metadata("preflight", template)
    plan = Plan(
        selected_tools=[_selection("preflight", template, [str(first), str(second)])]
    )

    execute(plan, {"preflight": metadata}, output_dir=tmp_path / "runs")

    assert calls == 1


def test_prerequisite_check_uses_trusted_project_cwd(tmp_path, monkeypatch):
    trusted = tmp_path / "trusted-project"
    hostile = tmp_path / "attacker-evidence"
    trusted.mkdir()
    hostile.mkdir()
    (hostile / "rogue-config").write_text("attacker-controlled", encoding="utf-8")
    probe = trusted / "show_cwd.py"
    probe.write_text("from pathlib import Path\nprint(Path.cwd())\n", encoding="utf-8")
    metadata = _metadata("cwd-preflight", f"{sys.executable} {{evidence_path}}")
    metadata.install_check = InstallCheck(
        command=f"{sys.executable} {probe}",
        expected_pattern=str(trusted.resolve()),
    )
    monkeypatch.setattr(settings, "PROJECT_ROOT", trusted)
    monkeypatch.chdir(hostile)

    ok, detail = GenericAdapter(metadata).validate_prerequisites()

    assert ok, detail


def test_jobs_and_single_worker_execution_are_priority_ordered(tmp_path, monkeypatch):
    template = f"{sys.executable} {{evidence_path}}"
    low_meta = _metadata("low", template, output_format="text")
    high_meta = _metadata("high", template, output_format="text")
    plan = Plan(
        selected_tools=[
            _selection("low", template, ["low.txt"], priority=1),
            _selection("high", template, ["high.txt"], priority=10),
        ]
    )
    tools = {"low": low_meta, "high": high_meta}
    assert [job.metadata.tool_id for job in _build_jobs(plan, tools)] == ["high", "low"]

    starts: list[str] = []
    starts_lock = threading.Lock()

    def fake_execute(job, output_dir, timeout_sec, preflight):
        with starts_lock:
            starts.append(job.metadata.tool_id)
        return ExecutionResult(tool_id=job.metadata.tool_id, status="success")

    monkeypatch.setattr(
        "forensicagent.executor.executor._execute_one", fake_execute
    )
    monkeypatch.setattr(
        "forensicagent.executor.executor._preflight_tools",
        lambda jobs: {job.metadata.tool_id: (True, "ok") for job in jobs},
    )

    execute(plan, tools, output_dir=tmp_path / "runs", max_parallel=1)

    assert starts == ["high", "low"]


def test_nonparallel_tool_is_serialized_without_blocking_other_tools(
    tmp_path, monkeypatch
):
    template = f"{sys.executable} {{evidence_path}}"
    serial_meta = _metadata(
        "serial", template, parallelizable=False, output_format="text"
    )
    other_meta = _metadata(
        "other", template, parallelizable=False, output_format="text"
    )
    plan = Plan(
        selected_tools=[
            _selection("serial", template, ["one", "two"], priority=10),
            _selection("other", template, ["three"], priority=1),
        ]
    )
    tools = {"serial": serial_meta, "other": other_meta}
    guard = threading.Lock()
    active: dict[str, int] = {"serial": 0, "other": 0}
    max_serial = 0
    max_total = 0

    def fake_execute(job, output_dir, timeout_sec, preflight):
        nonlocal max_serial, max_total
        with guard:
            active[job.metadata.tool_id] += 1
            max_serial = max(max_serial, active["serial"])
            max_total = max(max_total, sum(active.values()))
        time.sleep(0.08)
        with guard:
            active[job.metadata.tool_id] -= 1
        return ExecutionResult(tool_id=job.metadata.tool_id, status="success")

    monkeypatch.setattr(
        "forensicagent.executor.executor._execute_one", fake_execute
    )
    monkeypatch.setattr(
        "forensicagent.executor.executor._preflight_tools",
        lambda jobs: {job.metadata.tool_id: (True, "ok") for job in jobs},
    )

    execute(plan, tools, output_dir=tmp_path / "runs", max_parallel=2)

    assert max_serial == 1
    assert max_total == 2


def test_max_parallel_must_be_positive(tmp_path):
    with pytest.raises(ValueError, match="max_parallel must be >= 1"):
        execute(Plan(), {}, output_dir=tmp_path, max_parallel=0)


def test_runner_timeout_returns_manifested_streams(tmp_path):
    sleeper = tmp_path / "sleeper.py"
    sleeper.write_text(
        "import time\nprint('started', flush=True)\ntime.sleep(30)\n",
        encoding="utf-8",
    )
    template = f"{sys.executable} {{evidence_path}}"
    metadata = _metadata("sleeper", template, output_format="text")

    result = run_tool(
        metadata,
        [sys.executable, str(sleeper)],
        str(sleeper),
        tmp_path / "job",
        timeout_sec=1,
    )

    assert result.status == "timeout"
    assert result.exit_code == -1
    assert {artifact.role for artifact in result.artifacts} == {"stdout", "stderr"}
    assert Path(result.stdout_path).read_text(encoding="utf-8").strip() == "started"
