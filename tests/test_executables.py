from __future__ import annotations

import os
from pathlib import Path

from forensicagent import config as settings
from forensicagent.cli import doctor, tool_install
from forensicagent.tools import executables


def _make_executable(path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("echo fake\n", encoding="utf-8")
    if os.name != "nt":
        path.chmod(0o755)


def test_tools_bin_resolver_finds_nested_executable(tmp_path, monkeypatch):
    monkeypatch.setattr(settings, "USER_HOME", tmp_path)
    filename = "fakeprobe.exe" if os.name == "nt" else "fakeprobe"
    expected = tmp_path / "tools_bin" / "fakeprobe" / "release" / filename
    _make_executable(expected)

    assert executables.resolve_executable("fakeprobe") == expected.resolve()
    assert executables.find_executable("fakeprobe") == str(expected.resolve())


def test_explicit_executable_path_is_resolved(tmp_path):
    filename = "direct.exe" if os.name == "nt" else "direct"
    expected = tmp_path / filename
    _make_executable(expected)

    assert executables.resolve_executable(expected) == expected.resolve()


def test_path_takes_precedence_over_tools_bin(tmp_path, monkeypatch):
    monkeypatch.setattr(settings, "USER_HOME", tmp_path / "home")
    filename = "priorityprobe.exe" if os.name == "nt" else "priorityprobe"
    on_path = tmp_path / "path_bin" / filename
    local = tmp_path / "home" / "tools_bin" / "priorityprobe" / filename
    _make_executable(on_path)
    _make_executable(local)
    monkeypatch.setenv("PATH", str(on_path.parent))

    assert executables.resolve_executable("priorityprobe") == on_path.resolve()


def test_installer_doctor_and_executor_share_resolver():
    assert tool_install.find_executable is executables.find_executable
    assert doctor.find_executable is executables.find_executable
