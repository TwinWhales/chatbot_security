"""Shared executable discovery for installer, doctor, and executor.

Executables are resolved from the process ``PATH`` first, then from the
per-user ``~/.forensicagent/tools_bin`` tree populated by the install helper.
Keeping this policy here prevents the environment check from reporting a tool
as available while the executor is unable to launch it.
"""

from __future__ import annotations

import os
import shutil
from pathlib import Path
from typing import Optional

from forensicagent import config as settings


_WINDOWS_EXTENSIONS = ("", ".exe", ".cmd", ".bat", ".com")


def tools_bin_root() -> Path:
    """Return the directory used for locally installed standalone tools."""
    return Path(settings.USER_HOME) / "tools_bin"


def installed_bin_dirs() -> list[Path]:
    """Return deterministic search directories below ``tools_bin``.

    Release archives are commonly either flat (``tools_bin/tool/tool.exe``)
    or contain one additional top-level directory.  The root itself is also
    searched for manually installed binaries.
    """
    root = tools_bin_root()
    if not root.is_dir():
        return []

    directories = [root]
    try:
        children = sorted(
            (p for p in root.iterdir() if p.is_dir()),
            key=lambda p: p.name.lower(),
        )
    except OSError:
        return directories

    directories.extend(children)
    for child in children:
        try:
            directories.extend(
                sorted(
                    (p for p in child.iterdir() if p.is_dir()),
                    key=lambda p: p.name.lower(),
                )
            )
        except OSError:
            continue
    return directories


def _candidate_names(name: str) -> list[str]:
    p = Path(name)
    if p.suffix:
        return [p.name]
    if os.name == "nt":
        return [f"{p.name}{ext}" for ext in _WINDOWS_EXTENSIONS]
    return [p.name]


def _is_launchable(path: Path) -> bool:
    if not path.is_file():
        return False
    # Windows launchability is determined by the file association/extension.
    # On POSIX, reject files without any execute bit just as shutil.which does.
    return os.name == "nt" or os.access(path, os.X_OK)


def resolve_executable(name: str | os.PathLike[str]) -> Path | None:
    """Resolve an executable from an explicit path, ``PATH``, or tools_bin."""
    raw = os.fspath(name).strip()
    if len(raw) >= 2 and raw[0] == raw[-1] and raw[0] in {'"', "'"}:
        raw = raw[1:-1]
    if not raw:
        return None

    requested = Path(raw).expanduser()
    has_path_component = requested.is_absolute() or requested.parent != Path(".")
    if has_path_component:
        try:
            candidate = requested.resolve()
        except OSError:
            candidate = requested.absolute()
        return candidate if _is_launchable(candidate) else None

    on_path = shutil.which(raw)
    if on_path:
        return Path(on_path).resolve()

    names = _candidate_names(raw)
    for directory in installed_bin_dirs():
        for candidate_name in names:
            candidate = directory / candidate_name
            if _is_launchable(candidate):
                try:
                    return candidate.resolve()
                except OSError:
                    return candidate.absolute()
    return None


def find_executable(name: str | os.PathLike[str]) -> Optional[str]:
    """String-returning compatibility wrapper around :func:`resolve_executable`."""
    resolved = resolve_executable(name)
    return str(resolved) if resolved is not None else None


__all__ = [
    "find_executable",
    "installed_bin_dirs",
    "resolve_executable",
    "tools_bin_root",
]
