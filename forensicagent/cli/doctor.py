"""`forensicagent doctor` — 환경 점검.

체크 항목:
  * Python >= 3.10
  * Ollama 데몬 + 지정 모델
  * ChromaDB import
  * sentence-transformers import (or openai if EMBEDDING_MODEL startswith openai:)
  * python-magic / libmagic
  * (optional) 포렌식 도구가 PATH 에 있는지: volatility3, chainsaw, regripper, plaso 등

출력: Rich 테이블 (status, name, detail). 어디서 막히는지 한눈에 보인다.
"""

from __future__ import annotations

import shutil
import sys
from dataclasses import dataclass
from typing import Callable

from rich.console import Console
from rich.table import Table

from forensicagent import config as settings
from forensicagent.llm import OllamaClient


# Optional forensic tools surveyed by doctor. Missing ones are just hints —
# users only need the tools that match the evidence they actually have.
_OPTIONAL_TOOLS = [
    "volatility3",
    "vol",  # volatility3 alt entry
    "chainsaw",
    "rip",  # RegRipper
    "log2timeline.py",
    "psort.py",
    "plaso",
    "tshark",
    "tcpdump",
    "yara",
    "exiftool",
    "binwalk",
    "strings",
    "file",
]


@dataclass
class CheckResult:
    name: str
    ok: bool
    detail: str
    optional: bool = False


def _check_python() -> CheckResult:
    v = sys.version_info
    ok = (v.major, v.minor) >= (3, 10)
    return CheckResult(
        name="python",
        ok=ok,
        detail=f"{v.major}.{v.minor}.{v.micro} ({'>= 3.10' if ok else 'need >= 3.10'})",
    )


def _check_import(module: str, hint: str = "") -> CheckResult:
    try:
        __import__(module)
        return CheckResult(name=module, ok=True, detail="importable")
    except ImportError as e:
        return CheckResult(
            name=module,
            ok=False,
            detail=f"missing: {e}. {hint}",
        )


def _check_libmagic() -> CheckResult:
    try:
        import magic  # type: ignore

        # Trigger libmagic init by asking it to identify a byte string.
        try:
            magic.from_buffer(b"hello world")
            return CheckResult(name="libmagic", ok=True, detail="libmagic ok")
        except Exception as e:  # noqa: BLE001
            return CheckResult(
                name="libmagic",
                ok=False,
                detail=f"python-magic loaded but libmagic backend failed: {e}",
            )
    except ImportError as e:
        return CheckResult(
            name="libmagic",
            ok=False,
            detail=(
                f"missing: {e}. install python-magic-bin (Windows) or "
                "python-magic + libmagic (Linux/macOS)"
            ),
        )


def _check_ollama() -> CheckResult:
    client = OllamaClient()
    ok, detail = client.is_available()
    return CheckResult(name=f"ollama ({client.model})", ok=ok, detail=detail)


def _check_embedding_provider() -> CheckResult:
    model = settings.EMBEDDING_MODEL
    if model.startswith("openai:"):
        r = _check_import("openai", hint="pip install openai")
        r.name = f"embedding backend ({model})"
        if r.ok and not settings.OPENAI_API_KEY:
            r.ok = False
            r.detail = "openai imported, but OPENAI_API_KEY env var is empty"
        return r
    r = _check_import(
        "sentence_transformers", hint="pip install sentence-transformers"
    )
    r.name = f"embedding backend ({model})"
    return r


def _check_optional_tools() -> list[CheckResult]:
    out: list[CheckResult] = []
    for tool in _OPTIONAL_TOOLS:
        path = shutil.which(tool)
        out.append(
            CheckResult(
                name=tool,
                ok=path is not None,
                detail=path or "not on PATH",
                optional=True,
            )
        )
    return out


CORE_CHECKS: list[Callable[[], CheckResult]] = [
    _check_python,
    lambda: _check_import("chromadb", hint="pip install chromadb"),
    _check_embedding_provider,
    _check_libmagic,
    _check_ollama,
]


def run_doctor(console: Console | None = None, *, show_optional: bool = True) -> int:
    """모든 체크 실행 후 실패 개수를 반환 (CLI exit code)."""
    console = console or Console()

    core_results = [c() for c in CORE_CHECKS]
    optional_results = _check_optional_tools() if show_optional else []

    table = Table(title="forensicagent - environment check", show_lines=False)
    table.add_column("status", justify="center", style="bold")
    table.add_column("component")
    table.add_column("detail", overflow="fold")

    for r in core_results:
        status = "[green]OK[/]" if r.ok else "[red]FAIL[/]"
        table.add_row(status, r.name, r.detail)

    if optional_results:
        table.add_section()
        table.add_row("", "[dim]-- optional forensic tools --[/]", "")
        for r in optional_results:
            status = "[green]OK[/]" if r.ok else "[yellow]miss[/]"
            table.add_row(status, r.name, r.detail)

    console.print(table)

    core_failed = sum(1 for r in core_results if not r.ok)
    if core_failed:
        console.print(
            f"\n[red]{core_failed} core check(s) failed.[/] "
            "Fix these before running an analysis."
        )
    else:
        console.print("\n[green]All core checks passed.[/]")
    return core_failed
