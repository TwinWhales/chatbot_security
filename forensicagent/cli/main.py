"""Typer 진입점 — `forensicagent` 명령.

Phase 1 단계라 전체 파이프라인(Selector/Executor/Analyzer/Reporter)이
아직 stub 이므로, 현재는 다음만 동작한다:
  * `forensicagent` (default)        — CWD 스캔 + 인벤토리 출력 + 실행 계획 placeholder
  * `forensicagent doctor`           — 환경 점검
  * `forensicagent tools list/info`  — 도구 메타데이터 디렉토리 살펴보기
  * `forensicagent --dry-run`        — 스캔까지만, 실행 안 함

Phase 4+ 에서 Selector/Executor/Analyzer/Reporter 가 채워지면 default
명령이 전 파이프라인을 돌린다.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Optional

import typer

from forensicagent import __version__
from forensicagent import config as settings
from forensicagent.cli.doctor import run_doctor
from forensicagent.cli.ui import console, render_inventory
from forensicagent.scanner import scan

app = typer.Typer(
    name="forensicagent",
    help="Forensic auto-triage CLI agent.",
    no_args_is_help=False,
    add_completion=False,
    rich_markup_mode="rich",
)

tools_app = typer.Typer(help="Tool metadata management.")
app.add_typer(tools_app, name="tools")


def _version_callback(value: bool) -> None:
    if value:
        typer.echo(f"forensicagent {__version__}")
        raise typer.Exit(0)


@app.callback(invoke_without_command=True)
def root(
    ctx: typer.Context,
    auto: bool = typer.Option(False, "--auto", help="Skip approval prompts."),
    quick: bool = typer.Option(
        False, "--quick", help="Run only short-runtime tools."
    ),
    tools: Optional[str] = typer.Option(
        None,
        "--tools",
        help="Comma-separated tool_ids to force-run (skips selector).",
    ),
    dry_run: bool = typer.Option(
        False, "--dry-run", help="Stop after planning; do not execute tools."
    ),
    max_depth: int = typer.Option(
        5, "--max-depth", help="Recursive scan depth limit.", min=1
    ),
    path: Optional[Path] = typer.Option(
        None,
        "--path",
        help="Directory to analyze (default: CWD).",
        exists=False,
        file_okay=False,
        dir_okay=True,
    ),
    version: bool = typer.Option(
        False,
        "--version",
        callback=_version_callback,
        is_eager=True,
        help="Print version and exit.",
    ),
) -> None:
    """Default flow when no subcommand is given."""
    if ctx.invoked_subcommand is not None:
        return

    target = (path or Path(os.getcwd())).resolve()
    c = console()
    c.print(f"[bold]forensicagent[/] {__version__}")
    c.print(f"[*] 작업 디렉토리: {target}")

    # ----- Scan -----
    c.print("[*] 증거 스캔 중...")
    inv = scan(target, max_depth=max_depth)
    if not inv.evidence_list:
        c.print("[yellow]식별된 증거가 없습니다.[/]")
        raise typer.Exit(0)

    c.print(render_inventory(inv))
    c.print(
        f"[*] 스캔 완료: {inv.scanned_files} 파일 검사, "
        f"{len(inv.evidence_list)} 증거 식별."
    )

    # ----- Selector / Executor / Analyzer / Reporter (Phase 4+) -----
    c.print(
        "\n[yellow][!] Selector/Executor/Analyzer/Reporter 모듈은 아직 미구현 "
        "(Phase 4+).[/]"
    )
    if dry_run:
        c.print("[dim]--dry-run: stopping after scan.[/]")
        raise typer.Exit(0)

    forced = [t.strip() for t in tools.split(",")] if tools else []
    plan_msg = (
        f"forced tools={forced}" if forced else
        ("quick mode" if quick else ("auto mode" if auto else "interactive"))
    )
    c.print(f"[dim]plan placeholder ({plan_msg}) — wire up in Phase 4.[/]")


@app.command("doctor")
def doctor_cmd(
    skip_optional: bool = typer.Option(
        False, "--skip-optional", help="Skip optional forensic-tool PATH checks."
    ),
) -> None:
    """Check environment readiness."""
    failed = run_doctor(console=console(), show_optional=not skip_optional)
    raise typer.Exit(failed)


@tools_app.command("list")
def tools_list() -> None:
    """List tool metadata YAMLs found in tools_metadata_dir."""
    tdir = Path(settings.TOOLS_METADATA_DIR)
    c = console()
    if not tdir.exists():
        c.print(
            f"[yellow]tools_metadata_dir not found:[/] {tdir}\n"
            "Create it and drop *.yaml files, or set FORENSICAGENT_TOOLS_DIR."
        )
        raise typer.Exit(0)
    yamls = sorted(list(tdir.glob("*.yaml")) + list(tdir.glob("*.yml")))
    if not yamls:
        c.print(f"[yellow]no YAML files in[/] {tdir}")
        raise typer.Exit(0)
    c.print(f"[bold]tool metadata in {tdir}:[/]")
    for y in yamls:
        c.print(f"  - {y.name}")


@tools_app.command("info")
def tools_info(
    tool_id: str = typer.Argument(..., help="Tool ID (matches YAML filename stem).")
) -> None:
    """Print contents of tool metadata YAML."""
    tdir = Path(settings.TOOLS_METADATA_DIR)
    for ext in (".yaml", ".yml"):
        f = tdir / f"{tool_id}{ext}"
        if f.exists():
            console().print(f.read_text(encoding="utf-8"))
            return
    console().print(f"[red]not found:[/] {tool_id} in {tdir}")
    raise typer.Exit(1)


if __name__ == "__main__":
    app()
