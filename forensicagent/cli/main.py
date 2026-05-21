"""Typer 진입점 — `forensicagent` 명령.

전 파이프라인 흐름 (명세 0.2):
  Scanner → Selector → (사용자 승인) → Executor → Analyzer → Reporter
"""

from __future__ import annotations

import logging
import os
import sys
from pathlib import Path
from typing import Optional

import typer

from forensicagent import __version__
from forensicagent import config as settings
from forensicagent.analyzer import analyze_all
from forensicagent.cli.doctor import run_doctor
from forensicagent.cli.repl import run as run_repl
from forensicagent.cli.session import SessionOptions, make_session
from forensicagent.cli.ui import console, render_inventory
from forensicagent.executor import execute
from forensicagent.llm import OllamaClient
from forensicagent.reporter import write as write_report
from forensicagent.reporter.types import now_iso
from forensicagent.scanner import scan
from forensicagent.selector import select
from forensicagent.tools import load_all_tools

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


def _approve(c, *, auto: bool, prompt: str) -> bool:
    """interactive approval. --auto 면 항상 True."""
    if auto:
        return True
    if not sys.stdin.isatty():
        # 비대화형이면 기본 yes (스크립트로 돌릴 때 멈추지 않도록).
        c.print(f"[dim]{prompt} (non-tty, auto-yes)[/]")
        return True
    answer = c.input(prompt).strip().lower()
    return answer in ("", "y", "yes")


def _resolve_tools_dir() -> Path:
    tools_dir = Path(settings.TOOLS_METADATA_DIR)
    if not tools_dir.exists() or not any(tools_dir.glob("*.y*ml")):
        repo_tools = Path.cwd() / "tools_metadata"
        if repo_tools.exists() and any(repo_tools.glob("*.y*ml")):
            tools_dir = repo_tools
    return tools_dir


def _load_tools_or_exit(c) -> tuple[Path, list]:
    tools_dir = _resolve_tools_dir()
    tool_metas = load_all_tools(tools_dir)
    if not tool_metas:
        c.print(
            f"[yellow]경고: 도구 메타데이터가 없습니다 ({tools_dir}). "
            "tools_metadata/*.yaml 을 추가하세요.[/]"
        )
        raise typer.Exit(2)
    return tools_dir, tool_metas


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
        None, "--path",
        help="Directory to analyze (default: CWD).",
        exists=False, file_okay=False, dir_okay=True,
    ),
    no_llm: bool = typer.Option(
        False, "--no-llm",
        help="Skip LLM ranking and LLM analysis (deterministic only).",
    ),
    output_dir: Optional[Path] = typer.Option(
        None, "--output-dir",
        help="Where to write tool outputs + report (default: ./forensicagent_output).",
    ),
    timeout: int = typer.Option(
        0, "--timeout",
        help="Per-tool timeout seconds (0 = use config default).",
    ),
    verbose: bool = typer.Option(False, "--verbose", "-v"),
    version: bool = typer.Option(
        False, "--version", callback=_version_callback, is_eager=True,
        help="Print version and exit.",
    ),
) -> None:
    """Default flow when no subcommand is given."""
    if ctx.invoked_subcommand is not None:
        return

    if verbose:
        logging.basicConfig(
            level=logging.INFO, format="%(levelname)s %(name)s: %(message)s"
        )

    c = console()

    # 인자 없이 호출 + TTY 면 인터랙티브 REPL 로 진입.
    one_shot_signals = (
        auto or quick or dry_run or no_llm
        or tools is not None or path is not None
        or output_dir is not None or timeout != 0
    )
    if not one_shot_signals and sys.stdin.isatty():
        _, tool_metas = _load_tools_or_exit(c)
        state = make_session(
            path=None,
            output_dir=None,
            tool_metas=tool_metas,
            options=SessionOptions(no_llm=False),
        )
        raise typer.Exit(run_repl(state))

    target = (path or Path(os.getcwd())).resolve()
    c.print(f"[bold]forensicagent[/] {__version__}")
    c.print(f"[*] 작업 디렉토리: {target}")

    started_at = now_iso()
    stage_ms: dict[str, int] = {}

    # ---------- 1. Scanner ----------
    c.print("[*] 증거 스캔 중...")
    inv = scan(target, max_depth=max_depth, stage_ms=stage_ms)
    if not inv.evidence_list:
        c.print("[yellow]식별된 증거가 없습니다.[/]")
        raise typer.Exit(0)
    c.print(render_inventory(inv))
    c.print(
        f"[*] 스캔 완료: {inv.scanned_files} 파일 검사, "
        f"{len(inv.evidence_list)} 증거 식별 "
        f"(소요 {stage_ms.get('scan_walk', 0) + stage_ms.get('scan_detect', 0)} ms)."
    )

    # ---------- 2. Selector ----------
    tools_dir, tool_metas = _load_tools_or_exit(c)

    forced = [t.strip() for t in tools.split(",") if t.strip()] if tools else []
    c.print(
        f"[*] 도구 풀: {len(tool_metas)} 개 ({tools_dir}). "
        f"증거 기반 선별 시작..."
    )
    client = None if no_llm else OllamaClient()
    plan = select(
        inv,
        tool_metas,
        quick=quick,
        force_tools=forced or None,
        use_llm=not no_llm,
        client=client,
        stage_ms=stage_ms,
    )

    if not plan.selected_tools:
        c.print("[yellow]적용 가능한 도구가 없습니다.[/]")
        raise typer.Exit(0)

    c.print(f"\n[*] 적용 가능한 도구 {len(plan.selected_tools)} 개 선별됨:")
    for i, sel in enumerate(plan.selected_tools, 1):
        c.print(
            f"  {i}. [bold]{sel.tool_id}[/] "
            f"(prio={sel.priority}, runtime={sel.estimated_runtime}, "
            f"targets={len(sel.target_evidence)})"
        )
        c.print(f"     [dim]{sel.reason}[/]")
    if plan.llm_used:
        msg = "LLM 우선순위 보강 ok" if not plan.llm_fallback else "LLM 실패 → 기본 우선순위 fallback"
        c.print(f"[dim]({msg})[/]")

    if dry_run:
        c.print("\n[dim]--dry-run: stopping after plan.[/]")
        raise typer.Exit(0)

    if not _approve(c, auto=auto, prompt="\n계속 진행할까요? [Y/n] "):
        c.print("[yellow]사용자 취소.[/]")
        raise typer.Exit(0)

    # ---------- 3. Executor ----------
    out_dir = (output_dir or Path.cwd() / settings.OUTPUT_DIR_NAME).resolve()
    raw_out_dir = out_dir / "raw"
    c.print(f"\n[*] 도구 실행 중 (output → {out_dir})...")
    bundle = execute(
        plan,
        tool_metas,
        output_dir=raw_out_dir,
        timeout_sec=(timeout or None),
        console=c,
        stage_ms=stage_ms,
    )

    success_n = sum(1 for r in bundle.results if r.status == "success")
    fail_n = sum(1 for r in bundle.results if r.status in ("failed", "timeout"))
    skip_n = sum(1 for r in bundle.results if r.status == "skipped")
    c.print(
        f"[*] 실행 완료: success={success_n}, failed={fail_n}, skipped={skip_n}"
    )

    # ---------- 4. Analyzer ----------
    c.print("[*] 의심항목 추출 중...")
    analyses = analyze_all(
        bundle.results,
        tool_metas,
        use_llm=not no_llm,
        client=client,
        stage_ms=stage_ms,
    )

    # ---------- 5. Reporter ----------
    c.print("[*] 리포트 생성 중...\n")
    report, paths = write_report(
        inventory=inv,
        plan=plan,
        execution=bundle,
        analyses=analyses,
        started_at=started_at,
        working_directory=str(target),
        output_dir=out_dir,
        console=c,
        stage_ms=stage_ms,
    )

    if paths:
        c.print("")
        for fmt, p in paths.items():
            c.print(f"[green]리포트 저장됨 ({fmt}):[/] {p}")


@app.command("shell")
def shell_cmd(
    path: Optional[Path] = typer.Option(
        None, "--path",
        help="Initial target directory (default: CWD).",
        exists=False, file_okay=False, dir_okay=True,
    ),
    output_dir: Optional[Path] = typer.Option(
        None, "--output-dir",
        help="Where to write tool outputs + report (default: ./forensicagent_output).",
    ),
    no_llm: bool = typer.Option(
        False, "--no-llm",
        help="Disable LLM (Selector stage-2 + Analyzer LLM extract off).",
    ),
    quick: bool = typer.Option(
        False, "--quick", help="Only short-runtime tools when planning.",
    ),
) -> None:
    """Launch the interactive REPL (forensic> prompt)."""
    c = console()
    _, tool_metas = _load_tools_or_exit(c)
    state = make_session(
        path=path,
        output_dir=output_dir,
        tool_metas=tool_metas,
        options=SessionOptions(no_llm=no_llm, quick=quick),
    )
    raise typer.Exit(run_repl(state))


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
    # 우선순위: user dir → repo cwd fallback.
    candidates = [Path(settings.TOOLS_METADATA_DIR), Path.cwd() / "tools_metadata"]
    c = console()
    for tdir in candidates:
        yamls = sorted(list(tdir.glob("*.yaml")) + list(tdir.glob("*.yml"))) if tdir.exists() else []
        if yamls:
            c.print(f"[bold]tool metadata in {tdir}:[/]")
            for y in yamls:
                c.print(f"  - {y.name}")
            return
    c.print(f"[yellow]no YAMLs found in: {', '.join(map(str, candidates))}[/]")


@tools_app.command("info")
def tools_info(
    tool_id: str = typer.Argument(..., help="Tool ID (matches YAML filename stem).")
) -> None:
    """Print contents of tool metadata YAML."""
    candidates = [Path(settings.TOOLS_METADATA_DIR), Path.cwd() / "tools_metadata"]
    for tdir in candidates:
        for ext in (".yaml", ".yml"):
            f = tdir / f"{tool_id}{ext}"
            if f.exists():
                console().print(f.read_text(encoding="utf-8"))
                return
    console().print(f"[red]not found:[/] {tool_id}")
    raise typer.Exit(1)


if __name__ == "__main__":
    app()
