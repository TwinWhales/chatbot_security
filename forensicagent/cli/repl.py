"""Slash-command REPL — `forensicagent` 인터랙티브 셸.

기존 5 단계 파이프라인 (Scanner -> Selector -> Executor -> Analyzer -> Reporter)
함수들을 그대로 재사용. REPL 은 단지 그 호출을 사용자가 한 단계씩 (또는
/auto 로 한 번에) 트리거하게 해 주는 얇은 디스패처.

Phase B (자연어 라우터) 가 이 위에 얹힐 때, LLM 은 같은 do_* 함수를
호출하면 된다.
"""

from __future__ import annotations

import shlex
import sys
import traceback
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Optional

from rich.table import Table

from forensicagent import __version__
from forensicagent.analyzer import analyze_all
from forensicagent.analyzer.types import SEVERITY_RANK, ToolAnalysis
from forensicagent.cli.session import SessionState
from forensicagent.cli.ui import console, render_inventory
from forensicagent.executor import execute
from forensicagent.reporter import write as write_report
from forensicagent.scanner import scan
from forensicagent.selector import select


# ---------------------------------------------------------------------------
# do_* functions: REPL 명령 + (장차) LLM 라우터가 공유할 단위 액션
# ---------------------------------------------------------------------------


def do_scenario(state: SessionState, c, text: str = "") -> None:
    """조사 시나리오를 세션에 설정/표시/해제한다.

    /scenario <자유 텍스트>  → 설정 (Selector·Analyzer LLM 컨텍스트로 주입)
    /scenario                → 현재 시나리오 표시
    /scenario clear          → 해제
    """
    text = text.strip()
    if not text:
        if state.scenario:
            c.print(f"[*] 현재 시나리오: [cyan]{state.scenario}[/]")
        else:
            c.print("[dim](시나리오 없음 — /scenario <설명> 으로 설정)[/]")
        return
    if text.lower() in ("clear", "none", "reset"):
        state.scenario = None
        c.print("[*] 시나리오 해제됨.")
        return
    state.scenario = text
    c.print(f"[green]시나리오 설정됨:[/] {text}")
    c.print("[dim](/plan 과 /analyze 의 LLM 단계에 컨텍스트로 주입됩니다.)[/]")


def do_scan(
    state: SessionState, c, *, path: Optional[Path] = None,
    scenario: Optional[str] = None,
) -> None:
    if scenario and scenario.strip():
        state.scenario = scenario.strip()
        c.print(f"[green]시나리오 설정됨:[/] {state.scenario}")
    target = (path or state.target_path).resolve()
    if not target.exists():
        c.print(f"[red]경로가 없습니다:[/] {target}")
        return
    state.target_path = target
    c.print(f"[*] 스캔 시작: {target}")
    inv = scan(
        target,
        max_depth=state.options.max_depth,
        stage_ms=state.stage_ms,
    )
    state.inventory = inv
    if not inv.evidence_list:
        c.print("[yellow]식별된 증거가 없습니다.[/]")
        return
    c.print(render_inventory(inv))
    walk = state.stage_ms.get("scan_walk", 0)
    detect = state.stage_ms.get("scan_detect", 0)
    c.print(
        f"[*] 스캔 완료: {inv.scanned_files} 파일, "
        f"{len(inv.evidence_list)} 증거 ({walk + detect} ms)."
    )


def do_plan(state: SessionState, c) -> None:
    if state.inventory is None:
        c.print("[yellow]먼저 /scan 으로 증거 인벤토리를 만드세요.[/]")
        return
    forced = state.options.forced_tools or None
    plan = select(
        state.inventory,
        state.tool_metas,
        quick=state.options.quick,
        force_tools=forced,
        use_llm=not state.options.no_llm,
        use_rag=state.options.use_rag,
        client=state.client(),
        scenario=state.scenario,
        stage_ms=state.stage_ms,
    )
    state.plan = plan
    if not plan.selected_tools:
        c.print("[yellow]적용 가능한 도구가 없습니다.[/]")
        return
    c.print(f"[*] 선별 {len(plan.selected_tools)} 개 도구:")
    for i, sel in enumerate(plan.selected_tools, 1):
        c.print(
            f"  {i}. [bold]{sel.tool_id}[/] "
            f"(prio={sel.priority}, runtime={sel.estimated_runtime}, "
            f"targets={len(sel.target_evidence)})"
        )
        c.print(f"     [dim]{sel.reason}[/]")
    if plan.rag_used:
        c.print("[dim](RAG 관련도 재정렬 + 컨텍스트 주입 적용됨)[/]")
    if plan.llm_used:
        msg = "LLM 우선순위 보강 ok" if not plan.llm_fallback else "LLM 실패 -> 기본 우선순위"
        c.print(f"[dim]({msg})[/]")


def do_run(state: SessionState, c) -> None:
    if state.plan is None or not state.plan.selected_tools:
        c.print("[yellow]먼저 /plan 으로 도구 계획을 만드세요.[/]")
        return
    raw_dir = state.output_dir / "raw"
    c.print(f"[*] 도구 실행 (output -> {raw_dir})...")
    bundle = execute(
        state.plan,
        state.tool_metas,
        output_dir=raw_dir,
        timeout_sec=(state.options.timeout_sec or None),
        console=c,
        stage_ms=state.stage_ms,
    )
    state.bundle = bundle
    s = sum(1 for r in bundle.results if r.status == "success")
    f = sum(1 for r in bundle.results if r.status in ("failed", "timeout"))
    k = sum(1 for r in bundle.results if r.status == "skipped")
    c.print(f"[*] 실행 완료: success={s}, failed={f}, skipped={k}")


def do_analyze(state: SessionState, c) -> None:
    if state.bundle is None:
        c.print("[yellow]먼저 /run 으로 도구를 실행하세요.[/]")
        return
    analyses = analyze_all(
        state.bundle.results,
        state.tool_metas,
        use_llm=not state.options.no_llm,
        use_rag=state.options.use_rag,
        client=state.client(),
        scenario=state.scenario,
        stage_ms=state.stage_ms,
    )
    state.analyses = analyses
    total = sum(len(a.findings) for a in analyses)
    c.print(f"[*] 분석 완료: {len(analyses)} 도구, {total} findings.")
    for a in analyses:
        if a.findings:
            c.print(f"  - {a.tool_id}: {len(a.findings)} findings")


def do_report(state: SessionState, c) -> None:
    if (
        state.inventory is None
        or state.plan is None
        or state.bundle is None
        or state.analyses is None
    ):
        c.print("[yellow]리포트 직전까지의 단계가 부족합니다 (scan/plan/run/analyze).[/]")
        return
    c.print("[*] 리포트 생성 중...")
    report, paths = write_report(
        inventory=state.inventory,
        plan=state.plan,
        execution=state.bundle,
        analyses=state.analyses,
        started_at=state.started_at,
        working_directory=str(state.target_path),
        output_dir=state.output_dir,
        console=c,
        stage_ms=state.stage_ms,
    )
    state.last_report = report
    state.last_report_paths = paths
    for fmt, p in paths.items():
        c.print(f"[green]리포트 저장됨 ({fmt}):[/] {p}")


def do_auto(state: SessionState, c) -> None:
    """전 파이프라인 한 번에."""
    state.reset_run()
    do_scan(state, c)
    if state.inventory is None or not state.inventory.evidence_list:
        return
    do_plan(state, c)
    if state.plan is None or not state.plan.selected_tools:
        return
    do_run(state, c)
    do_analyze(state, c)
    do_report(state, c)


# ---------------------------------------------------------------------------
# Show / status / set
# ---------------------------------------------------------------------------


def do_show(state: SessionState, c, what: str) -> None:
    what = what.lower().strip()
    if what in ("inventory", "inv"):
        if state.inventory is None:
            c.print("[yellow](비어 있음)[/]")
            return
        c.print(render_inventory(state.inventory))
    elif what == "plan":
        if state.plan is None:
            c.print("[yellow](비어 있음)[/]")
            return
        for i, sel in enumerate(state.plan.selected_tools, 1):
            c.print(f"  {i}. {sel.tool_id} (prio={sel.priority}) - {sel.reason}")
    elif what in ("findings", "finding"):
        if state.analyses is None:
            c.print("[yellow](비어 있음)[/]")
            return
        t = Table(title="Findings", show_lines=False)
        t.add_column("tool", style="bold")
        t.add_column("severity")
        t.add_column("category")
        t.add_column("title", overflow="fold")
        all_findings: list[tuple[str, object]] = []
        for a in state.analyses:
            for f in a.findings:
                all_findings.append((a.tool_id, f))
        all_findings.sort(
            key=lambda x: SEVERITY_RANK.get(getattr(x[1], "severity", "low"), 0),
            reverse=True,
        )
        for tool_id, f in all_findings:
            t.add_row(
                tool_id,
                _sev_style(getattr(f, "severity", "low")),
                getattr(f, "category", ""),
                getattr(f, "title", "") or getattr(f, "description", ""),
            )
        if not all_findings:
            c.print("[yellow](findings 없음)[/]")
        else:
            c.print(t)
    elif what == "report":
        if not state.last_report_paths:
            c.print("[yellow](리포트 미생성)[/]")
            return
        for fmt, p in state.last_report_paths.items():
            c.print(f"  {fmt}: {p}")
    else:
        c.print(f"[red]알 수 없는 show 대상:[/] {what}")
        c.print("  사용: /show inventory | plan | findings | report")


def _sev_style(s: str) -> str:
    colors = {"high": "red", "medium": "yellow", "low": "dim"}
    return f"[{colors.get(s, 'white')}]{s}[/]"


def do_status(state: SessionState, c) -> None:
    o = state.options
    t = Table(title="session", show_header=False, show_lines=False)
    t.add_row("path", str(state.target_path))
    t.add_row("scenario", state.scenario or "-")
    t.add_row("output_dir", str(state.output_dir))
    t.add_row("tools loaded", str(len(state.tool_metas)))
    t.add_row("no_llm", str(o.no_llm))
    t.add_row("quick", str(o.quick))
    t.add_row("use_rag", str(o.use_rag))
    t.add_row("max_depth", str(o.max_depth))
    t.add_row("timeout_sec", str(o.timeout_sec or "default"))
    t.add_row("forced_tools", ",".join(o.forced_tools) or "-")
    t.add_row(
        "state",
        f"inv={'Y' if state.inventory else '-'} "
        f"plan={'Y' if state.plan else '-'} "
        f"run={'Y' if state.bundle else '-'} "
        f"analyze={'Y' if state.analyses else '-'} "
        f"report={'Y' if state.last_report else '-'}",
    )
    c.print(t)


def do_set(state: SessionState, c, key: str, value: str) -> None:
    key = key.lower()
    o = state.options
    if key == "no_llm":
        o.no_llm = _to_bool(value)
        state._client = None  # 다음 호출 때 다시 생성
    elif key == "quick":
        o.quick = _to_bool(value)
    elif key == "rag":
        o.use_rag = _to_bool(value)
    elif key == "max_depth":
        o.max_depth = int(value)
    elif key == "timeout":
        o.timeout_sec = int(value)
    elif key == "tools":
        o.forced_tools = [t.strip() for t in value.split(",") if t.strip()]
    elif key in ("output_dir", "out"):
        state.output_dir = Path(value).resolve()
    elif key == "path":
        state.target_path = Path(value).resolve()
    else:
        c.print(f"[red]알 수 없는 키:[/] {key}")
        c.print(
            "  가능: no_llm, quick, rag, max_depth, timeout, tools, output_dir, path"
        )
        return
    c.print(f"[green]ok[/] {key} = {value}")


def _to_bool(v: str) -> bool:
    return v.lower() in ("1", "true", "y", "yes", "on")


def do_tools(state: SessionState, c, arg: str = "") -> None:
    arg = arg.strip()
    if not arg or arg == "list":
        t = Table(title=f"tools ({len(state.tool_metas)})", show_lines=False)
        t.add_column("id", style="bold")
        t.add_column("category")
        t.add_column("evidence")
        t.add_column("runtime")
        for m in state.tool_metas.values():
            t.add_row(
                m.tool_id,
                m.category,
                ",".join(m.applicable_evidence_types),
                m.estimated_runtime,
            )
        c.print(t)
    else:
        # /tools info <id>
        parts = arg.split(None, 1)
        if len(parts) == 2 and parts[0] == "info":
            tid = parts[1].strip()
            meta = state.tool_metas.get(tid)
            if meta is not None:
                c.print(meta.model_dump_json(indent=2))
                return
            c.print(f"[red]not found:[/] {tid}")
        else:
            c.print("  사용: /tools | /tools list | /tools info <id>")


def do_cd(state: SessionState, c, path: str) -> None:
    p = Path(path).expanduser().resolve()
    if not p.exists() or not p.is_dir():
        c.print(f"[red]디렉토리가 아닙니다:[/] {p}")
        return
    state.target_path = p
    c.print(f"[*] target_path -> {p}")


def do_clear(state: SessionState, c) -> None:
    state.reset_run()
    c.print("[*] 실행 상태 초기화 (옵션은 유지).")


def do_help(c) -> None:
    c.print(
        "[bold]commands[/]\n"
        "  [cyan]/scan[/] [path]         증거 인벤토리 작성\n"
        "  [cyan]/scenario[/] <설명>     조사 시나리오 설정 (plan/analyze LLM 에 주입)\n"
        "  [cyan]/plan[/]                도구 선별 (selector)\n"
        "  [cyan]/run[/]                 선별된 도구 실행\n"
        "  [cyan]/analyze[/]             출력에서 의심항목 추출\n"
        "  [cyan]/report[/]              JSON+MD 리포트 저장\n"
        "  [cyan]/auto[/]                scan -> plan -> run -> analyze -> report\n"
        "\n"
        "  [cyan]/show[/] <대상>         inventory | plan | findings | report\n"
        "  [cyan]/status[/]              현재 세션 상태\n"
        "  [cyan]/set[/] <키> <값>       no_llm/quick/max_depth/timeout/tools/path/output_dir\n"
        "  [cyan]/cd[/] <path>           target_path 변경\n"
        "  [cyan]/tools[/] [info <id>]   도구 목록 / 상세\n"
        "  [cyan]/clear[/]               실행 상태 초기화\n"
        "  [cyan]/help[/] [cyan]?[/]            이 도움말\n"
        "  [cyan]/quit[/] [cyan]/exit[/] [cyan]/q[/]    종료\n"
    )


# ---------------------------------------------------------------------------
# Dispatcher
# ---------------------------------------------------------------------------


@dataclass
class _Cmd:
    name: str
    handler: Callable[..., None]
    min_args: int = 0
    max_args: int = 0


def _build_table(state: SessionState, c) -> dict[str, _Cmd]:
    return {
        "scan": _Cmd("scan", lambda *a: do_scan(state, c, path=Path(a[0]) if a else None), 0, 1),
        "scenario": _Cmd("scenario", lambda *a: do_scenario(state, c, " ".join(a)), 0, 99),
        "inventory": _Cmd("inventory", lambda *a: do_show(state, c, "inventory")),
        "inv": _Cmd("inv", lambda *a: do_show(state, c, "inventory")),
        "plan": _Cmd("plan", lambda *a: do_plan(state, c)),
        "run": _Cmd("run", lambda *a: do_run(state, c)),
        "analyze": _Cmd("analyze", lambda *a: do_analyze(state, c)),
        "report": _Cmd("report", lambda *a: do_report(state, c)),
        "auto": _Cmd("auto", lambda *a: do_auto(state, c)),
        "show": _Cmd("show", lambda *a: do_show(state, c, a[0] if a else ""), 1, 1),
        "status": _Cmd("status", lambda *a: do_status(state, c)),
        "set": _Cmd("set", lambda *a: do_set(state, c, a[0], a[1]), 2, 2),
        "cd": _Cmd("cd", lambda *a: do_cd(state, c, a[0]), 1, 1),
        "tools": _Cmd("tools", lambda *a: do_tools(state, c, " ".join(a)), 0, 2),
        "clear": _Cmd("clear", lambda *a: do_clear(state, c)),
        "help": _Cmd("help", lambda *a: do_help(c)),
        "?": _Cmd("?", lambda *a: do_help(c)),
    }


def _parse_slash(line: str) -> tuple[str, list[str]] | None:
    """슬래시 명령만 파싱. 슬래시 없으면 None (호출자가 NL 로 라우팅)."""
    line = line.strip()
    if not line or not line.startswith("/"):
        return None
    try:
        parts = shlex.split(line[1:])
    except ValueError as e:
        return ("__parse_error__", [str(e)])
    if not parts:
        return None
    return parts[0].lower(), parts[1:]


def run(state: SessionState) -> int:
    """REPL 진입점. 정상 종료 시 0, 비정상 -1."""
    c = console()
    c.print(f"[bold]forensicagent[/] {__version__} [dim](interactive shell)[/]")
    c.print(f"[dim]target: {state.target_path}[/]")
    c.print(f"[dim]tools loaded: {len(state.tool_metas)} (no_llm={state.options.no_llm})[/]")
    if state.options.no_llm:
        c.print("[dim]슬래시 명령 모드 - /help 로 명령 목록.[/]\n")
    else:
        c.print("[dim]/help 로 슬래시 명령, 또는 자연어로도 입력 가능. /quit 종료.[/]\n")

    table = _build_table(state, c)
    quit_words = {"quit", "exit", "q", "/quit", "/exit", "/q"}

    # NL 라우터는 lazy import — Ollama 없는 환경에서 import 단계 부담 0.
    from forensicagent.cli import nl_router

    while True:
        try:
            try:
                line = input("forensic> ")
            except EOFError:
                c.print("")
                return 0
        except KeyboardInterrupt:
            c.print("\n[dim](Ctrl+C - /quit 으로 종료)[/]")
            continue

        stripped = line.strip()
        if not stripped:
            continue
        if stripped.lower() in quit_words:
            return 0

        # 슬래시 명령 우선.
        parsed = _parse_slash(line)
        if parsed is not None:
            cmd, args = parsed
            if cmd == "__parse_error__":
                c.print(f"[red]파싱 에러:[/] {args[0]}")
                continue

            entry = table.get(cmd)
            if entry is None:
                c.print(f"[red]모르는 명령:[/] /{cmd}  [dim](/help 참조)[/]")
                continue
            if len(args) < entry.min_args:
                c.print(f"[red]인자 부족:[/] /{cmd}  [dim](/help 참조)[/]")
                continue
            if entry.max_args and len(args) > entry.max_args:
                c.print(f"[red]인자 너무 많음:[/] /{cmd}  [dim](/help 참조)[/]")
                continue

            try:
                entry.handler(*args)
            except KeyboardInterrupt:
                c.print("\n[yellow]중단됨.[/]")
            except SystemExit:
                c.print("[dim](sub-command exited)[/]")
            except Exception as e:  # noqa: BLE001
                c.print(f"[red]에러:[/] {e}")
                traceback.print_exc(file=sys.stderr)
            continue

        # 슬래시 아니면 자연어 라우팅.
        try:
            nl_router.handle(state, c, stripped)
        except KeyboardInterrupt:
            c.print("\n[yellow]중단됨.[/]")
        except Exception as e:  # noqa: BLE001
            c.print(f"[red]NL 라우팅 에러:[/] {e}")
            traceback.print_exc(file=sys.stderr)
