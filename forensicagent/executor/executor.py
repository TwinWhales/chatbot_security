"""Executor orchestrator.

  * Plan 의 각 ToolSelection 에 대해 target_evidence 개수만큼 run_tool() 호출.
  * parallelizable=True 인 도구들은 ThreadPoolExecutor (subprocess 는 IO bound).
    parallelizable=False 인 도구들은 직렬.
  * 한 도구 실패해도 다른 도구는 계속 (failure isolation).
  * Rich Progress 로 진행 상황 표시.
"""

from __future__ import annotations

import logging
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Any

from rich.console import Console
from rich.progress import (
    BarColumn,
    Progress,
    SpinnerColumn,
    TextColumn,
    TimeElapsedColumn,
)

from forensicagent import config as settings
from forensicagent.executor.adapter import get_adapter
from forensicagent.executor.runner import run_tool
from forensicagent.executor.types import ExecutionBundle, ExecutionResult
from forensicagent.observability import Stopwatch
from forensicagent.selector.types import Plan
from forensicagent.tools.schema import ToolMetadata

logger = logging.getLogger(__name__)


def _build_jobs(
    plan: Plan,
    tools: dict[str, ToolMetadata],
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """parallel jobs + serial jobs 로 분리.

    한 job 은 (selection, metadata, evidence_path, parallelizable) 묶음.
    """
    parallel: list[dict[str, Any]] = []
    serial: list[dict[str, Any]] = []
    for sel in plan.selected_tools:
        meta = tools.get(sel.tool_id)
        if meta is None:
            logger.warning("plan references unknown tool_id=%r, skipping", sel.tool_id)
            continue
        bucket = parallel if meta.parallelizable else serial
        if not sel.target_evidence:
            continue
        for evi in sel.target_evidence:
            bucket.append({"sel": sel, "meta": meta, "evidence": evi})
    return parallel, serial


def _execute_one(
    job: dict[str, Any],
    output_dir: Path,
    timeout_sec: int,
    run_index: int,
) -> ExecutionResult:
    meta: ToolMetadata = job["meta"]
    evidence: str = job["evidence"]
    adapter = get_adapter(meta)

    ok, detail = adapter.validate_prerequisites()
    if not ok:
        return ExecutionResult(
            tool_id=meta.tool_id,
            target_evidence=evidence,
            status="skipped",
            command_executed="",
            stdout_path="",
            stderr_path="",
            exit_code=-1,
            error_message=f"prerequisites failed: {detail}",
            output_format=meta.output_format,
        )

    try:
        argv = adapter.build_command(evidence, output_dir=str(output_dir))
    except (KeyError, IndexError, ValueError) as e:
        return ExecutionResult(
            tool_id=meta.tool_id,
            target_evidence=evidence,
            status="failed",
            command_executed="",
            error_message=f"failed to build command: {e}",
            output_format=meta.output_format,
        )

    result = run_tool(
        metadata=meta,
        argv=argv,
        evidence_path=evidence,
        output_dir=output_dir,
        timeout_sec=timeout_sec,
        run_index=run_index,
    )

    # Parsed inline output for small/json tools (Analyzer Case A 에 도움).
    if result.status == "success":
        result.parsed_output = adapter.parse_output(result.stdout_path)
    return result


def execute(
    plan: Plan,
    tools: dict[str, ToolMetadata],
    *,
    output_dir: str | Path,
    timeout_sec: int | None = None,
    max_parallel: int | None = None,
    console: Console | None = None,
    stage_ms: dict[str, int] | None = None,
) -> ExecutionBundle:
    """모든 ToolSelection 을 실행하고 결과 묶음 반환."""
    out_dir = Path(output_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    timeout = timeout_sec if timeout_sec is not None else settings.DEFAULT_TIMEOUT_SEC
    max_par = max_parallel if max_parallel is not None else settings.MAX_PARALLEL_TOOLS

    parallel_jobs, serial_jobs = _build_jobs(plan, tools)
    total = len(parallel_jobs) + len(serial_jobs)
    bundle = ExecutionBundle(output_dir=str(out_dir), parallel_max=max_par)

    if total == 0:
        return bundle

    progress: Progress | None = None
    task_id = None
    if console is not None:
        progress = Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TextColumn("{task.completed}/{task.total}"),
            TimeElapsedColumn(),
            console=console,
            transient=False,
        )
        progress.start()
        task_id = progress.add_task("Running tools", total=total)

    counter = 0

    with Stopwatch() as sw:
        # ---- parallel ----
        if parallel_jobs:
            with ThreadPoolExecutor(max_workers=max_par) as pool:
                futures = {}
                for job in parallel_jobs:
                    counter += 1
                    futures[pool.submit(_execute_one, job, out_dir, timeout, counter)] = job
                for fut in as_completed(futures):
                    job = futures[fut]
                    try:
                        res = fut.result()
                    except Exception as e:  # noqa: BLE001 — runner caught most, but keep safety net.
                        res = ExecutionResult(
                            tool_id=job["meta"].tool_id,
                            target_evidence=job["evidence"],
                            status="failed",
                            error_message=f"executor crashed: {e}",
                        )
                    bundle.results.append(res)
                    if progress and task_id is not None:
                        progress.update(
                            task_id,
                            advance=1,
                            description=f"[parallel] {res.tool_id}",
                        )

        # ---- serial ----
        for job in serial_jobs:
            counter += 1
            try:
                res = _execute_one(job, out_dir, timeout, counter)
            except Exception as e:  # noqa: BLE001
                res = ExecutionResult(
                    tool_id=job["meta"].tool_id,
                    target_evidence=job["evidence"],
                    status="failed",
                    error_message=f"executor crashed: {e}",
                )
            bundle.results.append(res)
            if progress and task_id is not None:
                progress.update(
                    task_id, advance=1, description=f"[serial] {res.tool_id}"
                )

    if progress is not None:
        progress.stop()

    if stage_ms is not None:
        stage_ms["execute"] = stage_ms.get("execute", 0) + sw.elapsed_ms

    return bundle
