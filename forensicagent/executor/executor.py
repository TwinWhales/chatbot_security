"""Executor orchestrator.

Each tool/evidence pair runs in an isolated job directory.  Jobs share one
priority-aware scheduler; tools marked non-parallelizable are serialized per
tool while remaining able to overlap with jobs from other tools.
"""

from __future__ import annotations

import inspect
import logging
import re
import threading
import uuid
from concurrent.futures import FIRST_COMPLETED, Future, ThreadPoolExecutor, wait
from dataclasses import dataclass
from pathlib import Path

from rich.console import Console
from rich.progress import (
    BarColumn,
    Progress,
    SpinnerColumn,
    TextColumn,
    TimeElapsedColumn,
)

from forensicagent import config as settings
from forensicagent.executor.adapter import GenericAdapter, get_adapter
from forensicagent.executor.runner import collect_generated_artifacts, run_tool
from forensicagent.executor.types import (
    MAX_INLINE_JSON_BYTES,
    ExecutionBundle,
    ExecutionResult,
)
from forensicagent.observability import Stopwatch
from forensicagent.selector.types import Plan, ToolSelection
from forensicagent.tools.executables import resolve_executable
from forensicagent.tools.schema import ToolMetadata

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class _Job:
    sequence: int
    selection: ToolSelection
    metadata: ToolMetadata
    evidence: str
    command_template: str
    variables: dict[str, str]
    label: str = ""

    @property
    def priority(self) -> int:
        return self.selection.priority


PreflightResult = tuple[bool, str]


def _build_jobs(plan: Plan, tools: dict[str, ToolMetadata]) -> list[_Job]:
    """Expand the plan and return a stable priority-descending job list."""
    expanded: list[
        tuple[int, ToolSelection, ToolMetadata, str, str, dict[str, str], str]
    ] = []
    original_order = 0
    for selection in plan.selected_tools:
        metadata = tools.get(selection.tool_id)
        if metadata is None:
            logger.warning(
                "plan references unknown tool_id=%r, skipping", selection.tool_id
            )
            continue
        if selection.run_specs:
            specs = [
                (
                    spec.target_evidence,
                    spec.command_template,
                    dict(spec.variables),
                    spec.label,
                )
                for spec in selection.run_specs
            ]
        else:
            specs = [
                (evidence, selection.command_template, {}, "")
                for evidence in selection.target_evidence
            ]
        for evidence, command_template, variables, label in specs:
            expanded.append(
                (
                    original_order,
                    selection,
                    metadata,
                    evidence,
                    command_template,
                    variables,
                    label,
                )
            )
            original_order += 1

    expanded.sort(key=lambda item: (-item[1].priority, item[0]))
    return [
        _Job(
            sequence=index,
            selection=selection,
            metadata=metadata,
            evidence=evidence,
            command_template=command_template,
            variables=variables,
            label=label,
        )
        for index, (
            _,
            selection,
            metadata,
            evidence,
            command_template,
            variables,
            label,
        ) in enumerate(expanded, 1)
    ]


def _preflight_tools(jobs: list[_Job]) -> dict[str, PreflightResult]:
    """Validate prerequisites exactly once for each tool in this execution."""
    results: dict[str, PreflightResult] = {}
    for job in jobs:
        tool_id = job.metadata.tool_id
        if tool_id in results:
            continue
        try:
            results[tool_id] = get_adapter(job.metadata).validate_prerequisites()
        except Exception as e:  # noqa: BLE001 - a bad adapter must not abort the run.
            results[tool_id] = (False, f"preflight crashed: {e}")
    return results


def _safe_slug(value: str, *, fallback: str) -> str:
    cleaned = re.sub(r"[^A-Za-z0-9._-]+", "_", value).strip("._-")
    return (cleaned or fallback)[:60]


def _make_job_dirs(root: Path, job: _Job) -> tuple[Path, Path]:
    tool = _safe_slug(job.metadata.tool_id, fallback="tool")
    evidence = _safe_slug(Path(job.evidence).name, fallback="evidence")
    unique = uuid.uuid4().hex[:10]
    job_dir = root / f"{job.sequence:04d}_{tool}_{evidence}_{unique}"
    generated_dir = job_dir / "generated"
    generated_dir.mkdir(parents=True, exist_ok=False)
    return job_dir, generated_dir


def _adapter_accepts_preferred_template(adapter: GenericAdapter) -> bool:
    try:
        parameters = inspect.signature(adapter.build_command).parameters.values()
    except (TypeError, ValueError):
        return True
    return any(
        parameter.name == "preferred_template"
        or parameter.kind == inspect.Parameter.VAR_KEYWORD
        for parameter in parameters
    )


def _build_command(
    adapter: GenericAdapter,
    job: _Job,
    generated_dir: Path,
) -> tuple[list[str], str]:
    preferred = job.command_template or None
    kwargs = dict(job.variables)
    # The executor owns output isolation; a plan cannot redirect generated
    # files into another job's directory via template variables.
    kwargs["output_dir"] = str(generated_dir)
    if preferred and _adapter_accepts_preferred_template(adapter):
        kwargs["preferred_template"] = preferred
    argv = adapter.build_command(job.evidence, **kwargs)
    if not argv:
        raise ValueError("adapter returned an empty command")

    resolved = resolve_executable(argv[0])
    if resolved is None:
        raise FileNotFoundError(
            f"command executable {argv[0]!r} not found on PATH or tools_bin"
        )
    argv[0] = str(resolved)

    selected = getattr(adapter, "selected_template", "") or ""
    if not selected:
        # A custom adapter may construct argv without a metadata template.  Do
        # not claim its preferred metadata template was actually executed.
        implementation = type(adapter).build_command
        if implementation is not GenericAdapter.build_command:
            selected = f"custom:{type(adapter).__name__}"
        else:
            selected = preferred or ""
    return argv, selected


def _execute_one(
    job: _Job,
    output_dir: Path,
    timeout_sec: int,
    preflight: PreflightResult,
) -> ExecutionResult:
    metadata = job.metadata
    ok, detail = preflight
    if not ok:
        return ExecutionResult(
            tool_id=metadata.tool_id,
            target_evidence=job.evidence,
            status="skipped",
            exit_code=-1,
            error_message=f"prerequisites failed: {detail}",
            output_format=metadata.output_format,
        )

    try:
        job_dir, generated_dir = _make_job_dirs(output_dir, job)
    except OSError as e:
        return ExecutionResult(
            tool_id=metadata.tool_id,
            target_evidence=job.evidence,
            status="failed",
            exit_code=-1,
            error_message=f"failed to create isolated job directory: {e}",
            output_format=metadata.output_format,
        )

    adapter = get_adapter(metadata)
    try:
        argv, selected_template = _build_command(adapter, job, generated_dir)
    except (FileNotFoundError, KeyError, IndexError, TypeError, ValueError) as e:
        return ExecutionResult(
            tool_id=metadata.tool_id,
            target_evidence=job.evidence,
            status="failed",
            command_template_used=getattr(adapter, "selected_template", "") or "",
            exit_code=-1,
            error_message=f"failed to build command: {e}",
            output_format=metadata.output_format,
        )

    result = run_tool(
        metadata=metadata,
        argv=argv,
        evidence_path=job.evidence,
        output_dir=job_dir,
        timeout_sec=timeout_sec,
        run_index=job.sequence,
        command_template_used=selected_template,
    )

    generated, warnings = collect_generated_artifacts(
        generated_dir,
        default_format=metadata.output_format,
    )
    result.artifacts.extend(generated)
    result.warnings.extend(warnings)

    expects_generated_output = "{output_dir}" in selected_template
    if result.status == "success" and expects_generated_output and not generated:
        message = (
            "selected command template expected generated output, but no files "
            f"were produced under {generated_dir}"
        )
        result.status = "output_missing"
        result.error_message = message
        result.warnings.append(message)

    # Preserve the legacy stdout JSON fast-path only for genuinely small
    # output. Large JSON remains available through the artifact manifest and
    # is never duplicated into the report payload.
    if result.status in ("success", "output_missing"):
        if (
            metadata.output_format == "json"
            and result.output_size_bytes > MAX_INLINE_JSON_BYTES
        ):
            result.warnings.append(
                "JSON eager parse/report embedding skipped: stdout is "
                f"{result.output_size_bytes} bytes (limit "
                f"{MAX_INLINE_JSON_BYTES}); raw artifact retained"
            )
        else:
            result.parsed_output = adapter.parse_output(result.stdout_path)
    return result


def _execute_with_lock(
    lock: threading.Lock,
    job: _Job,
    output_dir: Path,
    timeout_sec: int,
    preflight: PreflightResult,
) -> ExecutionResult:
    with lock:
        return _execute_one(job, output_dir, timeout_sec, preflight)


def _crashed_result(job: _Job, error: Exception) -> ExecutionResult:
    return ExecutionResult(
        tool_id=job.metadata.tool_id,
        target_evidence=job.evidence,
        status="failed",
        exit_code=-1,
        error_message=f"executor crashed: {error}",
        output_format=job.metadata.output_format,
    )


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
    """Execute every planned job with isolation, manifests, and failure isolation."""
    out_dir = Path(output_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    timeout = timeout_sec if timeout_sec is not None else settings.DEFAULT_TIMEOUT_SEC
    max_par = max_parallel if max_parallel is not None else settings.MAX_PARALLEL_TOOLS
    if max_par < 1:
        raise ValueError(f"max_parallel must be >= 1, got {max_par}")

    jobs = _build_jobs(plan, tools)
    bundle = ExecutionBundle(output_dir=str(out_dir), parallel_max=max_par)
    if not jobs:
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
        task_id = progress.add_task("Running tools", total=len(jobs))

    completed: dict[int, ExecutionResult] = {}
    try:
        with Stopwatch() as sw:
            preflight = _preflight_tools(jobs)
            pending: list[_Job] = []
            for job in jobs:
                check = preflight[job.metadata.tool_id]
                if check[0]:
                    pending.append(job)
                    continue
                completed[job.sequence] = _execute_one(
                    job, out_dir, timeout, check
                )
                if progress is not None and task_id is not None:
                    progress.update(
                        task_id,
                        advance=1,
                        description=f"[skipped] {job.metadata.tool_id}",
                    )

            serial_locks = {
                job.metadata.tool_id: threading.Lock()
                for job in pending
                if not job.metadata.parallelizable
            }
            active_serial_tools: set[str] = set()

            with ThreadPoolExecutor(max_workers=max_par) as pool:
                futures: dict[Future[ExecutionResult], _Job] = {}
                while pending or futures:
                    while len(futures) < max_par and pending:
                        eligible_index = next(
                            (
                                index
                                for index, job in enumerate(pending)
                                if job.metadata.parallelizable
                                or job.metadata.tool_id not in active_serial_tools
                            ),
                            None,
                        )
                        if eligible_index is None:
                            break
                        job = pending.pop(eligible_index)
                        check = preflight[job.metadata.tool_id]
                        if job.metadata.parallelizable:
                            future = pool.submit(
                                _execute_one, job, out_dir, timeout, check
                            )
                        else:
                            active_serial_tools.add(job.metadata.tool_id)
                            future = pool.submit(
                                _execute_with_lock,
                                serial_locks[job.metadata.tool_id],
                                job,
                                out_dir,
                                timeout,
                                check,
                            )
                        futures[future] = job

                    if not futures:
                        # Defensive guard: the eligibility rules above should
                        # always leave at least one runnable pending job.
                        break

                    done, _ = wait(futures, return_when=FIRST_COMPLETED)
                    for future in done:
                        job = futures.pop(future)
                        if not job.metadata.parallelizable:
                            active_serial_tools.discard(job.metadata.tool_id)
                        try:
                            result = future.result()
                        except Exception as e:  # noqa: BLE001
                            result = _crashed_result(job, e)
                        completed[job.sequence] = result
                        if progress is not None and task_id is not None:
                            progress.update(
                                task_id,
                                advance=1,
                                description=f"[{result.status}] {result.tool_id}",
                            )

        if stage_ms is not None:
            stage_ms["execute"] = stage_ms.get("execute", 0) + sw.elapsed_ms
    finally:
        if progress is not None:
            progress.stop()

    bundle.results = [completed[index] for index in sorted(completed)]
    return bundle
