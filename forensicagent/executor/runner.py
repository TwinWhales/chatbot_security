"""Single-tool runner — subprocess with timeout, stdout/stderr to files.

핵심 안전 규칙 (명세 2.3):
  * shell=False  — 사용자 파일명에 셸 메타문자가 있을 수 있음.
  * 결과는 메모리가 아니라 파일로. tail bytes 만 보고 size_bytes 누적.
  * 타임아웃 필수.
"""

from __future__ import annotations

import hashlib
import logging
import os
import shlex
import signal
import stat
import subprocess
import time
from pathlib import Path

from forensicagent.executor.types import ArtifactRole, ExecutionResult, OutputArtifact
from forensicagent.tools.schema import ToolMetadata

logger = logging.getLogger(__name__)


def _create_windows_kill_job() -> int:
    """Create a Job Object that kills every assigned process when closed."""
    import ctypes
    from ctypes import wintypes

    class _BasicLimits(ctypes.Structure):
        _fields_ = [
            ("PerProcessUserTimeLimit", ctypes.c_longlong),
            ("PerJobUserTimeLimit", ctypes.c_longlong),
            ("LimitFlags", wintypes.DWORD),
            ("MinimumWorkingSetSize", ctypes.c_size_t),
            ("MaximumWorkingSetSize", ctypes.c_size_t),
            ("ActiveProcessLimit", wintypes.DWORD),
            ("Affinity", ctypes.c_size_t),
            ("PriorityClass", wintypes.DWORD),
            ("SchedulingClass", wintypes.DWORD),
        ]

    class _IoCounters(ctypes.Structure):
        _fields_ = [
            ("ReadOperationCount", ctypes.c_ulonglong),
            ("WriteOperationCount", ctypes.c_ulonglong),
            ("OtherOperationCount", ctypes.c_ulonglong),
            ("ReadTransferCount", ctypes.c_ulonglong),
            ("WriteTransferCount", ctypes.c_ulonglong),
            ("OtherTransferCount", ctypes.c_ulonglong),
        ]

    class _ExtendedLimits(ctypes.Structure):
        _fields_ = [
            ("BasicLimitInformation", _BasicLimits),
            ("IoInfo", _IoCounters),
            ("ProcessMemoryLimit", ctypes.c_size_t),
            ("JobMemoryLimit", ctypes.c_size_t),
            ("PeakProcessMemoryUsed", ctypes.c_size_t),
            ("PeakJobMemoryUsed", ctypes.c_size_t),
        ]

    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel32.CreateJobObjectW.argtypes = [ctypes.c_void_p, wintypes.LPCWSTR]
    kernel32.CreateJobObjectW.restype = wintypes.HANDLE
    kernel32.SetInformationJobObject.argtypes = [
        wintypes.HANDLE,
        ctypes.c_int,
        ctypes.c_void_p,
        wintypes.DWORD,
    ]
    kernel32.SetInformationJobObject.restype = wintypes.BOOL
    kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
    kernel32.CloseHandle.restype = wintypes.BOOL

    handle = kernel32.CreateJobObjectW(None, None)
    if not handle:
        raise ctypes.WinError(ctypes.get_last_error())
    limits = _ExtendedLimits()
    limits.BasicLimitInformation.LimitFlags = 0x00002000
    if not kernel32.SetInformationJobObject(
        handle,
        9,  # JobObjectExtendedLimitInformation
        ctypes.byref(limits),
        ctypes.sizeof(limits),
    ):
        error = ctypes.get_last_error()
        kernel32.CloseHandle(handle)
        raise ctypes.WinError(error)
    return int(handle)


def _assign_windows_kill_job(handle: int, proc: subprocess.Popen) -> None:
    import ctypes
    from ctypes import wintypes

    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel32.AssignProcessToJobObject.argtypes = [wintypes.HANDLE, wintypes.HANDLE]
    kernel32.AssignProcessToJobObject.restype = wintypes.BOOL
    if not kernel32.AssignProcessToJobObject(handle, int(proc._handle)):
        raise ctypes.WinError(ctypes.get_last_error())


def _terminate_windows_kill_job(handle: int) -> None:
    import ctypes
    from ctypes import wintypes

    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel32.TerminateJobObject.argtypes = [wintypes.HANDLE, wintypes.UINT]
    kernel32.TerminateJobObject.restype = wintypes.BOOL
    if not kernel32.TerminateJobObject(handle, 1):
        raise ctypes.WinError(ctypes.get_last_error())


def _close_windows_kill_job(handle: int) -> None:
    import ctypes
    from ctypes import wintypes

    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
    kernel32.CloseHandle.restype = wintypes.BOOL
    if not kernel32.CloseHandle(handle):
        raise ctypes.WinError(ctypes.get_last_error())


def run_tool(
    metadata: ToolMetadata,
    argv: list[str],
    evidence_path: str,
    output_dir: Path,
    *,
    timeout_sec: int,
    run_index: int = 0,
    command_template_used: str = "",
) -> ExecutionResult:
    """단일 도구 1회 실행.

    Args:
        metadata: 도구 메타데이터 (output_format, output_size_estimate 등 사용).
        argv: shlex 로 분해된 인자 리스트 (shell=False 로 그대로 전달).
        evidence_path: 어떤 증거에 대한 실행인지 기록용.
        output_dir: stdout/stderr 가 저장될 디렉토리. 호출자가 mkdir 보장.
        timeout_sec: 도구 최대 실행 시간.
        run_index: 같은 도구가 여러 evidence 에 적용될 때 파일 충돌 방지.

    Returns:
        ExecutionResult. 어떤 예외도 외부로 전파하지 않음.
    """
    del run_index  # retained in the public signature for backwards compatibility.
    output_dir.mkdir(parents=True, exist_ok=True)
    # Tool processes must never inherit a caller/evidence working directory.
    # The executor creates one isolated job directory per invocation; resolving
    # it here also makes stream artifact paths stable for programmatic callers.
    output_dir = output_dir.resolve(strict=True)
    stdout_path = output_dir / "stdout"
    stderr_path = output_dir / "stderr"
    command_display = _command_display(argv)

    result = ExecutionResult(
        tool_id=metadata.tool_id,
        target_evidence=evidence_path,
        command_executed=command_display,
        command_template_used=command_template_used,
        stdout_path=str(stdout_path),
        stderr_path=str(stderr_path),
        output_format=metadata.output_format,
    )

    start = time.perf_counter()
    timed_out = False
    exit_code = -1
    windows_job: int | None = None
    try:
        with open(stdout_path, "wb") as out_f, open(stderr_path, "wb") as err_f:
            # 어떤 옵션으로 실행했는지 stderr 파일 상단에 기록한다.
            # (stdout 은 도구의 정형 출력이라 Analyzer 가 그대로 파싱 —
            #  헤더를 넣으면 JSON 이 깨지므로 stderr 쪽에만 남긴다.)
            header = (
                "=== COMMAND EXECUTED ===\n"
                f"{command_display}\n"
                "========================\n\n"
            ).encode("utf-8")
            err_f.write(header)
            err_f.flush()
            popen_kwargs: dict[str, object] = {}
            if os.name == "nt":
                popen_kwargs["creationflags"] = getattr(
                    subprocess, "CREATE_NEW_PROCESS_GROUP", 0
                )
                windows_job = _create_windows_kill_job()
            else:
                # A private process group lets timeout handling terminate child
                # processes spawned by the forensic tool as well as the parent.
                popen_kwargs["start_new_session"] = True
            proc = subprocess.Popen(
                argv,
                stdout=out_f,
                stderr=err_f,
                cwd=output_dir,
                shell=False,
                **popen_kwargs,
            )
            if windows_job is not None:
                try:
                    _assign_windows_kill_job(windows_job, proc)
                except OSError:
                    proc.kill()
                    proc.wait(timeout=5)
                    raise
            try:
                exit_code = proc.wait(timeout=timeout_sec)
            except subprocess.TimeoutExpired:
                timed_out = True
                result.warnings.extend(
                    _terminate_process_tree(proc, windows_job=windows_job)
                )
    except FileNotFoundError as e:
        result.duration_seconds = time.perf_counter() - start
        result.status = "failed"
        result.exit_code = -1
        result.error_message = f"executable not found: {e}"
        _finalize_stream_artifacts(result, metadata)
        return result
    except OSError as e:
        result.duration_seconds = time.perf_counter() - start
        result.status = "failed"
        result.exit_code = -1
        result.error_message = f"OS error: {e}"
        _finalize_stream_artifacts(result, metadata)
        return result
    finally:
        if windows_job is not None:
            try:
                _close_windows_kill_job(windows_job)
            except OSError as e:
                result.warnings.append(f"Windows process containment close failed: {e}")

    result.duration_seconds = time.perf_counter() - start
    if timed_out:
        result.status = "timeout"
        result.exit_code = -1
        result.error_message = f"timeout after {timeout_sec}s"
        _finalize_stream_artifacts(result, metadata)
        return result

    result.exit_code = exit_code
    result.status = "success" if exit_code == 0 else "failed"
    if result.status == "failed":
        # 짧은 stderr 요약을 메시지에 담는다 (긴 출력은 파일로).
        result.error_message = _tail_text(stderr_path, max_bytes=512) or (
            f"exit code {exit_code}"
        )
    _finalize_stream_artifacts(result, metadata)
    return result


def _command_display(argv: list[str]) -> str:
    if os.name == "nt":
        return subprocess.list2cmdline(argv)
    return shlex.join(argv)


def _system_taskkill() -> Path | None:
    """Return the real System32 taskkill, never a PATH/CWD substitute."""
    system_root = os.environ.get("SystemRoot", "")
    root = Path(system_root)
    if not system_root or not root.is_absolute():
        return None
    expected_parent = root / "System32"
    candidate = expected_parent / "taskkill.exe"
    try:
        resolved_parent = expected_parent.resolve(strict=True)
        resolved = candidate.resolve(strict=True)
        if resolved.parent != resolved_parent or resolved.name.casefold() != "taskkill.exe":
            return None
        return resolved if resolved.is_file() else None
    except OSError:
        return None


def _terminate_process_tree(
    proc: subprocess.Popen,
    *,
    windows_job: int | None = None,
) -> list[str]:
    """Best-effort termination of the process and every descendant."""
    warnings: list[str] = []
    if proc.poll() is not None:
        return warnings

    if os.name == "nt":
        if windows_job is not None:
            try:
                _terminate_windows_kill_job(windows_job)
                proc.wait(timeout=5)
                return warnings
            except (OSError, subprocess.TimeoutExpired) as e:
                warnings.append(f"Windows Job Object termination failed: {e}")
        taskkill = _system_taskkill()
        if taskkill is None:
            warnings.append("trusted System32 taskkill.exe unavailable")
        else:
            try:
                completed = subprocess.run(
                    [str(taskkill), "/PID", str(proc.pid), "/T", "/F"],
                    capture_output=True,
                    text=True,
                    timeout=5,
                    cwd=taskkill.parent,
                    check=False,
                )
                if completed.returncode != 0 and proc.poll() is None:
                    detail = (completed.stderr or completed.stdout or "").strip()
                    warnings.append(
                        "taskkill could not terminate full process tree: "
                        f"{detail[:200]}"
                    )
            except (OSError, subprocess.TimeoutExpired) as e:
                warnings.append(f"taskkill unavailable: {e}")
    else:
        try:
            os.killpg(proc.pid, signal.SIGTERM)
        except ProcessLookupError:
            return warnings
        except OSError as e:
            warnings.append(f"SIGTERM process-group failed: {e}")

    try:
        proc.wait(timeout=1)
    except subprocess.TimeoutExpired:
        pass

    if os.name != "nt":
        # The direct child may exit on SIGTERM while a descendant in the same
        # process group ignores it. Probe and kill the group independently.
        try:
            os.killpg(proc.pid, 0)
        except ProcessLookupError:
            return warnings
        except OSError as e:
            warnings.append(f"process-group probe failed: {e}")
        try:
            os.killpg(proc.pid, signal.SIGKILL)
        except ProcessLookupError:
            return warnings
        except OSError as e:
            warnings.append(f"SIGKILL process-group failed: {e}")
    elif proc.poll() is not None:
        return warnings
    if proc.poll() is None:
        try:
            proc.kill()
        except OSError as e:
            warnings.append(f"parent process kill failed: {e}")
    try:
        proc.wait(timeout=5)
    except subprocess.TimeoutExpired:
        warnings.append("process remained alive after timeout termination")
    return warnings


def _finalize_stream_artifacts(
    result: ExecutionResult,
    metadata: ToolMetadata,
) -> None:
    p = Path(result.stdout_path)
    if p.exists():
        try:
            result.output_size_bytes = p.stat().st_size
            result.artifacts.append(
                describe_artifact(p, role="stdout", output_format=metadata.output_format)
            )
        except OSError as e:
            result.warnings.append(f"could not manifest stdout: {e}")
    err = Path(result.stderr_path)
    if err.exists():
        try:
            result.artifacts.append(
                describe_artifact(err, role="stderr", output_format="text")
            )
        except OSError as e:
            result.warnings.append(f"could not manifest stderr: {e}")


def describe_artifact(
    path: str | Path,
    *,
    role: ArtifactRole,
    output_format: str,
) -> OutputArtifact:
    """Build a size/hash manifest entry for a completed output file."""
    p = Path(path)
    digest = hashlib.sha256()
    with open(p, "rb") as f:
        while chunk := f.read(1024 * 1024):
            digest.update(chunk)
    return OutputArtifact(
        path=str(p),
        role=role,
        format=output_format,
        size_bytes=p.stat().st_size,
        sha256=digest.hexdigest(),
    )


def collect_generated_artifacts(
    generated_dir: str | Path,
    *,
    default_format: str,
) -> tuple[list[OutputArtifact], list[str]]:
    """Recursively manifest regular files created in a job's generated dir."""
    root = Path(generated_dir)
    artifacts: list[OutputArtifact] = []
    warnings: list[str] = []
    if not root.is_dir():
        return artifacts, warnings
    paths: list[Path] = []
    pending = [root]
    while pending:
        directory = pending.pop()
        try:
            entries = list(os.scandir(directory))
        except OSError as e:
            warnings.append(f"could not enumerate generated outputs in {directory}: {e}")
            continue
        for entry in entries:
            path = Path(entry.path)
            try:
                value = entry.stat(follow_symlinks=False)
                is_reparse = bool(
                    getattr(value, "st_file_attributes", 0)
                    & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
                )
                if entry.is_symlink() or is_reparse:
                    warnings.append(f"ignored generated link/reparse point: {path}")
                    continue
                if entry.is_dir(follow_symlinks=False):
                    pending.append(path)
                elif entry.is_file(follow_symlinks=False):
                    paths.append(path)
            except OSError as e:
                warnings.append(f"could not inspect generated output {path}: {e}")
    paths.sort(key=lambda path: str(path).lower())
    for path in paths:
        try:
            artifacts.append(
                describe_artifact(
                    path,
                    role="generated",
                    output_format=_infer_format(path, default_format),
                )
            )
        except OSError as e:
            warnings.append(f"could not manifest generated output {path}: {e}")
    return artifacts, warnings


def _infer_format(path: Path, default: str) -> str:
    by_suffix = {
        ".csv": "csv",
        ".json": "json",
        ".jsonl": "jsonl",
        ".ndjson": "jsonl",
        ".txt": "text",
        ".log": "text",
        ".xml": "text",
    }
    return by_suffix.get(path.suffix.lower(), default or "binary")


def _tail_text(path: Path, max_bytes: int) -> str:
    try:
        with open(path, "rb") as f:
            f.seek(0, 2)
            size = f.tell()
            f.seek(max(0, size - max_bytes))
            data = f.read()
        return data.decode("utf-8", errors="replace").strip()
    except OSError:
        return ""
