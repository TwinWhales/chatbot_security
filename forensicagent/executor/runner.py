"""Single-tool runner — subprocess with timeout, stdout/stderr to files.

핵심 안전 규칙 (명세 2.3):
  * shell=False  — 사용자 파일명에 셸 메타문자가 있을 수 있음.
  * 결과는 메모리가 아니라 파일로. tail bytes 만 보고 size_bytes 누적.
  * 타임아웃 필수.
"""

from __future__ import annotations

import logging
import subprocess
import time
from pathlib import Path

from forensicagent.executor.types import ExecutionResult
from forensicagent.tools.schema import ToolMetadata

logger = logging.getLogger(__name__)


def run_tool(
    metadata: ToolMetadata,
    argv: list[str],
    evidence_path: str,
    output_dir: Path,
    *,
    timeout_sec: int,
    run_index: int = 0,
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
    safe_tool = metadata.tool_id.replace("/", "_")
    safe_evi = Path(evidence_path).name.replace("/", "_")
    base = output_dir / f"{run_index:02d}_{safe_tool}_{safe_evi}"
    stdout_path = base.with_suffix(".stdout")
    stderr_path = base.with_suffix(".stderr")

    result = ExecutionResult(
        tool_id=metadata.tool_id,
        target_evidence=evidence_path,
        command_executed=" ".join(argv),
        stdout_path=str(stdout_path),
        stderr_path=str(stderr_path),
        output_format=metadata.output_format,
    )

    start = time.perf_counter()
    try:
        with open(stdout_path, "wb") as out_f, open(stderr_path, "wb") as err_f:
            proc = subprocess.Popen(
                argv,
                stdout=out_f,
                stderr=err_f,
                shell=False,
            )
            try:
                exit_code = proc.wait(timeout=timeout_sec)
            except subprocess.TimeoutExpired:
                proc.kill()
                # Drain so the OS can release the file handles cleanly.
                try:
                    proc.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    pass
                result.duration_seconds = time.perf_counter() - start
                result.status = "timeout"
                result.exit_code = -1
                result.error_message = f"timeout after {timeout_sec}s"
                _fill_size(result)
                return result
    except FileNotFoundError as e:
        result.duration_seconds = time.perf_counter() - start
        result.status = "failed"
        result.exit_code = -1
        result.error_message = f"executable not found: {e}"
        _fill_size(result)
        return result
    except OSError as e:
        result.duration_seconds = time.perf_counter() - start
        result.status = "failed"
        result.exit_code = -1
        result.error_message = f"OS error: {e}"
        _fill_size(result)
        return result

    result.duration_seconds = time.perf_counter() - start
    result.exit_code = exit_code
    result.status = "success" if exit_code == 0 else "failed"
    if result.status == "failed":
        # 짧은 stderr 요약을 메시지에 담는다 (긴 출력은 파일로).
        result.error_message = _tail_text(stderr_path, max_bytes=512) or (
            f"exit code {exit_code}"
        )
    _fill_size(result)
    return result


def _fill_size(result: ExecutionResult) -> None:
    p = Path(result.stdout_path)
    if p.exists():
        result.output_size_bytes = p.stat().st_size


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
