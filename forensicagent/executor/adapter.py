"""ToolAdapter — 도구별 커스터마이즈 포인트.

명세 2.3 의 어댑터 패턴 구현. 도구마다 출력 형식과 검증 방법이 다르므로
이 인터페이스를 통해 캡슐화한다.

기본 구현 (GenericAdapter) 은 YAML 메타데이터만으로 작동:
  * validate_prerequisites: install_check 의 command 를 실행, expected_pattern 매칭
  * build_command: command_template 의 {evidence_path} placeholder 치환,
    shlex 로 안전하게 토큰화
  * parse_output: output_format 이 json 이면 json.loads, 아니면 raw text
  * get_metadata: ToolMetadata 그대로 반환

도구마다 더 정교한 로직이 필요하면 GenericAdapter 를 상속해서 register_adapter 로 등록.
"""

from __future__ import annotations

import json
import logging
import shlex
import shutil
import subprocess
from pathlib import Path
from typing import Any, Optional, Protocol

from forensicagent.tools.schema import ToolMetadata

logger = logging.getLogger(__name__)


class ToolAdapter(Protocol):
    def validate_prerequisites(self) -> tuple[bool, str]: ...
    def build_command(self, evidence_path: str, **vars: str) -> list[str]: ...
    def parse_output(self, stdout_path: str) -> Optional[dict[str, Any]]: ...
    def get_metadata(self) -> ToolMetadata: ...


class GenericAdapter:
    """YAML 메타데이터만으로 동작하는 기본 어댑터."""

    def __init__(self, metadata: ToolMetadata) -> None:
        self._meta = metadata

    # ---- prerequisites ----

    def validate_prerequisites(self) -> tuple[bool, str]:
        check = self._meta.install_check
        if check is None:
            # check 가 없으면 PATH 에 tool_id 가 있는지만 확인 (best effort).
            if shutil.which(self._meta.tool_id) is None:
                return False, f"{self._meta.tool_id} not on PATH"
            return True, f"{self._meta.tool_id} found on PATH"

        try:
            argv = shlex.split(check.command, posix=False)
        except ValueError as e:
            return False, f"invalid install_check.command: {e}"

        # 명령의 첫 토큰이 PATH 에 없으면 즉시 실패.
        if argv and shutil.which(argv[0]) is None:
            return False, f"{argv[0]} not on PATH"

        try:
            proc = subprocess.run(
                argv,
                capture_output=True,
                text=True,
                timeout=10,
                shell=False,
                check=False,
            )
        except (subprocess.TimeoutExpired, OSError) as e:
            return False, f"install_check failed to run: {e}"

        haystack = (proc.stdout or "") + (proc.stderr or "")
        if check.expected_pattern in haystack:
            return True, f"{self._meta.tool_id} {check.expected_pattern} found"
        return False, (
            f"install_check stdout/stderr did not contain "
            f"{check.expected_pattern!r}"
        )

    # ---- command building ----

    def build_command(self, evidence_path: str, **vars: str) -> list[str]:
        """Pick the first command_template and substitute placeholders.

        Selector 가 더 똑똑한 템플릿 선택을 한다면 evidence_path 외에
        추가 변수를 vars 로 넘긴다.
        """
        tpl = self._meta.command_templates[0].template
        substituted = tpl.format(evidence_path=evidence_path, **vars)
        return shlex.split(substituted, posix=False)

    # ---- output parsing ----

    def parse_output(self, stdout_path: str) -> Optional[dict[str, Any]]:
        p = Path(stdout_path)
        if not p.exists() or p.stat().st_size == 0:
            return None
        if self._meta.output_format != "json":
            return None
        # 출력이 small 일 때만 즉시 파싱; 대용량은 Analyzer 가 스트리밍.
        if self._meta.output_size_estimate == "large":
            return None
        try:
            text = p.read_text(encoding="utf-8", errors="replace")
        except OSError as e:
            logger.warning("parse_output: cannot read %s: %s", p, e)
            return None
        try:
            return _parse_json_or_ndjson(text)
        except json.JSONDecodeError as e:
            logger.warning("parse_output: JSON decode failed for %s: %s", p, e)
            return None

    def get_metadata(self) -> ToolMetadata:
        return self._meta


def _parse_json_or_ndjson(text: str) -> dict[str, Any]:
    """JSON object/array 단일 문서, 또는 NDJSON 을 dict 로 정규화."""
    stripped = text.strip()
    if not stripped:
        return {"items": []}

    # NDJSON: 첫 char 가 '{' 이고 줄마다 '{' 로 시작하면 줄별 파싱.
    if "\n" in stripped and all(
        ln.lstrip().startswith(("{", "["))
        for ln in stripped.splitlines()
        if ln.strip()
    ):
        items: list[Any] = []
        for ln in stripped.splitlines():
            ln = ln.strip()
            if not ln:
                continue
            try:
                items.append(json.loads(ln))
            except json.JSONDecodeError:
                # 단일 문서 시도로 폴백.
                break
        else:
            return {"items": items}

    parsed = json.loads(stripped)
    if isinstance(parsed, list):
        return {"items": parsed}
    if isinstance(parsed, dict):
        return parsed
    return {"value": parsed}


# ---------- registry ----------

# 도구별 커스텀 어댑터를 등록할 수 있다. 미등록이면 GenericAdapter.
_REGISTRY: dict[str, type] = {}


def register_adapter(tool_id: str, adapter_cls: type) -> None:
    _REGISTRY[tool_id] = adapter_cls


def get_adapter(metadata: ToolMetadata) -> GenericAdapter:
    cls = _REGISTRY.get(metadata.tool_id, GenericAdapter)
    return cls(metadata)
