"""REPL 세션 상태 — Scanner~Reporter 결과물을 턴 사이에 들고 다닌다."""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

from forensicagent import config as settings
from forensicagent.analyzer.types import ToolAnalysis
from forensicagent.executor.types import ExecutionBundle
from forensicagent.llm import OllamaClient
from forensicagent.reporter.types import Report, now_iso
from forensicagent.scanner.types import Inventory
from forensicagent.selector.types import Plan
from forensicagent.tools.schema import ToolMetadata


@dataclass
class SessionOptions:
    no_llm: bool = False
    quick: bool = False
    max_depth: int = 5
    timeout_sec: int = 0
    forced_tools: list[str] = field(default_factory=list)
    auto_yes: bool = True  # REPL 안에서는 매 단계 사용자 입력이 곧 승인.


@dataclass
class SessionState:
    target_path: Path
    output_dir: Path
    tool_metas: dict[str, ToolMetadata]
    options: SessionOptions = field(default_factory=SessionOptions)

    inventory: Optional[Inventory] = None
    plan: Optional[Plan] = None
    bundle: Optional[ExecutionBundle] = None
    analyses: Optional[list[ToolAnalysis]] = None
    last_report: Optional[Report] = None
    last_report_paths: dict[str, Path] = field(default_factory=dict)

    started_at: str = field(default_factory=now_iso)
    stage_ms: dict[str, int] = field(default_factory=dict)
    _client: Optional[OllamaClient] = None

    def client(self) -> Optional[OllamaClient]:
        if self.options.no_llm:
            return None
        if self._client is None:
            self._client = OllamaClient()
        return self._client

    def reset_run(self) -> None:
        """Scanner 이후 결과만 비운다 (옵션은 유지)."""
        self.inventory = None
        self.plan = None
        self.bundle = None
        self.analyses = None
        self.last_report = None
        self.last_report_paths = {}
        self.started_at = now_iso()
        self.stage_ms = {}


def make_session(
    *,
    path: Optional[Path],
    output_dir: Optional[Path],
    tool_metas: dict[str, ToolMetadata],
    options: Optional[SessionOptions] = None,
) -> SessionState:
    target = (path or Path(os.getcwd())).resolve()
    out_dir = (output_dir or Path.cwd() / settings.OUTPUT_DIR_NAME).resolve()
    return SessionState(
        target_path=target,
        output_dir=out_dir,
        tool_metas=tool_metas,
        options=options or SessionOptions(),
    )
