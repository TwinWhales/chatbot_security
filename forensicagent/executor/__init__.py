"""Executor — Layer 4 도구 실행 (subprocess 격리)."""

from forensicagent.executor.adapter import GenericAdapter, get_adapter, register_adapter
from forensicagent.executor.executor import execute
from forensicagent.executor.types import ExecStatus, ExecutionBundle, ExecutionResult

__all__ = [
    "execute",
    "ExecutionResult",
    "ExecutionBundle",
    "ExecStatus",
    "GenericAdapter",
    "get_adapter",
    "register_adapter",
]
