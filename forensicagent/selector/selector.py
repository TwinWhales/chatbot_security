"""Selector orchestrator — 2단계 하이브리드.

  Stage 1 (filter.py)   결정론 evidence_type 매칭
  Stage 2 (llm_rank.py) LLM 우선순위 보강 (실패시 Stage 1 결과 그대로)

CLI 플래그 매핑:
  --auto       Stage 2 까지 실행 후 사용자 승인 없이 다음으로 (CLI 영역).
  --quick      Stage 1 이후 estimated_runtime == "short" 만 통과.
  --tools t1,t2  Stage 1/2 모두 건너뛰고 명시 도구만 (force_tools).
"""

from __future__ import annotations

import logging
from typing import Iterable

from forensicagent.llm import OllamaClient
from forensicagent.observability import Stopwatch
from forensicagent.scanner.types import Inventory
from forensicagent.selector.filter import filter_by_evidence, skipped_by_evidence_gap
from forensicagent.selector.llm_rank import rank_with_llm
from forensicagent.selector.types import Plan, ToolSelection
from forensicagent.tools.schema import ToolMetadata

logger = logging.getLogger(__name__)


def _build_forced(
    force_tools: Iterable[str],
    inventory: Inventory,
    tools: dict[str, ToolMetadata],
) -> list[ToolSelection]:
    out: list[ToolSelection] = []
    by_type: dict[str, list[str]] = {}
    for e in inventory.evidence_list:
        by_type.setdefault(e.evidence_type, []).append(e.path)

    for tid in force_tools:
        meta = tools.get(tid)
        if meta is None:
            logger.warning("--tools requested unknown tool_id=%r, skipping", tid)
            continue
        targets: list[str] = []
        for et in meta.applicable_evidence_types:
            targets.extend(by_type.get(et, []))
        out.append(
            ToolSelection(
                tool_id=tid,
                tool_version=meta.version_supported,
                reason="forced by --tools",
                target_evidence=targets,
                command_template=meta.command_templates[0].template,
                estimated_runtime=meta.estimated_runtime,
                priority=10,
            )
        )
    return out


def select(
    inventory: Inventory,
    tools: dict[str, ToolMetadata],
    *,
    quick: bool = False,
    force_tools: list[str] | None = None,
    use_llm: bool = True,
    client: OllamaClient | None = None,
    stage_ms: dict[str, int] | None = None,
) -> Plan:
    """Return the execution Plan.

    use_llm=False 는 테스트/오프라인용 (Stage 2 건너뛰기).
    """
    plan = Plan()

    if force_tools:
        with Stopwatch() as sw:
            plan.selected_tools = _build_forced(force_tools, inventory, tools)
            plan.stage_one_candidates = len(plan.selected_tools)
        if stage_ms is not None:
            stage_ms["select_force"] = (
                stage_ms.get("select_force", 0) + sw.elapsed_ms
            )
        return plan

    # ---- Stage 1: deterministic filter ----
    with Stopwatch() as sw:
        candidates = filter_by_evidence(inventory, tools)
        plan.skipped_no_evidence = skipped_by_evidence_gap(inventory, tools)
    if stage_ms is not None:
        stage_ms["select_filter"] = stage_ms.get("select_filter", 0) + sw.elapsed_ms

    if quick:
        candidates = [c for c in candidates if c.estimated_runtime == "short"]
    plan.stage_one_candidates = len(candidates)

    if not candidates:
        return plan

    # ---- Stage 2: LLM ranking ----
    if not use_llm:
        plan.selected_tools = candidates
        return plan

    with Stopwatch() as sw:
        ranked, used, fallback = rank_with_llm(candidates, tools, inventory, client)
    if stage_ms is not None:
        stage_ms["select_rank"] = stage_ms.get("select_rank", 0) + sw.elapsed_ms

    plan.selected_tools = ranked
    plan.llm_used = used
    plan.llm_fallback = fallback
    return plan
