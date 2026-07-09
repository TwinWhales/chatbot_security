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


def _rag_query(inventory: Inventory, scenario: str | None) -> str:
    """RAG 질의 텍스트 — 증거 타입 분포 + (있으면) 시나리오."""
    by_type: dict[str, int] = {}
    for e in inventory.evidence_list:
        if e.evidence_type == "unknown":
            continue
        by_type[e.evidence_type] = by_type.get(e.evidence_type, 0) + 1
    ev = ", ".join(f"{t}({n})" for t, n in sorted(by_type.items())) or "unknown evidence"
    parts = [f"Evidence present: {ev}."]
    if scenario and scenario.strip():
        parts.append(f"Investigation scenario: {scenario.strip()}")
    parts.append("Which forensic tools are most relevant?")
    return " ".join(parts)


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
    use_rag: bool = True,
    client: OllamaClient | None = None,
    scenario: str | None = None,
    stage_ms: dict[str, int] | None = None,
) -> Plan:
    """Return the execution Plan.

    use_llm=False 는 테스트/오프라인용 (Stage 2 건너뛰기).
    use_rag=True 면 Stage1 후보를 RAG 관련도로 재정렬하고 LLM 컨텍스트에
    스니펫을 주입한다. RAG 는 순서/프롬프트에만 영향 — Stage1 자격 게이트는
    그대로. 의존성/질의 실패 시 조용히 결정론 순서로 폴백.
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

    # ---- RAG: 순서 힌트 + 스니펫 (Stage1 자격은 불변, 실패 시 조용히 폴백) ----
    rag_snippets: dict[str, str] = {}
    if use_rag:
        with Stopwatch() as sw_rag:
            rag_snippets = _apply_rag(plan, candidates, inventory, scenario)
        if stage_ms is not None:
            stage_ms["select_rag"] = (
                stage_ms.get("select_rag", 0) + sw_rag.elapsed_ms
            )

    # ---- Stage 2: LLM ranking ----
    if not use_llm:
        # RAG 가 candidates 를 in-place 재정렬했으므로 그 순서로 확정.
        plan.selected_tools = candidates
        return plan

    with Stopwatch() as sw:
        ranked, used, fallback = rank_with_llm(
            candidates, tools, inventory, client,
            scenario=scenario, rag_snippets=rag_snippets,
        )
    if stage_ms is not None:
        stage_ms["select_rank"] = stage_ms.get("select_rank", 0) + sw.elapsed_ms

    plan.selected_tools = ranked
    plan.llm_used = used
    plan.llm_fallback = fallback
    return plan


def _apply_rag(
    plan: Plan,
    candidates: list[ToolSelection],
    inventory: Inventory,
    scenario: str | None,
) -> dict[str, str]:
    """candidates 를 RAG 관련도로 in-place 재정렬하고 tool_id→스니펫 맵 반환.

    RAG 를 못 쓰면(None) 아무것도 바꾸지 않고 빈 dict 를 반환한다.
    """
    from forensicagent.rag.retrieval import retrieve_tools

    eligible = {c.tool_id for c in candidates}
    hits = retrieve_tools(
        _rag_query(inventory, scenario),
        top_k=len(candidates),
        tool_ids=eligible,
    )
    if not hits:  # None(폴백) 또는 [](관련 히트 없음) → 순서 불변.
        return {}

    score = {h.tool_id: h.score for h in hits}
    snippets = {h.tool_id: h.snippet for h in hits}
    # 관련도 내림차순. 점수 없는(검색 안 걸린) 후보는 -1 로 뒤로.
    candidates.sort(key=lambda c: score.get(c.tool_id, -1.0), reverse=True)
    plan.rag_used = True
    return snippets
