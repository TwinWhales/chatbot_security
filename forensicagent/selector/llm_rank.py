"""Stage 2 — LLM 기반 우선순위/리즌 보강.

Stage 1 통과 후보들의 메타데이터를 컨텍스트로 LLM 에게 JSON 응답을
강제한다. JSON 파싱 실패하면 Stage 1 결과를 그대로 fallback.

LLM 은 priority (1~10) 와 보강된 reason 만 반환한다.
"""

from __future__ import annotations

import logging
from typing import Any

from forensicagent.llm import JsonRetryFailed, OllamaClient, OllamaUnavailable
from forensicagent.llm.ollama_client import ChatMessage
from forensicagent.scanner.types import Inventory
from forensicagent.selector.types import ToolSelection
from forensicagent.tools.schema import ToolMetadata

logger = logging.getLogger(__name__)


_SYSTEM_PROMPT = (
    "You are a forensic triage planner. Given an evidence inventory and a "
    "shortlist of candidate tools (already filtered by evidence-type match), "
    "you must prioritize them.\n"
    "Rules:\n"
    " - Avoid redundancy: if two tools cover the same category, prefer the "
    "more authoritative one and lower the other's priority.\n"
    " - Higher priority = run sooner. Range 1..10, 10 = run first.\n"
    " - Briefly justify each ranking in `reason` (one short sentence, KO or EN).\n"
    " - Reply with ONLY a JSON object of the form:\n"
    '   {\"rankings\": [{\"tool_id\": \"<id>\", \"priority\": <int>, '
    '\"reason\": \"<sentence>\"}]}'
)


def _inventory_summary(inventory: Inventory) -> str:
    by_type: dict[str, int] = {}
    for e in inventory.evidence_list:
        by_type[e.evidence_type] = by_type.get(e.evidence_type, 0) + 1
    parts = [f"{t}={n}" for t, n in sorted(by_type.items())]
    return ", ".join(parts) or "(empty)"


def _candidates_block(
    candidates: list[ToolSelection],
    metas: dict[str, ToolMetadata],
) -> str:
    lines = []
    for c in candidates:
        m = metas.get(c.tool_id)
        if m is None:
            continue
        desc = (m.usage_description or "").strip().splitlines()
        short = " ".join(desc[:2])[:240]
        lines.append(
            f"- {c.tool_id} [{m.category}/{m.subcategory or '-'}] "
            f"runtime={m.estimated_runtime} parallel={m.parallelizable} "
            f"targets={len(c.target_evidence)} :: {short}"
        )
    return "\n".join(lines)


def rank_with_llm(
    candidates: list[ToolSelection],
    metas: dict[str, ToolMetadata],
    inventory: Inventory,
    client: OllamaClient | None = None,
) -> tuple[list[ToolSelection], bool, bool]:
    """LLM 으로 priority/reason 보강.

    Returns:
        (selections, llm_used, llm_fallback)
        llm_used: 실제로 LLM 호출에 도달했는지.
        llm_fallback: JSON 파싱/Ollama 실패로 입력 후보를 그대로 반환했는지.
    """
    if not candidates:
        return [], False, False

    client = client or OllamaClient()
    user_msg = (
        f"Evidence inventory: {_inventory_summary(inventory)}\n\n"
        f"Candidate tools:\n{_candidates_block(candidates, metas)}\n\n"
        "Return the JSON object now."
    )

    try:
        parsed: Any = client.json_chat(
            [
                ChatMessage(role="system", content=_SYSTEM_PROMPT),
                ChatMessage(role="user", content=user_msg),
            ],
            retry=1,
        )
    except OllamaUnavailable as e:
        logger.info("LLM unavailable, using Stage 1 ranking as-is: %s", e)
        return candidates, False, True
    except JsonRetryFailed as e:
        logger.warning("LLM JSON parse failed twice, falling back: %s", e)
        return candidates, True, True

    rankings = parsed.get("rankings") if isinstance(parsed, dict) else None
    if not isinstance(rankings, list):
        logger.warning("LLM response missing 'rankings' list, falling back")
        return candidates, True, True

    # tool_id → (priority, reason)
    by_id: dict[str, tuple[int, str]] = {}
    for r in rankings:
        if not isinstance(r, dict):
            continue
        tid = r.get("tool_id")
        if not isinstance(tid, str):
            continue
        prio = r.get("priority", 5)
        if not isinstance(prio, int):
            try:
                prio = int(prio)
            except (TypeError, ValueError):
                prio = 5
        prio = max(1, min(10, prio))
        reason = r.get("reason") or ""
        by_id[tid] = (prio, str(reason))

    # 입력 candidates 의 순서를 유지하면서 priority/reason 만 갱신.
    # LLM 이 추천하지 않은 도구는 hallucination 방지를 위해 그대로 둔다.
    out: list[ToolSelection] = []
    for c in candidates:
        if c.tool_id in by_id:
            prio, reason = by_id[c.tool_id]
            out.append(
                ToolSelection(
                    tool_id=c.tool_id,
                    tool_version=c.tool_version,
                    reason=reason or c.reason,
                    target_evidence=c.target_evidence,
                    command_template=c.command_template,
                    estimated_runtime=c.estimated_runtime,
                    priority=prio,
                )
            )
        else:
            out.append(c)

    # priority 내림차순 정렬.
    out.sort(key=lambda s: s.priority, reverse=True)
    return out, True, False
