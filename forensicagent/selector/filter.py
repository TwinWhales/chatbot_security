"""Stage 1 — 결정론 필터링.

증거 인벤토리의 evidence_type 집합과 각 도구의 applicable_evidence_types
교집합으로 후보를 추린다. LLM 호출 없음. 50 → 10~15 개 까지 줄이는 단계.
"""

from __future__ import annotations

from forensicagent.scanner.types import Inventory
from forensicagent.selector.types import ToolSelection
from forensicagent.tools.schema import ToolMetadata


def filter_by_evidence(
    inventory: Inventory,
    tools: dict[str, ToolMetadata],
) -> list[ToolSelection]:
    """Stage 1 결과를 ToolSelection list 로 반환.

    target_evidence 에는 매칭된 evidence path 들이 들어간다.
    command_template 은 첫 번째 템플릿을 기본으로 (Selector 가 LLM 으로 더
    구체화하면 덮어쓸 수 있게 둠).
    """
    # evidence_type → [evidence.path] 인덱스.
    by_type: dict[str, list[str]] = {}
    for e in inventory.evidence_list:
        if e.evidence_type == "unknown":
            continue
        by_type.setdefault(e.evidence_type, []).append(e.path)

    selections: list[ToolSelection] = []
    for tool_id, meta in tools.items():
        targets: list[str] = []
        matched_types: list[str] = []
        for et in meta.applicable_evidence_types:
            if et in by_type:
                targets.extend(by_type[et])
                matched_types.append(et)
        if not targets:
            continue

        reason = (
            f"{', '.join(matched_types)} 증거가 발견되어 "
            f"{meta.display_name} 적용 가능 ({meta.category})."
        )
        selections.append(
            ToolSelection(
                tool_id=tool_id,
                tool_version=meta.version_supported,
                reason=reason,
                target_evidence=targets,
                command_template=meta.command_templates[0].template,
                estimated_runtime=meta.estimated_runtime,
                priority=5,
            )
        )
    return selections


def skipped_by_evidence_gap(
    inventory: Inventory,
    tools: dict[str, ToolMetadata],
) -> list[str]:
    """Stage 1 에서 떨어진 도구 id 목록. UX 에 '왜 안 돌렸나' 표시 용."""
    present = {e.evidence_type for e in inventory.evidence_list}
    return [
        tid
        for tid, m in tools.items()
        if not set(m.applicable_evidence_types) & present
    ]
