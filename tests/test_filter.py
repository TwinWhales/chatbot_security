"""Selector Stage 1 (결정론 evidence_type 매칭) 테스트.

LLM 의존성 없음 — 합성 Inventory + ToolMetadata fixture 로 교집합 로직만.
"""

from __future__ import annotations

import pytest

from forensicagent.scanner.types import Evidence, Inventory
from forensicagent.selector.filter import filter_by_evidence, skipped_by_evidence_gap
from forensicagent.tools.schema import CommandTemplate, ToolMetadata


def _meta(
    tool_id: str,
    *,
    applicable: list[str],
    category: str = "log_analysis",
    runtime: str = "short",
    parallelizable: bool = True,
) -> ToolMetadata:
    return ToolMetadata(
        tool_id=tool_id,
        display_name=tool_id.title(),
        category=category,
        applicable_evidence_types=applicable,  # type: ignore[arg-type]
        command_templates=[
            CommandTemplate(
                name="default",
                template=f"{tool_id} {{evidence_path}}",
                when="default",
            )
        ],
        usage_description="test",
        estimated_runtime=runtime,  # type: ignore[arg-type]
        parallelizable=parallelizable,
    )


def _evidence(path: str, etype: str) -> Evidence:
    return Evidence(
        path=path,
        filename=path.split("/")[-1],
        size_bytes=100,
        evidence_type=etype,  # type: ignore[arg-type]
        detected_by="magic_bytes",
        platform_hint="unknown",
        confidence=0.9,
    )


@pytest.fixture
def tools_pool() -> dict[str, ToolMetadata]:
    return {
        "chainsaw": _meta("chainsaw", applicable=["evtx_log"]),
        "volatility3": _meta(
            "volatility3",
            applicable=["memory_dump"],
            category="memory_analysis",
            runtime="long",
            parallelizable=False,
        ),
        "regripper": _meta(
            "regripper",
            applicable=["registry_hive"],
            category="registry_analysis",
        ),
        "yara_disk": _meta(
            "yara_disk",
            applicable=["disk_image", "memory_dump"],
            category="string_extraction",
        ),
    }


class TestFilterByEvidence:
    def test_evtx_only_inventory_picks_chainsaw(self, tools_pool):
        inv = Inventory(
            scan_root="/case",
            evidence_list=[_evidence("/case/Security.evtx", "evtx_log")],
        )
        sels = filter_by_evidence(inv, tools_pool)
        tool_ids = {s.tool_id for s in sels}
        assert tool_ids == {"chainsaw"}

    def test_memory_dump_picks_vol_and_yara(self, tools_pool):
        inv = Inventory(
            scan_root="/case",
            evidence_list=[_evidence("/case/memory.raw", "memory_dump")],
        )
        sels = filter_by_evidence(inv, tools_pool)
        tool_ids = {s.tool_id for s in sels}
        assert tool_ids == {"volatility3", "yara_disk"}

    def test_multi_evidence_union(self, tools_pool):
        inv = Inventory(
            scan_root="/case",
            evidence_list=[
                _evidence("/case/Security.evtx", "evtx_log"),
                _evidence("/case/memory.raw", "memory_dump"),
                _evidence("/case/NTUSER.DAT", "registry_hive"),
            ],
        )
        sels = filter_by_evidence(inv, tools_pool)
        tool_ids = {s.tool_id for s in sels}
        assert tool_ids == {"chainsaw", "volatility3", "regripper", "yara_disk"}

    def test_unknown_evidence_ignored(self, tools_pool):
        """unknown 타입은 어떤 도구에도 매칭되면 안 된다."""
        inv = Inventory(
            scan_root="/case",
            evidence_list=[_evidence("/case/file.xyz", "unknown")],
        )
        sels = filter_by_evidence(inv, tools_pool)
        assert sels == []

    def test_target_evidence_lists_all_matching_paths(self, tools_pool):
        """한 도구에 여러 evidence 가 매칭되면 모두 target_evidence 에 들어가야 한다."""
        inv = Inventory(
            scan_root="/case",
            evidence_list=[
                _evidence("/case/memory.raw", "memory_dump"),
                _evidence("/case/disk.e01", "disk_image"),
            ],
        )
        sels = filter_by_evidence(inv, tools_pool)
        # yara_disk 는 두 evidence 모두 처리 가능.
        yara = next(s for s in sels if s.tool_id == "yara_disk")
        assert set(yara.target_evidence) == {"/case/memory.raw", "/case/disk.e01"}

    def test_command_template_from_first(self, tools_pool):
        inv = Inventory(
            scan_root="/case",
            evidence_list=[_evidence("/case/Security.evtx", "evtx_log")],
        )
        sels = filter_by_evidence(inv, tools_pool)
        assert sels[0].command_template == "chainsaw {evidence_path}"

    def test_estimated_runtime_inherited(self, tools_pool):
        inv = Inventory(
            scan_root="/case",
            evidence_list=[_evidence("/case/memory.raw", "memory_dump")],
        )
        sels = filter_by_evidence(inv, tools_pool)
        vol = next(s for s in sels if s.tool_id == "volatility3")
        assert vol.estimated_runtime == "long"

    def test_empty_inventory_returns_empty(self, tools_pool):
        inv = Inventory(scan_root="/case", evidence_list=[])
        assert filter_by_evidence(inv, tools_pool) == []

    def test_empty_tools_returns_empty(self):
        inv = Inventory(
            scan_root="/case",
            evidence_list=[_evidence("/case/Security.evtx", "evtx_log")],
        )
        assert filter_by_evidence(inv, {}) == []


class TestSkippedByEvidenceGap:
    def test_lists_tools_with_no_matching_evidence(self, tools_pool):
        inv = Inventory(
            scan_root="/case",
            evidence_list=[_evidence("/case/Security.evtx", "evtx_log")],
        )
        skipped = skipped_by_evidence_gap(inv, tools_pool)
        # chainsaw 는 매칭되므로 제외; 나머지 3개는 모두 skipped.
        assert set(skipped) == {"volatility3", "regripper", "yara_disk"}

    def test_no_skips_when_all_match(self, tools_pool):
        inv = Inventory(
            scan_root="/case",
            evidence_list=[
                _evidence("/case/Security.evtx", "evtx_log"),
                _evidence("/case/memory.raw", "memory_dump"),
                _evidence("/case/NTUSER.DAT", "registry_hive"),
                _evidence("/case/disk.e01", "disk_image"),
            ],
        )
        # yara_disk 의 두 applicable 중 하나 (disk_image) 만 매칭돼도 통과.
        skipped = skipped_by_evidence_gap(inv, tools_pool)
        assert skipped == []
