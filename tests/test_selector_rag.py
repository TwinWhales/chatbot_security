"""Selector RAG 배선 — query 호출 시 재정렬, 폴백, Stage1 안전속성 (mock).

절대 원칙 검증:
  * RAG 는 순서만 바꾼다 — Stage1 자격 밖 도구를 절대 승격시키지 않는다.
  * retrieve_tools 가 None(의존성/질의 실패) 이면 결정론 순서로 조용히 폴백.
  * use_rag=False 면 RAG 를 아예 건드리지 않는다.
"""

from __future__ import annotations

from forensicagent.rag import retrieval as retrieval_mod
from forensicagent.rag.retrieval import ToolHit
from forensicagent.scanner.types import Evidence, Inventory
from forensicagent.selector import select
from forensicagent.tools.schema import CommandTemplate, ToolMetadata


def _meta(tool_id, *, category, applicable):
    return ToolMetadata(
        tool_id=tool_id,
        display_name=tool_id.title(),
        category=category,
        applicable_evidence_types=list(applicable),  # type: ignore[arg-type]
        command_templates=[
            CommandTemplate(name="c", template="t {evidence_path}", when="w")
        ],
        usage_description="desc",
    )


def _evtx_and_mem_tools():
    return {
        "chainsaw": _meta("chainsaw", category="log_analysis", applicable=["evtx_log"]),
        "evtxecmd": _meta("evtxecmd", category="log_analysis", applicable=["evtx_log"]),
        "volatility3": _meta("volatility3", category="memory_analysis", applicable=["memory_dump"]),
    }


def _evtx_only_inventory():
    return Inventory(evidence_list=[
        Evidence(path="S.evtx", filename="S.evtx", size_bytes=1,
                 evidence_type="evtx_log", detected_by="extension"),
    ])


def test_rag_reorders_candidates(monkeypatch):
    monkeypatch.setattr(
        retrieval_mod, "retrieve_tools",
        lambda q, **k: [ToolHit("evtxecmd", 0.9, "snip"), ToolHit("chainsaw", 0.4, "snip")],
    )
    plan = select(_evtx_only_inventory(), _evtx_and_mem_tools(), use_llm=False, use_rag=True)
    assert plan.rag_used is True
    ids = [t.tool_id for t in plan.selected_tools]
    assert ids[0] == "evtxecmd"          # higher RAG score sorted first
    assert set(ids) == {"chainsaw", "evtxecmd"}   # evtx-only → no volatility3


def test_rag_none_falls_back_to_deterministic(monkeypatch):
    monkeypatch.setattr(retrieval_mod, "retrieve_tools", lambda q, **k: None)
    plan = select(_evtx_only_inventory(), _evtx_and_mem_tools(), use_llm=False, use_rag=True)
    assert plan.rag_used is False
    # 순서 불변 = 결정론 필터 순서 (dict 삽입 순서: chainsaw, evtxecmd).
    assert [t.tool_id for t in plan.selected_tools] == ["chainsaw", "evtxecmd"]


def test_rag_never_promotes_tool_outside_stage1(monkeypatch):
    # retrieve_tools 가 (버그로) 자격 밖 도구를 반환해도 selector 는 무시해야 한다.
    monkeypatch.setattr(
        retrieval_mod, "retrieve_tools",
        lambda q, **k: [ToolHit("volatility3", 0.99, "x"), ToolHit("chainsaw", 0.3, "y")],
    )
    plan = select(_evtx_only_inventory(), _evtx_and_mem_tools(), use_llm=False, use_rag=True)
    ids = [t.tool_id for t in plan.selected_tools]
    assert "volatility3" not in ids      # 증거(evtx)에 없는 도구는 절대 실행 계획에 없음
    assert set(ids) == {"chainsaw", "evtxecmd"}


def test_use_rag_false_skips_retrieval(monkeypatch):
    called = {"n": 0}

    def _spy(*a, **k):
        called["n"] += 1
        return None

    monkeypatch.setattr(retrieval_mod, "retrieve_tools", _spy)
    plan = select(_evtx_only_inventory(), _evtx_and_mem_tools(), use_llm=False, use_rag=False)
    assert called["n"] == 0
    assert plan.rag_used is False


def test_rag_snippets_passed_to_llm_rank(monkeypatch):
    """RAG 스니펫이 Stage2 LLM 프롬프트 컨텍스트로 전달되는지."""
    monkeypatch.setattr(
        retrieval_mod, "retrieve_tools",
        lambda q, **k: [ToolHit("chainsaw", 0.9, "SNIPPET-MARKER-XYZ")],
    )
    captured = {}

    def fake_rank(candidates, metas, inventory, client, *, scenario=None, rag_snippets=None):
        captured["snippets"] = rag_snippets
        return candidates, True, False

    import forensicagent.selector.selector as sel_mod
    monkeypatch.setattr(sel_mod, "rank_with_llm", fake_rank)

    select(_evtx_only_inventory(), _evtx_and_mem_tools(), use_llm=True, use_rag=True, client=object())
    assert captured["snippets"].get("chainsaw") == "SNIPPET-MARKER-XYZ"
