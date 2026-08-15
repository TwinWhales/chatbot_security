"""RAG benchmark harness — deterministic baseline vs RAG reranking.

각 골든 케이스에 대해 Selector 를 여러 모드로 돌려 선택 도구/순서/타이밍을
캡처하고, golden relevance 라벨 대비 랭킹 지표(NDCG/MRR/P/R @k)를 계산한다.

모드:
  * deterministic : use_rag=False, use_llm=False  (baseline — Stage1 필터 순서)
  * rag           : use_rag=True,  use_llm=False  (RAG 관련도 재정렬)
  * llm           : use_rag=False, use_llm=True    (opt-in, Ollama 필요)
  * rag_llm       : use_rag=True,  use_llm=True     (opt-in, Ollama 필요)

핵심 원칙: 자격 게이트(Stage1)는 모드 간 동일하므로 개선 신호는 순전히
순서 품질(NDCG/MRR/P/R)에 있다. LLM 모드는 로컬 CPU 추론이 느려 기본 off,
`--with-llm` 로만 켠다(Ollama 없으면 우아하게 skip). RAG 의존성이 없으면
select 가 결정론 순서로 폴백하므로 rag==deterministic 이 되고 delta=0.
"""

from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any, Optional

from forensicagent.scanner.types import Evidence, Inventory
from forensicagent.selector import select
from forensicagent.tools import load_all_tools
from bench import metrics as M

BENCH_DIR = Path(__file__).resolve().parent
GOLDEN_PATH = BENCH_DIR / "goldenset.json"
KS = (3, 5)
METRIC_KEYS = [f"ndcg@{k}" for k in KS] + ["mrr", "core_mrr"] + \
    [f"p@{k}" for k in KS] + [f"r@{k}" for k in KS] + \
    [f"core_r@{k}" for k in KS]


# ---------------------------------------------------------------------------
# Golden set + inventory
# ---------------------------------------------------------------------------

def load_cases(path: Path = GOLDEN_PATH) -> list[dict[str, Any]]:
    data = json.loads(path.read_text(encoding="utf-8"))
    return data["cases"]


def _inventory(case: dict[str, Any]) -> Inventory:
    evs = [
        Evidence(
            path=e["filename"],
            filename=e["filename"],
            size_bytes=1,
            evidence_type=e["evidence_type"],
            detected_by="extension",
        )
        for e in case["evidence"]
    ]
    return Inventory(evidence_list=evs, scan_root="(bench synthetic)")


# ---------------------------------------------------------------------------
# One (case, mode) run + metrics
# ---------------------------------------------------------------------------

def _run_mode(
    inv: Inventory,
    tools: dict,
    scenario: Optional[str],
    *,
    use_rag: bool,
    use_llm: bool,
    client,
) -> tuple[list[str], dict[str, int], bool]:
    stage_ms: dict[str, int] = {}
    plan = select(
        inv, tools,
        use_llm=use_llm, use_rag=use_rag,
        client=client, scenario=scenario, stage_ms=stage_ms,
    )
    return [t.tool_id for t in plan.selected_tools], stage_ms, plan.rag_used


def _case_metrics(predicted_ids: list[str], labels: dict[str, int]) -> dict[str, float]:
    rels = [float(labels.get(t, 0)) for t in predicted_ids]
    out: dict[str, float] = {}
    for k in KS:
        out[f"ndcg@{k}"] = M.ndcg_at_k(rels, k)
        out[f"p@{k}"] = M.precision_at_k(rels, k)
        out[f"r@{k}"] = M.recall_at_k(rels, k)
    out["mrr"] = M.mrr(rels)
    # Grade 1 is useful context, but it made the previous MRR saturate at 1.0
    # for nearly every synthetic case. Track the first core (grade 2) tool and
    # core coverage separately so a primary-tool regression is visible.
    out["core_mrr"] = M.mrr(rels, threshold=2.0)
    for k in KS:
        out[f"core_r@{k}"] = M.recall_at_k(rels, k, threshold=2.0)
    return out


# ---------------------------------------------------------------------------
# Full benchmark
# ---------------------------------------------------------------------------

def run_benchmark(*, with_llm: bool = False, rebuild: bool = True) -> dict[str, Any]:
    tools = load_all_tools()  # 공용 리졸버 (env -> ~/.forensicagent -> repo)
    n_tools = len(tools)

    # ---- index build (timed) ----
    index_info: dict[str, Any] = {"rebuilt": rebuild}
    if rebuild:
        from forensicagent.rag.tool_indexer import index_tools
        stats = index_tools(tools, overwrite=True)
        index_info.update(
            tools_indexed=stats.tools_indexed,
            embedding_ms=stats.embedding_ms,
            chroma_ms=stats.chroma_ms,
            elapsed_s=round(stats.elapsed_s, 2),
            errors=stats.errors,
        )

    # ---- modes (LLM opt-in + availability gated) ----
    modes: list[tuple[str, bool, bool]] = [
        ("deterministic", False, False),
        ("rag", True, False),
    ]
    client = None
    llm_note = "LLM modes not requested (--with-llm off)."
    if with_llm:
        from forensicagent.llm import OllamaClient
        c = OllamaClient()
        ok, detail = c.is_available()
        if ok:
            client = c
            modes += [("llm", False, True), ("rag_llm", True, True)]
            llm_note = f"LLM modes enabled ({c.model}: {detail})."
        else:
            llm_note = f"LLM modes SKIPPED - Ollama unavailable: {detail}"

    cases = load_cases()
    per_case: list[dict[str, Any]] = []
    # accumulators: mode -> metric -> [values]; mode -> timing lists
    agg: dict[str, dict[str, list[float]]] = {m[0]: {k: [] for k in METRIC_KEYS} for m in modes}
    timing: dict[str, dict[str, list[float]]] = {
        m[0]: {"select_filter": [], "select_rag": [], "select_rank": []} for m in modes
    }
    rag_used_count = 0

    for case in cases:
        inv = _inventory(case)
        scenario = case.get("scenario")
        labels = case.get("labels", {})
        row: dict[str, Any] = {
            "id": case["id"],
            "n_eligible": None,
            "scenario": bool(scenario),
            "modes": {},
        }
        for name, use_rag, use_llm in modes:
            ids, stage_ms, rag_used = _run_mode(
                inv, tools, scenario, use_rag=use_rag, use_llm=use_llm, client=client
            )
            row["n_eligible"] = len(ids)
            met = _case_metrics(ids, labels)
            row["modes"][name] = {"order": ids, **{k: round(v, 4) for k, v in met.items()}}
            for k in METRIC_KEYS:
                agg[name][k].append(met[k])
            for tkey in ("select_filter", "select_rag", "select_rank"):
                timing[name][tkey].append(float(stage_ms.get(tkey, 0)))
            if name == "rag" and rag_used:
                rag_used_count += 1
        per_case.append(row)

    # ---- aggregate means + delta ----
    aggregate = {
        name: {k: round(M.mean(vals), 4) for k, vals in mets.items()}
        for name, mets in agg.items()
    }
    timing_mean = {
        name: {tkey: round(M.mean(vals), 2) for tkey, vals in t.items()}
        for name, t in timing.items()
    }
    delta = {}
    if "deterministic" in aggregate and "rag" in aggregate:
        delta["rag_vs_deterministic"] = {
            k: round(aggregate["rag"][k] - aggregate["deterministic"][k], 4)
            for k in METRIC_KEYS
        }
    if "llm" in aggregate and "rag_llm" in aggregate:
        delta["rag_llm_vs_llm"] = {
            k: round(aggregate["rag_llm"][k] - aggregate["llm"][k], 4)
            for k in METRIC_KEYS
        }

    return {
        "config": {
            "n_cases": len(cases),
            "n_tools": n_tools,
            "ks": list(KS),
            "modes": [m[0] for m in modes],
            "llm_note": llm_note,
            "rag_used_cases": rag_used_count,
        },
        "index": index_info,
        "aggregate": aggregate,
        "delta": delta,
        "timing_ms": timing_mean,
        "per_case": per_case,
    }
