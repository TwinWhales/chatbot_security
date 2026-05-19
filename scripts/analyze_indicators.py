"""Stage 4a 산출물 분석 + 병합 후보 매핑.

`seed_docs/_indicator_candidates/*.yaml` (Stage 4a 의 후보 indicator 들)
을 읽어 통계를 내고, 각 indicator 가 어느 기존 tool YAML 에 병합되면 좋을지
제안한다.

Ollama 호출 없음, 결정론적. 사람이 검수 전 한눈에 컨텐츠 파악용.

산출물:
  * stdout 의 Rich 표 (severity / tool_hint / evidence_type 별 카운트)
  * `seed_docs/_indicator_candidates/_merge_plan.yaml`
    각 후보 indicator → {target_tool_yaml, conflict_with_existing_id, ...}

사용:
    python scripts/analyze_indicators.py
    python scripts/analyze_indicators.py --target-dir tools_metadata
    python scripts/analyze_indicators.py --quiet  # 표 끄고 plan 만 생성
"""

from __future__ import annotations

import argparse
import sys
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any

import yaml
from rich.console import Console
from rich.table import Table

from forensicagent.tools import load_all_tools

CAND_DIR = Path("seed_docs/_indicator_candidates")
PLAN_PATH = CAND_DIR / "_merge_plan.yaml"

# tool_hint (Stage 4a 출력) → tool_id (실제 tools_metadata YAML) 매핑 시도.
# 한 hint 가 여러 도구로 갈 수 있다 (예: evtx 는 chainsaw + evtxecmd 모두).
_HINT_TO_TOOLS = {
    "evtx": ["chainsaw", "evtxecmd"],
    "volatility": ["volatility3"],
    "regripper": ["regripper", "recmd"],
    "tshark": ["tshark"],
    "yara": ["yara"],
    "plaso": ["plaso", "log2timeline"],
    "browser": ["hindsight", "chromehistory"],
    "eztools": ["mftecmd", "evtxecmd", "recmd", "pecmd"],
    "other": [],
}


def _load_candidates() -> list[tuple[Path, dict[str, Any]]]:
    out: list[tuple[Path, dict[str, Any]]] = []
    if not CAND_DIR.exists():
        return out
    for f in sorted(CAND_DIR.glob("*.yaml")):
        if f.name.startswith("_"):  # skip _merge_plan.yaml etc
            continue
        try:
            data = yaml.safe_load(f.read_text(encoding="utf-8"))
        except yaml.YAMLError:
            continue
        if isinstance(data, dict):
            out.append((f, data))
    return out


def _collect_indicators(
    candidates: list[tuple[Path, dict[str, Any]]],
) -> list[dict[str, Any]]:
    """후보 파일들의 indicators 를 flat 리스트로. 출처 메타 첨부."""
    flat: list[dict[str, Any]] = []
    for f, doc in candidates:
        items = doc.get("indicators") or []
        if not isinstance(items, list):
            continue
        for it in items:
            if not isinstance(it, dict):
                continue
            it = dict(it)  # copy
            it["_source"] = f.stem
            it["_topic"] = doc.get("topic", "")
            flat.append(it)
    return flat


def _suggest_target_tools(
    indicator: dict[str, Any],
    tools_known: set[str],
) -> list[str]:
    """이 indicator 가 어느 tool_id 의 YAML 로 들어가야 할지 후보 리스트."""
    hint = (indicator.get("tool_hint") or "").lower().strip()
    candidates = list(_HINT_TO_TOOLS.get(hint, []))
    # 알려진 도구만 통과.
    return [t for t in candidates if t in tools_known]


def render_summary(
    flat: list[dict[str, Any]],
    candidates: list[tuple[Path, dict[str, Any]]],
    console: Console,
) -> None:
    console.print(
        f"\n[bold]Stage 4a 후보 indicator 통계[/]\n"
        f"  source posts: {len(candidates)}\n"
        f"  total indicators: {len(flat)}\n"
    )

    sev = Counter(it.get("severity_baseline", "?") for it in flat)
    sev_table = Table(title="Severity 분포")
    sev_table.add_column("severity")
    sev_table.add_column("count", justify="right")
    for s in ("critical", "high", "medium", "low", "info", "?"):
        if sev.get(s, 0):
            sev_table.add_row(s, str(sev[s]))
    console.print(sev_table)

    hints = Counter(it.get("tool_hint", "?") for it in flat)
    hint_table = Table(title="tool_hint 분포")
    hint_table.add_column("tool_hint")
    hint_table.add_column("count", justify="right")
    for h, n in hints.most_common():
        hint_table.add_row(str(h), str(n))
    console.print(hint_table)

    et_table = Table(title="applicable_evidence_types 분포")
    et_table.add_column("evidence_type")
    et_table.add_column("count", justify="right")
    et_counter: Counter = Counter()
    for it in flat:
        for et in it.get("applicable_evidence_types") or []:
            et_counter[str(et)] += 1
    for et, n in et_counter.most_common():
        et_table.add_row(et, str(n))
    console.print(et_table)


def build_plan(
    flat: list[dict[str, Any]],
    tools_known: dict[str, Any],
) -> dict[str, Any]:
    """병합 계획 생성."""
    plan: dict[str, Any] = {
        "summary": {
            "total_indicators": len(flat),
            "candidates_with_target": 0,
            "candidates_without_target": 0,
            "duplicate_ids": [],
        },
        "by_target_tool": defaultdict(list),
        "unmapped": [],
    }
    tool_id_set = set(tools_known.keys())

    seen_ids: dict[str, list[str]] = defaultdict(list)
    for it in flat:
        ind_id = str(it.get("id", "")).strip()
        if ind_id:
            seen_ids[ind_id].append(it.get("_source", ""))

        targets = _suggest_target_tools(it, tool_id_set)
        record = {
            "id": ind_id,
            "pattern": it.get("pattern", ""),
            "severity_baseline": it.get("severity_baseline", "low"),
            "description": it.get("description", ""),
            "tool_hint": it.get("tool_hint", ""),
            "applicable_evidence_types": it.get("applicable_evidence_types") or [],
            "source_post": it.get("_source", ""),
        }
        if targets:
            plan["summary"]["candidates_with_target"] += 1
            for t in targets:
                # detect conflict with existing indicator id in target YAML.
                existing_meta = tools_known.get(t)
                existing_ids: set[str] = set()
                if existing_meta is not None:
                    existing_ids = {
                        si.id for si in existing_meta.suspicious_indicators
                    }
                rec = dict(record)
                rec["conflict_with_existing_id"] = ind_id in existing_ids
                plan["by_target_tool"][t].append(rec)
        else:
            plan["summary"]["candidates_without_target"] += 1
            plan["unmapped"].append(record)

    for ind_id, sources in seen_ids.items():
        if len(sources) > 1:
            plan["summary"]["duplicate_ids"].append(
                {"id": ind_id, "sources": sources}
            )

    # defaultdict → dict for clean YAML output
    plan["by_target_tool"] = dict(plan["by_target_tool"])
    return plan


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument(
        "--target-dir",
        default="tools_metadata",
        help="Where existing tool YAMLs live (for conflict detection).",
    )
    ap.add_argument("--quiet", action="store_true", help="Skip Rich tables, write plan only.")
    args = ap.parse_args(argv)

    console = Console()

    candidates = _load_candidates()
    if not candidates:
        console.print(f"[yellow]no Stage 4a candidates in {CAND_DIR}[/]")
        return 0

    flat = _collect_indicators(candidates)
    tools_known = load_all_tools(args.target_dir)

    if not args.quiet:
        render_summary(flat, candidates, console)

    plan = build_plan(flat, tools_known)

    if not args.quiet:
        console.print(
            f"\n[bold]Merge plan summary[/]:\n"
            f"  candidates with target tool: {plan['summary']['candidates_with_target']}\n"
            f"  unmapped (tool_hint=other or unknown): {plan['summary']['candidates_without_target']}\n"
            f"  duplicate ids across posts: {len(plan['summary']['duplicate_ids'])}\n"
        )
        # Per-tool breakdown
        per_tool = Table(title="Per-tool merge load")
        per_tool.add_column("target tool_id")
        per_tool.add_column("# new indicators", justify="right")
        per_tool.add_column("# id collisions w/ existing", justify="right")
        for t, items in plan["by_target_tool"].items():
            coll = sum(1 for x in items if x["conflict_with_existing_id"])
            per_tool.add_row(t, str(len(items)), str(coll))
        console.print(per_tool)

    PLAN_PATH.parent.mkdir(parents=True, exist_ok=True)
    PLAN_PATH.write_text(
        yaml.safe_dump(plan, sort_keys=False, allow_unicode=True, width=120),
        encoding="utf-8",
    )
    console.print(f"\n[green]merge plan written:[/] {PLAN_PATH}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
