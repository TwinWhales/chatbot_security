"""Analyzer orchestrator.

처리 전략 (명세 2.4):
  Case A — 출력이 작고 정형 (≤ 100 KB) :
           rules + LLM 양쪽 적용 후 머지.
  Case B — 정형 + 큼 (100 KB ~ 수 MB) :
           rules 만 적용 (이미 효과적인 사전 필터). 룰 결과가 적으면 LLM
           으로 자연어 설명 보강.
  Case C — 거대 (> 수 MB) :
           rules 만. LLM 호출 안 함 (컨텍스트 초과 위험).
"""

from __future__ import annotations

import logging
from pathlib import Path

from forensicagent.analyzer.llm_extract import extract as llm_extract
from forensicagent.analyzer.rules import apply_rules
from forensicagent.analyzer.types import (
    SEVERITY_RANK,
    Finding,
    ToolAnalysis,
    by_severity_count,
)
from forensicagent.executor.types import ExecutionResult
from forensicagent.llm import OllamaClient
from forensicagent.observability import Stopwatch
from forensicagent.tools.schema import ToolMetadata

logger = logging.getLogger(__name__)

# Case 경계 (bytes)
CASE_A_MAX = 100 * 1024
CASE_B_MAX = 4 * 1024 * 1024


def _read_text(path: str, *, max_bytes: int) -> str:
    p = Path(path)
    if not p.exists():
        return ""
    try:
        with open(p, "rb") as f:
            data = f.read(max_bytes)
        return data.decode("utf-8", errors="replace")
    except OSError as e:
        logger.warning("cannot read %s: %s", p, e)
        return ""


def _dedupe(findings: list[Finding]) -> list[Finding]:
    """동일 (title, raw_excerpt[:120]) 키로 중복 제거. rule + llm 중 더 높은 severity 유지."""
    seen: dict[tuple[str, str], Finding] = {}
    for f in findings:
        key = (f.title.strip().lower(), f.evidence_ref.raw_excerpt[:120].strip())
        prev = seen.get(key)
        if prev is None:
            seen[key] = f
            continue
        if SEVERITY_RANK[f.severity] > SEVERITY_RANK[prev.severity]:
            seen[key] = f
    return list(seen.values())


def _sort_severity_desc(findings: list[Finding]) -> list[Finding]:
    return sorted(findings, key=lambda f: SEVERITY_RANK[f.severity], reverse=True)


def analyze_one(
    result: ExecutionResult,
    metadata: ToolMetadata,
    *,
    use_llm: bool = True,
    client: OllamaClient | None = None,
    stage_ms: dict[str, int] | None = None,
) -> ToolAnalysis:
    """단일 ExecutionResult 분석."""
    analysis = ToolAnalysis(tool_id=metadata.tool_id)

    if result.status != "success":
        analysis.summary = f"skipped ({result.status}): {result.error_message[:160]}"
        return analysis

    size = result.output_size_bytes
    parsed = result.parsed_output

    # Decide case
    if size <= CASE_A_MAX:
        case = "A"
        raw_budget = CASE_A_MAX
    elif size <= CASE_B_MAX:
        case = "B"
        raw_budget = CASE_B_MAX
    else:
        case = "C"
        raw_budget = CASE_B_MAX  # 룰 적용용으로 일부만 읽음
    analysis.case_used = case

    raw_text = _read_text(result.stdout_path, max_bytes=raw_budget)

    # ---- rule pass (always) ----
    with Stopwatch() as sw_rules:
        rule_findings = apply_rules(
            parsed,
            raw_text,
            metadata,
            evidence_path=result.target_evidence,
        )
    if stage_ms is not None:
        stage_ms[f"analyze_rules:{metadata.tool_id}"] = (
            stage_ms.get(f"analyze_rules:{metadata.tool_id}", 0) + sw_rules.elapsed_ms
        )

    # ---- LLM pass ----
    llm_findings: list[Finding] = []
    summary = ""
    invoked = False
    failed = False
    if use_llm and case != "C":
        with Stopwatch() as sw_llm:
            llm_findings, summary, invoked, failed = llm_extract(
                metadata,
                raw_text,
                evidence_path=result.target_evidence,
                client=client,
            )
        if stage_ms is not None:
            stage_ms[f"analyze_llm:{metadata.tool_id}"] = (
                stage_ms.get(f"analyze_llm:{metadata.tool_id}", 0) + sw_llm.elapsed_ms
            )

    merged = _dedupe(rule_findings + llm_findings)
    merged = _sort_severity_desc(merged)
    analysis.findings = merged
    analysis.llm_invoked = invoked
    analysis.llm_failed = failed

    counts = by_severity_count(merged)
    cat_breakdown: dict[str, int] = {}
    for f in merged:
        cat_breakdown[f.category] = cat_breakdown.get(f.category, 0) + 1
    top_cats = sorted(cat_breakdown.items(), key=lambda x: x[1], reverse=True)[:3]
    cat_str = ", ".join(f"{c}({n})" for c, n in top_cats) or "n/a"
    sev_str = (
        f"critical={counts['critical']} high={counts['high']} "
        f"medium={counts['medium']} low={counts['low']} info={counts['info']}"
    )
    auto_summary = f"{len(merged)} findings ({sev_str}); top: {cat_str}"
    analysis.summary = summary or auto_summary
    return analysis


def analyze_all(
    execution_results: list[ExecutionResult],
    tools: dict[str, ToolMetadata],
    *,
    use_llm: bool = True,
    client: OllamaClient | None = None,
    stage_ms: dict[str, int] | None = None,
) -> list[ToolAnalysis]:
    out: list[ToolAnalysis] = []
    for result in execution_results:
        meta = tools.get(result.tool_id)
        if meta is None:
            logger.warning("no metadata for tool_id=%r", result.tool_id)
            continue
        out.append(
            analyze_one(
                result, meta, use_llm=use_llm, client=client, stage_ms=stage_ms
            )
        )
    return out
