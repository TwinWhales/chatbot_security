"""Rule-based finding extraction.

YAML 의 suspicious_indicators 를 입력으로, 도구 출력에서 패턴이 나타나는
부분을 Finding 으로 만든다. ID 기반 dispatch — id 가 같은 indicator 마다
간단한 매처를 미리 매핑하고, 미등록 id 는 단순 substring 매칭으로 fallback.

이 모듈은 LLM 호출이 없고 결정론적이라 Analyzer 의 Case B/C 의 1차
필터로도 사용된다 (대용량 출력의 sigma_rule_hit 만 추리는 등).
"""

from __future__ import annotations

import re
from typing import Any, Callable

from forensicagent.analyzer.types import EvidenceRef, Finding, Severity
from forensicagent.tools.schema import SuspiciousIndicator, ToolMetadata


# Matcher: (parsed_dict, raw_text) -> list[Finding]
Matcher = Callable[[Any, str, ToolMetadata, SuspiciousIndicator], list[Finding]]


# ---------- generic matchers ----------

def _match_sigma_rule_hit(
    parsed: Any, raw: str, meta: ToolMetadata, ind: SuspiciousIndicator
) -> list[Finding]:
    """parsed['items'] 에 rule_name 필드가 있는 항목 → Finding."""
    items = _items(parsed)
    out: list[Finding] = []
    for it in items:
        if not isinstance(it, dict):
            continue
        rule = it.get("rule_name") or _get_nested(it, ["name"]) or _get_nested(it, ["rule"])
        if rule:
            out.append(
                Finding(
                    severity=ind.severity_baseline,
                    category="threat_intel",
                    title=f"Sigma rule match: {rule}",
                    description=f"{meta.display_name} matched rule {rule}.",
                    evidence_ref=EvidenceRef(
                        raw_excerpt=_excerpt(it, max_chars=400),
                    ),
                    suggested_followup="해당 룰의 컨텍스트 확인 후 원본 이벤트 검토.",
                    source="rule",
                )
            )
    return out


def _match_run_key_unusual_binary(
    parsed: Any, raw: str, meta: ToolMetadata, ind: SuspiciousIndicator
) -> list[Finding]:
    """RegRipper run plugin 결과 텍스트에서 의심 경로 매칭."""
    out: list[Finding] = []
    if not raw:
        return out
    suspicious = re.compile(
        r"(?i)(?:%AppData%|%Temp%|C:\\Users\\Public|\\Temp\\|\\AppData\\Local\\Temp\\)"
    )
    for line in raw.splitlines():
        if suspicious.search(line):
            out.append(
                Finding(
                    severity=ind.severity_baseline,
                    category="persistence",
                    title="Suspicious Run/RunOnce entry",
                    description=line.strip()[:240],
                    evidence_ref=EvidenceRef(raw_excerpt=line.strip()[:400]),
                    suggested_followup="해당 바이너리 해시 + 서명 확인, 다른 호스트 동일 경로 점검.",
                    source="rule",
                )
            )
    return out


def _match_malfind_pe_unbacked(
    parsed: Any, raw: str, meta: ToolMetadata, ind: SuspiciousIndicator
) -> list[Finding]:
    out: list[Finding] = []
    if not raw:
        return out
    has_pe = re.compile(r"\bMZ\b|^4d 5a", re.MULTILINE)
    has_unbacked = re.compile(r"(?i)(unbacked|RX\b.*MZ|No mapped path)")
    blocks = re.split(r"\n\s*\n", raw)
    for blk in blocks:
        if has_pe.search(blk) and has_unbacked.search(blk):
            out.append(
                Finding(
                    severity=ind.severity_baseline,
                    category="defense_evasion",
                    title="Unbacked memory region with PE header",
                    description="malfind reported a PE header in an unbacked memory region.",
                    evidence_ref=EvidenceRef(raw_excerpt=blk.strip()[:400]),
                    suggested_followup="해당 프로세스 메모리 덤프 → 정적 분석 + YARA.",
                    source="rule",
                )
            )
    return out


# Indicator id → matcher 매핑. 신규 indicator id 추가 시 여기 등록.
_SPECIFIC_MATCHERS: dict[str, Matcher] = {
    "sigma_rule_hit": _match_sigma_rule_hit,
    "run_key_unusual_binary": _match_run_key_unusual_binary,
    "malfind_pe_in_unbacked_region": _match_malfind_pe_unbacked,
}


def _fallback_substring_matcher(
    parsed: Any, raw: str, meta: ToolMetadata, ind: SuspiciousIndicator
) -> list[Finding]:
    """등록된 matcher 가 없으면 indicator.pattern 의 키워드를 raw 에서 substring 검색."""
    if not raw:
        return []
    keywords = [w for w in re.split(r"\W+", ind.pattern.lower()) if len(w) >= 4]
    keywords = list(dict.fromkeys(keywords))[:6]
    if not keywords:
        return []
    out: list[Finding] = []
    for line in raw.splitlines():
        ll = line.lower()
        if all(kw in ll for kw in keywords[:2]):  # 첫 2개 키워드 AND
            out.append(
                Finding(
                    severity=ind.severity_baseline,
                    category="anomaly",
                    title=ind.id,
                    description=line.strip()[:240],
                    evidence_ref=EvidenceRef(raw_excerpt=line.strip()[:400]),
                    suggested_followup=ind.description or "수동 확인 필요.",
                    source="rule",
                )
            )
            if len(out) >= 50:  # 폴백은 false positive 가 많아 캡.
                break
    return out


# ---------- helpers ----------

def _items(parsed: Any) -> list[Any]:
    if isinstance(parsed, dict):
        v = parsed.get("items")
        if isinstance(v, list):
            return v
    if isinstance(parsed, list):
        return parsed
    return []


def _get_nested(obj: Any, path: list[str]) -> Any:
    cur = obj
    for k in path:
        if not isinstance(cur, dict):
            return None
        cur = cur.get(k)
        if cur is None:
            return None
    return cur


def _excerpt(obj: Any, max_chars: int = 400) -> str:
    import json
    try:
        s = json.dumps(obj, ensure_ascii=False, default=str)
    except (TypeError, ValueError):
        s = str(obj)
    return s[:max_chars]


# ---------- public API ----------

def apply_rules(
    parsed: Any,
    raw: str,
    metadata: ToolMetadata,
    *,
    evidence_path: str = "",
) -> list[Finding]:
    """ToolMetadata.suspicious_indicators 를 모두 적용해 Finding 누적."""
    out: list[Finding] = []
    for ind in metadata.suspicious_indicators:
        matcher = _SPECIFIC_MATCHERS.get(ind.id, _fallback_substring_matcher)
        try:
            findings = matcher(parsed, raw, metadata, ind)
        except Exception as e:  # noqa: BLE001
            # rule 하나가 폭주해도 다른 룰은 계속.
            import logging
            logging.getLogger(__name__).warning(
                "rule %s for tool %s raised: %s", ind.id, metadata.tool_id, e
            )
            findings = []
        for f in findings:
            if not f.evidence_ref.source_file and evidence_path:
                f.evidence_ref.source_file = evidence_path
        out.extend(findings)
    return out


# ---------- severity utilities ----------

def severity_at_least(s: Severity, threshold: Severity) -> bool:
    from forensicagent.analyzer.types import SEVERITY_RANK
    return SEVERITY_RANK[s] >= SEVERITY_RANK[threshold]
