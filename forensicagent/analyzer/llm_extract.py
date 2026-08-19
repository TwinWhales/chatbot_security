"""LLM-based finding extraction (Case A / Case B 후처리).

Case A — 출력이 작고 정형 (< ~100KB): 도구 출력 전체를 컨텍스트에 투입.
Case B — 룰이 추린 의심 라인들을 LLM 으로 자연어 설명 보강.

Severity 결정 가이드라인은 시스템 프롬프트로 강제하고, 모델이 확실하지
않으면 'low' 로 두라고 지시한다 (명세 2.4).
"""

from __future__ import annotations

import logging
import re
from typing import Any

from forensicagent.analyzer.types import EvidenceRef, Finding, Severity
from forensicagent.llm import JsonRetryFailed, OllamaClient, OllamaUnavailable
from forensicagent.llm.ollama_client import ChatMessage
from forensicagent.tools.schema import ToolMetadata

logger = logging.getLogger(__name__)


VALID_SEVERITIES = {"info", "low", "medium", "high", "critical"}

_RESPONSE_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {
        "findings": {
            "type": "array",
            "items": {
                "type": "object",
                "properties": {
                    "severity": {
                        "type": "string",
                        "enum": ["info", "low", "medium", "high", "critical"],
                    },
                    "category": {"type": "string"},
                    "title": {"type": "string"},
                    "description": {"type": "string"},
                    "raw_excerpt": {"type": "string"},
                    "suggested_followup": {"type": "string"},
                    "confidence": {"type": "number", "minimum": 0, "maximum": 1},
                },
                "required": [
                    "severity",
                    "category",
                    "title",
                    "description",
                    "raw_excerpt",
                    "suggested_followup",
                    "confidence",
                ],
                "additionalProperties": False,
            },
        },
        "summary": {"type": "string"},
    },
    "required": ["findings", "summary"],
    "additionalProperties": False,
}

_SEVERITY_GUIDE = (
    "Severity scale:\n"
    "  critical — clear compromise evidence (known-bad hash, C2 traffic).\n"
    "  high     — very abnormal pattern (e.g. lsass unusual parent, "
    "successful external RDP).\n"
    "  medium   — suspicious but possibly normal.\n"
    "  low      — odd but more likely benign.\n"
    "  info     — context metadata.\n"
    "When unsure, return severity=\"low\" — under-claim, do not over-claim."
)


def _system_prompt(meta: ToolMetadata) -> str:
    fp = "\n".join(f" - {x}" for x in meta.known_false_positives) or " - (none listed)"
    return (
        f"You are extracting forensic findings from {meta.display_name} output.\n"
        f"Tool purpose: {meta.usage_description.strip()[:600]}\n"
        f"Output format: {meta.output_format}.\n\n"
        f"{_SEVERITY_GUIDE}\n\n"
        "LLM-only observations are advisory and cannot exceed low severity. "
        "Deterministic rules own medium/high/critical classifications.\n\n"
        f"Known false positives (do not promote these):\n{fp}\n\n"
        "Reply with ONLY a JSON object matching this schema:\n"
        '{ "findings": [\n'
        '  { "severity": "info|low|medium|high|critical",\n'
        '    "category": "<short kebab tag, e.g. persistence>",\n'
        '    "title": "<one short sentence>",\n'
        '    "description": "<2-3 sentences>",\n'
        '    "raw_excerpt": "<the line(s) that triggered this>",\n'
        '    "suggested_followup": "<one short sentence>",\n'
        '    "confidence": 0.0 }\n'
        "], \"summary\": \"<one-sentence overall summary>\" }"
    )


def _truncate(text: str, budget_chars: int) -> str:
    if len(text) <= budget_chars:
        return text
    head = text[: budget_chars // 2]
    tail = text[-budget_chars // 2 :]
    return f"{head}\n\n... [truncated {len(text) - budget_chars} chars] ...\n\n{tail}"


def extract(
    metadata: ToolMetadata,
    raw_text: str,
    *,
    evidence_path: str = "",
    budget_chars: int = 12_000,
    client: OllamaClient | None = None,
    scenario: str | None = None,
    rag_context: str | None = None,
) -> tuple[list[Finding], str, bool, bool]:
    """LLM 으로 finding 추출.

    Returns:
        (findings, summary, invoked, failed)
        invoked: LLM 호출에 도달했는지.
        failed:  JSON 파싱/Ollama 실패로 빈 결과를 반환했는지.
    """
    if not raw_text.strip():
        return [], "no output", False, False

    client = client or OllamaClient()
    payload = _truncate(raw_text, budget_chars)
    scenario_block = ""
    if scenario and scenario.strip():
        scenario_block = (
            f"Investigation scenario - prioritize findings relevant to this, "
            f"but still report other clearly suspicious items:\n{scenario.strip()}\n\n"
        )
    rag_block = ""
    if rag_context and rag_context.strip():
        rag_block = (
            "Reference forensic domain knowledge (retrieved; use to judge what "
            "is suspicious, do not invent findings not in the output):\n"
            f"{rag_context.strip()}\n\n"
        )
    messages = [
        ChatMessage(role="system", content=_system_prompt(metadata)),
        ChatMessage(
            role="user",
            content=(
                f"{scenario_block}{rag_block}"
                f"Tool output:\n```\n{payload}\n```\n\nReturn the JSON now."
            ),
        ),
    ]
    try:
        try:
            parsed: Any = client.json_chat(
                messages,
                retry=1,
                format_schema=_RESPONSE_SCHEMA,
            )
        except TypeError as exc:
            # Lightweight test/dry-run clients written against the old
            # protocol may not accept format_schema. Do not hide unrelated
            # TypeErrors raised *inside* a client implementation.
            if "format_schema" not in str(exc):
                raise
            parsed = client.json_chat(messages, retry=1)
    except OllamaUnavailable as e:
        logger.info("LLM unavailable for %s: %s", metadata.tool_id, e)
        return [], "", False, True
    except JsonRetryFailed as e:
        logger.warning("LLM JSON parse failed for %s: %s", metadata.tool_id, e)
        return [], "", True, True

    if not isinstance(parsed, dict):
        logger.warning("LLM response not a dict for %s", metadata.tool_id)
        return [], "", True, True

    items = parsed.get("findings")
    if not isinstance(items, list):
        return [], str(parsed.get("summary", "")), True, True

    out: list[Finding] = []
    for it in items:
        if not isinstance(it, dict):
            continue
        sev = str(it.get("severity", "low")).casefold()
        if sev not in VALID_SEVERITIES:
            sev = "low"
        # Evidence text is attacker-controlled. Grounding prevents invented
        # excerpts, but it cannot make model-assigned severity trustworthy.
        if sev not in {"info", "low"}:
            sev = "low"
        excerpt = str(it.get("raw_excerpt", "")).strip()
        # An LLM finding is admissible only when its quoted evidence exists in
        # the exact grounded input. This prevents invented evidence from being
        # promoted into a deterministic report.
        if not excerpt or excerpt not in payload:
            logger.warning(
                "drop ungrounded LLM finding for %s: excerpt not in input",
                metadata.tool_id,
            )
            continue
        title = str(it.get("title", ""))[:200]
        slug = re.sub(r"[^a-z0-9]+", "-", title.casefold()).strip("-")[:80]
        try:
            confidence = min(0.6, max(0.0, float(it.get("confidence", 0.4))))
        except (TypeError, ValueError):
            confidence = 0.4
        out.append(
            Finding(
                severity=sev,  # type: ignore[arg-type]
                category=str(it.get("category", "anomaly"))[:64],
                title=title,
                description=str(it.get("description", "")),
                evidence_ref=EvidenceRef(
                    source_file=evidence_path,
                    raw_excerpt=excerpt[:600],
                ),
                suggested_followup=str(it.get("suggested_followup", "")),
                source="llm",
                rule_id=f"llm:{slug or 'finding'}",
                confidence=confidence,
            )
        )

    summary = str(parsed.get("summary", "")) if isinstance(parsed.get("summary"), str) else ""
    return out, summary, True, False
