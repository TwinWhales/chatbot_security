"""Analyzer orchestration over structured executor artifacts.

Generated artifacts are authoritative when a tool writes progress text to
stdout. CSV and text artifacts are streamed in overlapping batches so evidence
near the tail is not silently omitted.
"""

from __future__ import annotations

import csv
import hashlib
import json
import logging
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable, Iterator

from forensicagent.analyzer.llm_extract import extract as llm_extract
from forensicagent.analyzer.rules import (
    apply_rules_with_status,
    cross_batch_correlation_family,
)
from forensicagent.analyzer.types import (
    MAX_RETAINED_FINDINGS,
    SEVERITY_RANK,
    Finding,
    ToolAnalysis,
    by_severity_count,
)
from forensicagent.executor.types import MAX_INLINE_JSON_BYTES, ExecutionResult
from forensicagent.llm import OllamaClient
from forensicagent.observability import Stopwatch
from forensicagent.tools.schema import ToolMetadata

logger = logging.getLogger(__name__)

CASE_A_MAX = MAX_INLINE_JSON_BYTES
CASE_B_MAX = 4 * 1024 * 1024
ROW_BATCH_SIZE = 5_000
ROW_OVERLAP = 512
ROW_BATCH_MAX_CHARS = CASE_B_MAX
# Only Event IDs used by cross-row matchers are retained. Families are isolated
# so a failed-logon flood cannot evict account events (or vice versa), and each
# family remains bounded to one batch's worth of relevant records.
CORRELATION_FAMILY_CARRY = ROW_BATCH_SIZE
CORRELATION_FAMILY_MAX_CHARS = CASE_B_MAX
TEXT_CHUNK_CHARS = 512 * 1024
TEXT_OVERLAP_CHARS = 8 * 1024


@dataclass(frozen=True)
class _ArtifactInput:
    path: Path
    role: str
    format: str
    size_bytes: int


class _CsvRecordLimitError(Exception):
    def __init__(self, *, line_number: int, recoverable: bool) -> None:
        super().__init__("CSV record exceeds the analysis limit")
        self.line_number = line_number
        self.recoverable = recoverable


class _BoundedCsvLines:
    """Feed csv.reader without allowing it to buffer an unbounded record."""

    def __init__(self, handle: Any) -> None:
        self.handle = handle
        self.line_number = 0
        self.record_chars = 0

    def __iter__(self) -> _BoundedCsvLines:
        return self

    def __next__(self) -> str:
        line = self.handle.readline(ROW_BATCH_MAX_CHARS + 1)
        if not line:
            raise StopIteration
        self.line_number += 1
        prior_chars = self.record_chars
        if len(line) > ROW_BATCH_MAX_CHARS:
            while line and not line.endswith(("\n", "\r")):
                line = self.handle.readline(ROW_BATCH_MAX_CHARS + 1)
            self.record_chars = 0
            raise _CsvRecordLimitError(
                line_number=self.line_number,
                recoverable=prior_chars == 0,
            )
        self.record_chars += len(line)
        if self.record_chars > ROW_BATCH_MAX_CHARS:
            raise _CsvRecordLimitError(
                line_number=self.line_number,
                recoverable=False,
            )
        return line

    def reset_record(self) -> None:
        self.record_chars = 0


def _rag_context_for(metadata: ToolMetadata) -> str:
    """Retrieve only the current tool's knowledge document."""
    from forensicagent.rag.retrieval import retrieve_tools

    indicator_text = " ".join(
        f"{item.pattern} {item.description}"
        for item in metadata.suspicious_indicators
    ).strip()
    query = (
        f"{metadata.display_name} {metadata.category}: "
        f"what output patterns are suspicious? {indicator_text}"
    )
    hits = retrieve_tools(query, tool_ids={metadata.tool_id})
    if not hits:
        return ""
    return "\n".join(
        f"- {' '.join(hit.snippet.split())[:400]}" for hit in hits[:3]
    )


def _artifact_value(artifact: Any, name: str, default: Any = "") -> Any:
    if isinstance(artifact, dict):
        return artifact.get(name, default)
    return getattr(artifact, name, default)


def _artifact_inputs(result: ExecutionResult) -> list[_ArtifactInput]:
    generated: list[_ArtifactInput] = []
    stdout: list[_ArtifactInput] = []
    seen: set[str] = set()

    for artifact in _artifact_value(result, "artifacts", None) or []:
        path_text = _artifact_value(artifact, "path")
        if not path_text:
            continue
        path = Path(str(path_text))
        if not path.is_file():
            continue
        try:
            actual_size = path.stat().st_size
        except OSError:
            continue
        if actual_size <= 0:
            continue
        key = str(path.resolve()).casefold()
        if key in seen:
            continue
        seen.add(key)
        role = str(_artifact_value(artifact, "role", "generated")).casefold()
        fmt = str(_artifact_value(artifact, "format", "")).casefold()
        declared_size = _artifact_value(artifact, "size_bytes", actual_size)
        try:
            size = max(actual_size, int(declared_size or 0))
        except (TypeError, ValueError):
            size = actual_size
        item = _ArtifactInput(path=path, role=role, format=fmt, size_bytes=size)
        if role == "generated":
            generated.append(item)
        elif role == "stdout":
            stdout.append(item)

    # Compatibility with pre-artifact executor results.
    stdout_path = Path(str(_artifact_value(result, "stdout_path", "") or ""))
    if stdout_path.is_file():
        key = str(stdout_path.resolve()).casefold()
        if key not in seen:
            try:
                size = stdout_path.stat().st_size
            except OSError:
                size = 0
            if size > 0:
                stdout.append(
                    _ArtifactInput(
                        path=stdout_path,
                        role="stdout",
                        format=str(_artifact_value(result, "output_format", "") or "").casefold(),
                        size_bytes=size,
                    )
                )

    # Generated files are authoritative and are analyzed first.  Stdout is
    # still evidence for tools that emit a useful summary in addition to a
    # generated CSV/JSON; canonical de-duplication removes repeated records.
    return generated + stdout


def _infer_format(artifact: _ArtifactInput) -> str:
    hint = artifact.format.casefold().strip().lstrip(".")
    suffix = artifact.path.suffix.casefold()
    # Executors commonly describe line-delimited JSON as generic ``json``.
    # The more-specific filename suffix wins so we do not try json.load() on
    # a stream containing multiple top-level objects.
    if suffix in {".jsonl", ".ndjson"}:
        return suffix[1:]
    if hint in {"csv", "json", "jsonl", "ndjson", "text", "txt", "log"}:
        return "text" if hint in {"txt", "log"} else hint
    return {
        ".csv": "csv",
        ".json": "json",
        ".jsonl": "jsonl",
        ".ndjson": "ndjson",
        ".log": "text",
        ".txt": "text",
    }.get(suffix, "text")


def _render_rows(rows: list[dict[str, Any]], budget: int = CASE_A_MAX) -> str:
    pieces: list[str] = []
    used = 0
    for row in rows:
        rendered = json.dumps(row, ensure_ascii=False, default=str, sort_keys=True)
        if used + len(rendered) + 1 > budget:
            break
        pieces.append(rendered)
        used += len(rendered) + 1
    return "\n".join(pieces)


def _row_size(row: dict[str, Any]) -> int:
    return len(json.dumps(row, ensure_ascii=False, default=str, sort_keys=True)) + 1


def _iter_row_batches(
    rows: Iterator[dict[str, Any]],
    coverage_warnings: list[str],
) -> Iterator[tuple[dict[str, list[dict[str, Any]]], str]]:
    carry: list[dict[str, Any]] = []
    correlation_carry: dict[str, list[tuple[dict[str, Any], int]]] = {}
    pending_correlation: list[dict[str, Any]] | None = None
    current: list[dict[str, Any]] = []
    current_chars = 0
    for row in rows:
        row_chars = _row_size(row)
        if row_chars > ROW_BATCH_MAX_CHARS:
            warning = (
                "structured artifact contains a record above the "
                f"{ROW_BATCH_MAX_CHARS}-character analysis limit; the record was "
                "skipped and the raw artifact was retained"
            )
            if warning not in coverage_warnings:
                logger.warning(warning)
                coverage_warnings.append(warning)
            continue
        # Delay state retention until another row proves that a later batch
        # exists. An exact-size final batch cannot lose a future correlation.
        if pending_correlation is not None:
            _update_correlation_carry(
                correlation_carry,
                pending_correlation,
                coverage_warnings,
            )
            pending_correlation = None
        current.append(row)
        current_chars += row_chars
        if len(current) < ROW_BATCH_SIZE and current_chars < ROW_BATCH_MAX_CHARS:
            continue
        correlation_groups = [
            [item[0] for item in family_rows]
            for family_rows in correlation_carry.values()
        ]
        batch = _merge_unique_rows(*correlation_groups, carry, current)
        yield {"items": batch}, _render_rows(batch)
        carry = current[-ROW_OVERLAP:]
        pending_correlation = current
        current = []
        current_chars = 0
    if current:
        correlation_groups = [
            [item[0] for item in family_rows]
            for family_rows in correlation_carry.values()
        ]
        batch = _merge_unique_rows(*correlation_groups, carry, current)
        yield {"items": batch}, _render_rows(batch)


def _merge_unique_rows(
    *groups: Iterable[dict[str, Any]],
) -> list[dict[str, Any]]:
    """Merge row references without double-counting overlap/correlation carry."""
    out: list[dict[str, Any]] = []
    seen: set[int] = set()
    for group in groups:
        for row in group:
            identity = id(row)
            if identity in seen:
                continue
            seen.add(identity)
            out.append(row)
    return out


def _update_correlation_carry(
    carry: dict[str, list[tuple[dict[str, Any], int]]],
    current: list[dict[str, Any]],
    coverage_warnings: list[str],
) -> None:
    for row in current:
        family = cross_batch_correlation_family(row)
        if family is not None:
            carry.setdefault(family, []).append((row, _row_size(row)))

    for family, family_rows in carry.items():
        total_chars = sum(item[1] for item in family_rows)
        drop = 0
        while drop < len(family_rows) and (
            len(family_rows) - drop > CORRELATION_FAMILY_CARRY
            or total_chars > CORRELATION_FAMILY_MAX_CHARS
        ):
            total_chars -= family_rows[drop][1]
            drop += 1
        if drop == 0:
            continue
        del family_rows[:drop]
        warning = (
            f"{family} event correlation carry exceeded its bounded "
            f"{CORRELATION_FAMILY_CARRY}-row/{CORRELATION_FAMILY_MAX_CHARS}-character "
            "budget; cross-batch correlation "
            "coverage was truncated"
        )
        if warning not in coverage_warnings:
            logger.warning(warning)
            coverage_warnings.append(warning)


def _iter_csv(
    artifact: _ArtifactInput,
    coverage_warnings: list[str],
) -> Iterator[tuple[Any, str]]:
    with artifact.path.open("r", encoding="utf-8-sig", errors="replace", newline="") as handle:
        source = _BoundedCsvLines(handle)
        header_reader = csv.reader(source)
        try:
            fieldnames = next(header_reader)
        except (StopIteration, csv.Error, _CsvRecordLimitError) as exc:
            warning = (
                f"CSV artifact {artifact.path} has an unreadable or oversized header: "
                f"{exc}; the raw artifact was retained"
            )
            logger.warning(warning)
            coverage_warnings.append(warning)
            return
        source.reset_record()
        reader = csv.DictReader(source, fieldnames=fieldnames)

        def rows() -> Iterator[dict[str, Any]]:
            nonlocal reader
            errors = 0
            while True:
                try:
                    row = next(reader)
                except StopIteration:
                    return
                except _CsvRecordLimitError as exc:
                    errors += 1
                    warning = (
                        f"CSV artifact {artifact.path} contains a record above the "
                        f"{ROW_BATCH_MAX_CHARS}-character limit near line "
                        f"{exc.line_number}; the record was skipped and the raw "
                        "artifact was retained"
                    )
                    logger.warning(warning)
                    if warning not in coverage_warnings:
                        coverage_warnings.append(warning)
                    source.reset_record()
                    if not exc.recoverable or errors >= 100:
                        return
                    reader = csv.DictReader(source, fieldnames=fieldnames)
                    continue
                except csv.Error as exc:
                    errors += 1
                    warning = (
                        f"CSV artifact {artifact.path} contains an oversized or "
                        f"malformed record near line {reader.line_num}: {exc}; "
                        "the record was skipped and the raw artifact was retained"
                    )
                    logger.warning(warning)
                    if warning not in coverage_warnings:
                        coverage_warnings.append(warning)
                    if errors >= 100:
                        return
                    source.reset_record()
                    reader = csv.DictReader(source, fieldnames=fieldnames)
                    continue
                source.reset_record()
                yield dict(row)

        yield from _iter_row_batches(rows(), coverage_warnings)


def _iter_ndjson(
    artifact: _ArtifactInput,
    coverage_warnings: list[str],
) -> Iterator[tuple[Any, str]]:
    def rows() -> Iterator[dict[str, Any]]:
        oversized_warning_emitted = False
        malformed_warning_emitted = False
        with artifact.path.open("r", encoding="utf-8-sig", errors="replace") as handle:
            line_number = 0
            while True:
                line = handle.readline(CASE_A_MAX + 1)
                if not line:
                    break
                line_number += 1
                if len(line) > CASE_A_MAX:
                    while line and not line.endswith("\n"):
                        line = handle.readline(CASE_A_MAX + 1)
                    if not oversized_warning_emitted:
                        warning = (
                            f"NDJSON artifact {artifact.path} contains records above "
                            f"the {CASE_A_MAX}-character line limit; oversized records "
                            "were skipped and the raw artifact was retained"
                        )
                        logger.warning(warning)
                        coverage_warnings.append(warning)
                        oversized_warning_emitted = True
                    continue
                stripped = line.strip()
                if not stripped:
                    continue
                try:
                    value = json.loads(stripped)
                except json.JSONDecodeError as exc:
                    logger.warning(
                        "skip malformed NDJSON %s:%d: %s",
                        artifact.path,
                        line_number,
                        exc,
                    )
                    if not malformed_warning_emitted:
                        warning = (
                            f"NDJSON artifact {artifact.path} contains malformed "
                            "records; invalid records were skipped and the raw "
                            "artifact was retained"
                        )
                        coverage_warnings.append(warning)
                        malformed_warning_emitted = True
                    continue
                if isinstance(value, dict):
                    yield value

    yield from _iter_row_batches(rows(), coverage_warnings)


def _iter_json(
    artifact: _ArtifactInput,
    coverage_warnings: list[str],
) -> Iterator[tuple[Any, str]]:
    if artifact.size_bytes > CASE_B_MAX:
        warning = (
            f"JSON artifact {artifact.path} is {artifact.size_bytes} bytes, above "
            f"the {CASE_B_MAX}-byte parser limit; raw artifact retained but "
            "content was not analyzed"
        )
        logger.warning(warning)
        coverage_warnings.append(warning)
        return
    try:
        with artifact.path.open("r", encoding="utf-8-sig", errors="replace") as handle:
            value = json.load(handle)
    except (OSError, json.JSONDecodeError) as exc:
        logger.warning("cannot parse JSON artifact %s: %s", artifact.path, exc)
        coverage_warnings.append(
            f"JSON artifact {artifact.path} could not be parsed; raw artifact "
            "retained but content was not analyzed"
        )
        return
    rows: list[dict[str, Any]] | None = None
    if isinstance(value, list):
        rows = [row for row in value if isinstance(row, dict)]
    elif isinstance(value, dict):
        for key, candidate in value.items():
            normalized = re.sub(r"[^a-z0-9]", "", str(key).casefold())
            if normalized in {"items", "results", "rows", "events", "records"}:
                if isinstance(candidate, list):
                    rows = [row for row in candidate if isinstance(row, dict)]
                    break
    if rows is not None:
        yield from _iter_row_batches(iter(rows), coverage_warnings)
        return

    raw = ""
    if artifact.size_bytes <= CASE_A_MAX:
        try:
            raw = artifact.path.read_text(encoding="utf-8-sig", errors="replace")
        except OSError:
            raw = ""
    yield value, raw


def _iter_text(
    artifact: _ArtifactInput,
    coverage_warnings: list[str],
) -> Iterator[tuple[Any, str]]:
    try:
        with artifact.path.open("r", encoding="utf-8-sig", errors="replace") as handle:
            overlap = ""
            while True:
                chunk = handle.read(TEXT_CHUNK_CHARS)
                if not chunk:
                    break
                text = overlap + chunk
                yield None, text
                overlap = text[-TEXT_OVERLAP_CHARS:]
    except OSError as exc:
        logger.warning("cannot read text artifact %s: %s", artifact.path, exc)
        coverage_warnings.append(
            f"text artifact {artifact.path} could not be read; raw artifact "
            "coverage is incomplete"
        )


def _iter_artifact_batches(
    artifact: _ArtifactInput,
    coverage_warnings: list[str],
) -> Iterator[tuple[Any, str]]:
    fmt = _infer_format(artifact)
    if fmt == "csv":
        yield from _iter_csv(artifact, coverage_warnings)
    elif fmt in {"jsonl", "ndjson"}:
        yield from _iter_ndjson(artifact, coverage_warnings)
    elif fmt == "json":
        yield from _iter_json(artifact, coverage_warnings)
    else:
        yield from _iter_text(artifact, coverage_warnings)


def _line_hint(finding: Finding) -> str:
    match = re.search(r":(\d+)(?:\b|\s+-)", finding.description)
    return match.group(1) if match else ""


def _canonical_key(finding: Finding, tool_id: str) -> tuple[str, ...]:
    ref = finding.evidence_ref
    rule = (finding.rule_id or finding.title).strip().casefold()
    source_file = ref.source_file.strip().casefold()
    line = _line_hint(finding)
    location = (
        source_file,
        line,
        str(ref.event_id or ""),
        ref.timestamp.strip(),
    )
    # Event IDs and timestamps are not unique: several records can occur in
    # the same second.  Keep the normalized excerpt in every key; exact rows
    # repeated by streaming overlap still collapse, while distinct events do
    # not disappear.
    excerpt = re.sub(r"\s+", " ", ref.raw_excerpt).strip()
    excerpt_hash = hashlib.sha256(excerpt.encode("utf-8")).hexdigest()[:20]
    return (tool_id.casefold(), rule, *location, excerpt_hash)


def _dedupe(findings: list[Finding], *, tool_id: str = "") -> list[Finding]:
    """Dedupe by stable rule and tool-output location, never display title."""
    seen: dict[tuple[str, ...], Finding] = {}
    for finding in findings:
        finding.refresh_fingerprint()
        key = _canonical_key(finding, tool_id)
        previous = seen.get(key)
        if previous is None:
            seen[key] = finding
            continue
        previous_rank = SEVERITY_RANK[previous.severity]
        current_rank = SEVERITY_RANK[finding.severity]
        if current_rank > previous_rank or (
            current_rank == previous_rank and finding.confidence > previous.confidence
        ):
            seen[key] = finding
    return list(seen.values())


def _sort_severity_desc(findings: list[Finding]) -> list[Finding]:
    return sorted(
        findings,
        key=lambda finding: (SEVERITY_RANK[finding.severity], finding.confidence),
        reverse=True,
    )


def _merge_bounded(
    existing: list[Finding], incoming: list[Finding], *, tool_id: str
) -> tuple[list[Finding], bool]:
    merged = _dedupe(existing + incoming, tool_id=tool_id)
    ordered = _sort_severity_desc(merged)
    return ordered[:MAX_RETAINED_FINDINGS], len(ordered) > MAX_RETAINED_FINDINGS


def _grounded_rule_input(findings: list[Finding]) -> str:
    blocks: list[str] = []
    used = 0
    for finding in findings:
        excerpt = finding.evidence_ref.raw_excerpt.strip()
        if not excerpt:
            continue
        block = (
            f"Rule: {finding.rule_id or finding.title}\n"
            f"Deterministic title: {finding.title}\n"
            f"Evidence excerpt:\n{excerpt}"
        )
        if used + len(block) > 12_000:
            break
        blocks.append(block)
        used += len(block)
    return "\n\n".join(blocks)


def _case_for(size: int) -> str:
    if size <= CASE_A_MAX:
        return "A"
    if size <= CASE_B_MAX:
        return "B"
    return "C"


def analyze_one(
    result: ExecutionResult,
    metadata: ToolMetadata,
    *,
    use_llm: bool = True,
    use_rag: bool = True,
    client: OllamaClient | None = None,
    scenario: str | None = None,
    stage_ms: dict[str, int] | None = None,
) -> ToolAnalysis:
    analysis = ToolAnalysis(tool_id=metadata.tool_id)
    artifacts = _artifact_inputs(result)
    parsed_inline = _artifact_value(result, "parsed_output", None)
    status = str(_artifact_value(result, "status", "skipped"))
    target_evidence = str(_artifact_value(result, "target_evidence", "") or "")

    if not artifacts and parsed_inline is None:
        analysis.summary = (
            f"deterministic=0; total=0; execution_status={status}: "
            f"{str(_artifact_value(result, 'error_message', ''))[:160]}"
        )
        return analysis

    total_size = sum(artifact.size_bytes for artifact in artifacts)
    if not total_size:
        total_size = int(_artifact_value(result, "output_size_bytes", 0) or 0)
    analysis.case_used = _case_for(total_size)

    rule_findings: list[Finding] = []
    llm_raw_parts: list[str] = []
    coverage_warnings = analysis.coverage_warnings
    with Stopwatch() as sw_rules:
        if artifacts:
            for artifact in artifacts:
                for parsed, raw in _iter_artifact_batches(
                    artifact,
                    coverage_warnings,
                ):
                    if analysis.case_used == "A" and raw:
                        remaining = CASE_A_MAX - sum(len(part) for part in llm_raw_parts)
                        if remaining > 0:
                            llm_raw_parts.append(raw[:remaining])
                    batch_findings, batch_limit_reached = apply_rules_with_status(
                        parsed,
                        raw,
                        metadata,
                        evidence_path=target_evidence,
                    )
                    rule_findings, merge_limit_reached = _merge_bounded(
                        rule_findings,
                        batch_findings,
                        tool_id=metadata.tool_id,
                    )
                    if batch_limit_reached or merge_limit_reached:
                        analysis.finding_limit_reached = True
        else:
            batch_findings, batch_limit_reached = apply_rules_with_status(
                parsed_inline,
                "",
                metadata,
                evidence_path=target_evidence,
            )
            rule_findings, merge_limit_reached = _merge_bounded(
                rule_findings,
                batch_findings,
                tool_id=metadata.tool_id,
            )
            analysis.finding_limit_reached = (
                batch_limit_reached or merge_limit_reached
            )

    if stage_ms is not None:
        key = f"analyze_rules:{metadata.tool_id}"
        stage_ms[key] = stage_ms.get(key, 0) + sw_rules.elapsed_ms

    deterministic = _dedupe(rule_findings, tool_id=metadata.tool_id)
    llm_findings: list[Finding] = []
    llm_summary = ""
    invoked = False
    failed = False
    llm_input = ""
    # Code-security artifacts can contain live credentials or source literals.
    # Deterministic parsers handle them without sending raw content to an LLM.
    if use_llm and analysis.case_used != "C" and metadata.category != "code_security":
        if analysis.case_used == "B":
            # Case B never sends a raw multi-megabyte artifact to the model.
            llm_input = _grounded_rule_input(deterministic)
        else:
            llm_input = "\n".join(llm_raw_parts)
            if not llm_input and deterministic:
                llm_input = _grounded_rule_input(deterministic)

    if llm_input.strip():
        rag_context = _rag_context_for(metadata) if use_rag else ""
        with Stopwatch() as sw_llm:
            llm_findings, llm_summary, invoked, failed = llm_extract(
                metadata,
                llm_input,
                evidence_path=target_evidence,
                client=client,
                scenario=scenario,
                rag_context=rag_context or None,
            )
        if stage_ms is not None:
            key = f"analyze_llm:{metadata.tool_id}"
            stage_ms[key] = stage_ms.get(key, 0) + sw_llm.elapsed_ms

    merged = _dedupe(deterministic + llm_findings, tool_id=metadata.tool_id)
    merged = _sort_severity_desc(merged)
    if len(merged) > MAX_RETAINED_FINDINGS:
        analysis.finding_limit_reached = True
        merged = merged[:MAX_RETAINED_FINDINGS]
    analysis.findings = merged
    analysis.llm_invoked = invoked
    analysis.llm_failed = failed

    counts = by_severity_count(merged)
    categories: dict[str, int] = {}
    for finding in merged:
        categories[finding.category] = categories.get(finding.category, 0) + 1
    top_categories = sorted(categories.items(), key=lambda item: item[1], reverse=True)[:3]
    category_text = ", ".join(f"{name}({count})" for name, count in top_categories) or "n/a"
    severity_text = (
        f"critical={counts['critical']} high={counts['high']} "
        f"medium={counts['medium']} low={counts['low']} info={counts['info']}"
    )
    summary_parts = [
        f"deterministic={len(deterministic)}",
        f"total={len(merged)} ({severity_text})",
        f"top={category_text}",
    ]
    if status != "success":
        summary_parts.append(f"execution_status={status} (partial artifact analyzed)")
    warnings = _artifact_value(result, "warnings", None) or []
    if warnings:
        summary_parts.append(f"executor_warnings={len(warnings)}")
    if coverage_warnings:
        summary_parts.append("coverage_truncated=true")
        summary_parts.append(f"coverage_warning={coverage_warnings[0][:240]}")
    if llm_summary.strip():
        # The model may add context, but can never replace deterministic counts.
        summary_parts.append(f"llm_note={llm_summary.strip()[:240]}")
    if analysis.finding_limit_reached:
        summary_parts.append("finding_limit_reached=true")
    analysis.summary = "; ".join(summary_parts)
    return analysis


def analyze_all(
    execution_results: list[ExecutionResult],
    tools: dict[str, ToolMetadata],
    *,
    use_llm: bool = True,
    use_rag: bool = True,
    client: OllamaClient | None = None,
    scenario: str | None = None,
    stage_ms: dict[str, int] | None = None,
) -> list[ToolAnalysis]:
    out: list[ToolAnalysis] = []
    for result in execution_results:
        tool_id = str(_artifact_value(result, "tool_id", ""))
        metadata = tools.get(tool_id)
        if metadata is None:
            logger.warning("no metadata for tool_id=%r", tool_id)
            continue
        try:
            analysis = analyze_one(
                result,
                metadata,
                use_llm=use_llm,
                use_rag=use_rag,
                client=client,
                scenario=scenario,
                stage_ms=stage_ms,
            )
        except Exception as exc:  # noqa: BLE001 - isolate one malformed tool artifact.
            logger.exception("analysis failed for tool_id=%s", tool_id)
            analysis = ToolAnalysis(
                tool_id=tool_id,
                summary=f"not analyzed: analyzer error: {exc}",
                coverage_warnings=[
                    f"analyzer failed for {tool_id}; raw artifacts were retained"
                ],
            )
        out.append(analysis)
    return out
