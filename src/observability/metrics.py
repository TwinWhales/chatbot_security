"""Metrics primitives shared by ingestion, query, response, and logging layers.

Goals:
  * Every stage is timed.
  * Every quantity (bytes in, chunks out, scores, token counts) is recorded.
  * Metrics are JSON-serializable so they can be persisted in the log store
    and consumed by the analytics module.
"""

from __future__ import annotations

import statistics
import time
from dataclasses import dataclass, field
from typing import Any


# ---------- timing ----------

class Stopwatch:
    """Context manager that records a single elapsed-ms measurement.

        with Stopwatch() as sw:
            do_work()
        elapsed = sw.elapsed_ms
    """

    __slots__ = ("_start", "elapsed_ms")

    def __init__(self) -> None:
        self._start = 0.0
        self.elapsed_ms = 0

    def __enter__(self) -> "Stopwatch":
        self._start = time.perf_counter()
        return self

    def __exit__(self, *_exc: Any) -> None:
        self.elapsed_ms = int((time.perf_counter() - self._start) * 1000)


class StageTimings(dict):
    """Mapping of stage name -> elapsed milliseconds.

    Subclasses dict so it serializes naturally to JSON.
    """

    def time(self, name: str) -> "_StageContext":
        return _StageContext(self, name)


class _StageContext:
    __slots__ = ("_timings", "_name", "_start")

    def __init__(self, timings: StageTimings, name: str) -> None:
        self._timings = timings
        self._name = name
        self._start = 0.0

    def __enter__(self) -> "_StageContext":
        self._start = time.perf_counter()
        return self

    def __exit__(self, *_exc: Any) -> None:
        elapsed = int((time.perf_counter() - self._start) * 1000)
        # Accumulate so a stage can be entered multiple times within one cycle.
        self._timings[self._name] = self._timings.get(self._name, 0) + elapsed


# ---------- aggregate stats ----------

@dataclass
class ScoreStats:
    count: int = 0
    top: float = 0.0
    mean: float = 0.0
    median: float = 0.0
    min: float = 0.0
    max: float = 0.0
    stdev: float = 0.0

    @classmethod
    def from_values(cls, values: list[float]) -> "ScoreStats":
        if not values:
            return cls()
        return cls(
            count=len(values),
            top=max(values),
            mean=float(statistics.fmean(values)),
            median=float(statistics.median(values)),
            min=min(values),
            max=max(values),
            stdev=float(statistics.pstdev(values)) if len(values) > 1 else 0.0,
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "count": self.count,
            "top": self.top,
            "mean": self.mean,
            "median": self.median,
            "min": self.min,
            "max": self.max,
            "stdev": self.stdev,
        }


@dataclass
class LengthStats:
    """Char-length distribution across a list of strings."""

    count: int = 0
    total_chars: int = 0
    mean_chars: float = 0.0
    min_chars: int = 0
    max_chars: int = 0

    @classmethod
    def from_strings(cls, strings: list[str]) -> "LengthStats":
        if not strings:
            return cls()
        lens = [len(s) for s in strings]
        return cls(
            count=len(lens),
            total_chars=sum(lens),
            mean_chars=sum(lens) / len(lens),
            min_chars=min(lens),
            max_chars=max(lens),
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "count": self.count,
            "total_chars": self.total_chars,
            "mean_chars": self.mean_chars,
            "min_chars": self.min_chars,
            "max_chars": self.max_chars,
        }


# ---------- per-cycle metrics ----------

@dataclass
class IngestMetrics:
    source_file: str = ""
    file_type: str = ""
    file_size_bytes: int = 0
    used_ocr: bool = False

    pages_extracted: int = 0
    pages_after_clean: int = 0
    chunks_written: int = 0

    chunk_lengths: LengthStats = field(default_factory=LengthStats)
    embedding_dimension: int = 0

    stage_ms: StageTimings = field(default_factory=StageTimings)
    total_ms: int = 0

    def to_dict(self) -> dict[str, Any]:
        return {
            "source_file": self.source_file,
            "file_type": self.file_type,
            "file_size_bytes": self.file_size_bytes,
            "used_ocr": self.used_ocr,
            "pages_extracted": self.pages_extracted,
            "pages_after_clean": self.pages_after_clean,
            "chunks_written": self.chunks_written,
            "chunk_lengths": self.chunk_lengths.to_dict(),
            "embedding_dimension": self.embedding_dimension,
            "stage_ms": dict(self.stage_ms),
            "total_ms": self.total_ms,
        }


@dataclass
class QueryMetrics:
    query_chars: int = 0
    processed_chars: int = 0
    rewritten: bool = False

    embedding_dimension: int = 0
    top_k: int = 0
    threshold: float = 0.0

    chunks_retrieved: int = 0
    threshold_met: bool = False
    similarity: ScoreStats = field(default_factory=ScoreStats)
    retrieved_chunk_lengths: LengthStats = field(default_factory=LengthStats)

    retrieval_source: str = ""    # "rag" | "web"
    web_results_raw: int = 0
    web_results_kept: int = 0

    answer_chars: int = 0
    prompt_chars: int = 0
    llm_provider: str = ""
    llm_model: str = ""

    stage_ms: StageTimings = field(default_factory=StageTimings)
    total_ms: int = 0

    def to_dict(self) -> dict[str, Any]:
        return {
            "query_chars": self.query_chars,
            "processed_chars": self.processed_chars,
            "rewritten": self.rewritten,
            "embedding_dimension": self.embedding_dimension,
            "top_k": self.top_k,
            "threshold": self.threshold,
            "chunks_retrieved": self.chunks_retrieved,
            "threshold_met": self.threshold_met,
            "similarity": self.similarity.to_dict(),
            "retrieved_chunk_lengths": self.retrieved_chunk_lengths.to_dict(),
            "retrieval_source": self.retrieval_source,
            "web_results_raw": self.web_results_raw,
            "web_results_kept": self.web_results_kept,
            "answer_chars": self.answer_chars,
            "prompt_chars": self.prompt_chars,
            "llm_provider": self.llm_provider,
            "llm_model": self.llm_model,
            "stage_ms": dict(self.stage_ms),
            "total_ms": self.total_ms,
        }


# ---------- percentile helpers (for analytics) ----------

def percentile(values: list[float], p: float) -> float:
    """Linear-interpolation percentile, matching numpy default. p in [0, 100]."""
    if not values:
        return 0.0
    if len(values) == 1:
        return float(values[0])
    s = sorted(values)
    rank = (p / 100.0) * (len(s) - 1)
    lo = int(rank)
    hi = min(lo + 1, len(s) - 1)
    frac = rank - lo
    return float(s[lo] + (s[hi] - s[lo]) * frac)
