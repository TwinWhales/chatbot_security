"""Aggregate views over the log store for future-learning use cases.

Everything quantitative is exposed here so dashboards / CLIs / schedulers
can read the same numbers without re-running SQL by hand.
"""

from __future__ import annotations

from collections import Counter, defaultdict
from dataclasses import dataclass
from typing import Any

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from src.logging.log_store import LogStore, QueryLog
from src.observability.metrics import percentile


@dataclass
class RouteBreakdown:
    rag: int
    web: int

    @property
    def total(self) -> int:
        return self.rag + self.web


@dataclass
class LatencyStats:
    count: int
    mean_ms: float
    p50_ms: float
    p95_ms: float
    p99_ms: float
    min_ms: float
    max_ms: float

    def to_dict(self) -> dict[str, Any]:
        return {
            "count": self.count,
            "mean_ms": self.mean_ms,
            "p50_ms": self.p50_ms,
            "p95_ms": self.p95_ms,
            "p99_ms": self.p99_ms,
            "min_ms": self.min_ms,
            "max_ms": self.max_ms,
        }


def _all_logs(store: LogStore) -> list[QueryLog]:
    with Session(store._engine) as session:  # noqa: SLF001
        return list(session.execute(select(QueryLog)).scalars())


def route_counts(store: LogStore) -> RouteBreakdown:
    with Session(store._engine) as session:  # noqa: SLF001
        stmt = select(QueryLog.retrieval_source, func.count()).group_by(QueryLog.retrieval_source)
        rows = session.execute(stmt).all()
    counts = {src: n for src, n in rows}
    return RouteBreakdown(rag=counts.get("rag", 0), web=counts.get("web", 0))


def fallback_queries(store: LogStore, limit: int = 50) -> list[dict[str, Any]]:
    """Web-fallback queries — primary candidates for KB enrichment."""
    with Session(store._engine) as session:  # noqa: SLF001
        stmt = (
            select(QueryLog)
            .where(QueryLog.retrieval_source == "web")
            .order_by(QueryLog.timestamp.desc())
            .limit(limit)
        )
        rows = session.execute(stmt).scalars().all()
    return [
        {
            "log_id": r.log_id,
            "timestamp": r.timestamp.isoformat() if r.timestamp else None,
            "user_query": r.user_query,
            "top_score": r.top_score,
        }
        for r in rows
    ]


def average_latency_ms(store: LogStore) -> float:
    with Session(store._engine) as session:  # noqa: SLF001
        avg = session.execute(select(func.avg(QueryLog.response_time_ms))).scalar()
    return float(avg or 0.0)


def latency_stats(store: LogStore) -> LatencyStats:
    """End-to-end response_time_ms with mean/p50/p95/p99/min/max."""
    with Session(store._engine) as session:  # noqa: SLF001
        rows = session.execute(select(QueryLog.response_time_ms)).all()
    values = [float(r[0]) for r in rows if r[0] is not None]
    if not values:
        return LatencyStats(0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0)
    return LatencyStats(
        count=len(values),
        mean_ms=sum(values) / len(values),
        p50_ms=percentile(values, 50),
        p95_ms=percentile(values, 95),
        p99_ms=percentile(values, 99),
        min_ms=min(values),
        max_ms=max(values),
    )


def stage_latency_stats(store: LogStore) -> dict[str, LatencyStats]:
    """Per-stage timing aggregation, pulled from the embedded metrics JSON."""
    buckets: dict[str, list[float]] = defaultdict(list)
    for row in _all_logs(store):
        m = row.metrics or {}
        stages = m.get("stage_ms") or {}
        for name, val in stages.items():
            try:
                buckets[name].append(float(val))
            except (TypeError, ValueError):
                continue

    out: dict[str, LatencyStats] = {}
    for name, vals in buckets.items():
        out[name] = LatencyStats(
            count=len(vals),
            mean_ms=sum(vals) / len(vals),
            p50_ms=percentile(vals, 50),
            p95_ms=percentile(vals, 95),
            p99_ms=percentile(vals, 99),
            min_ms=min(vals),
            max_ms=max(vals),
        )
    return out


@dataclass
class QualityStats:
    queries: int
    threshold_met_rate: float
    rag_rate: float
    web_rate: float
    avg_top_score: float
    avg_chunks_retrieved: float
    rewritten_rate: float

    def to_dict(self) -> dict[str, Any]:
        return self.__dict__.copy()


def quality_stats(store: LogStore) -> QualityStats:
    rows = _all_logs(store)
    n = len(rows)
    if n == 0:
        return QualityStats(0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0)

    route_counter: Counter[str] = Counter()
    threshold_met = 0
    rewritten = 0
    top_scores: list[float] = []
    chunk_counts: list[int] = []

    for r in rows:
        route_counter[r.retrieval_source] += 1
        m = r.metrics or {}
        if m.get("threshold_met"):
            threshold_met += 1
        if m.get("rewritten"):
            rewritten += 1
        ts = r.top_score
        if ts is not None:
            top_scores.append(float(ts))
        chunks_retrieved = m.get("chunks_retrieved")
        if isinstance(chunks_retrieved, (int, float)):
            chunk_counts.append(int(chunks_retrieved))

    return QualityStats(
        queries=n,
        threshold_met_rate=threshold_met / n,
        rag_rate=route_counter.get("rag", 0) / n,
        web_rate=route_counter.get("web", 0) / n,
        avg_top_score=(sum(top_scores) / len(top_scores)) if top_scores else 0.0,
        avg_chunks_retrieved=(sum(chunk_counts) / len(chunk_counts)) if chunk_counts else 0.0,
        rewritten_rate=rewritten / n,
    )


def full_report(store: LogStore) -> dict[str, Any]:
    """One-stop summary used by the CLI `metrics` command."""
    routes = route_counts(store)
    return {
        "totals": {
            "queries": routes.total,
            "rag": routes.rag,
            "web": routes.web,
        },
        "latency_overall_ms": latency_stats(store).to_dict(),
        "latency_per_stage_ms": {k: v.to_dict() for k, v in stage_latency_stats(store).items()},
        "quality": quality_stats(store).to_dict(),
    }
