"""Aggregate views over the log store for future-learning use cases.

명세 5.2 — 직접 구현해보세요.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from src.logging.log_store import LogStore


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


def route_counts(store: LogStore) -> RouteBreakdown:
    """retrieval_source 별 카운트 집계.

    TODO: SELECT retrieval_source, COUNT(*) GROUP BY retrieval_source
    """
    raise NotImplementedError("route_counts")


def fallback_queries(store: LogStore, limit: int = 50) -> list[dict[str, Any]]:
    """웹 폴백된 질문 목록 (KB 보강 후보).

    TODO:
      - retrieval_source == "web" 인 row 를 timestamp DESC 로 limit 개
      - {log_id, timestamp, user_query, top_score} dict 의 list 반환
    """
    raise NotImplementedError("fallback_queries")


def average_latency_ms(store: LogStore) -> float:
    """전체 응답시간 평균.

    TODO: SELECT AVG(response_time_ms)
    """
    raise NotImplementedError("average_latency_ms")


def latency_stats(store: LogStore) -> LatencyStats:
    """전체 응답시간의 mean/p50/p95/p99/min/max.

    TODO:
      - 모든 response_time_ms 를 가져와 list[float]
      - src.observability.metrics.percentile 로 p50/p95/p99 계산
      - LatencyStats 반환
    """
    raise NotImplementedError("latency_stats")


def stage_latency_stats(store: LogStore) -> dict[str, LatencyStats]:
    """metrics.stage_ms 를 풀어 그래프 노드별 latency 집계.

    TODO:
      - 모든 row 의 metrics["stage_ms"] 를 stage 이름으로 bucket
      - bucket 별로 LatencyStats 계산
      - {stage_name: LatencyStats} 반환
    """
    raise NotImplementedError("stage_latency_stats")


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
    """품질 지표 집계.

    TODO: 전체 row 를 1 회 순회하며 다음을 누적
      - threshold_met_rate: metrics["threshold_met"] = True 의 비율
      - rag_rate / web_rate: retrieval_source 비율
      - avg_top_score: top_score 평균
      - avg_chunks_retrieved: metrics["chunks_retrieved"] 평균
      - rewritten_rate: metrics["rewritten"] = True 의 비율
    """
    raise NotImplementedError("quality_stats")


def full_report(store: LogStore) -> dict[str, Any]:
    """CLI `metrics` 명령이 출력하는 통합 리포트.

    TODO: 다음을 dict 로 묶어 반환
      - totals: {queries, rag, web}
      - latency_overall_ms: latency_stats(store).to_dict()
      - latency_per_stage_ms: {stage: stats.to_dict()}
      - quality: quality_stats(store).to_dict()
    """
    raise NotImplementedError("full_report")
