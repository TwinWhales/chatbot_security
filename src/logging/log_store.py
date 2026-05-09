"""SQLAlchemy-backed log store for query/answer cycles."""

from __future__ import annotations

import json
import uuid
from dataclasses import asdict, is_dataclass
from datetime import datetime, timezone
from typing import Any

from sqlalchemy import (
    JSON,
    Column,
    DateTime,
    Float,
    Integer,
    String,
    Text,
    create_engine,
)
from sqlalchemy.orm import DeclarativeBase, Session

from config import settings


class Base(DeclarativeBase):
    pass


class QueryLog(Base):
    __tablename__ = "query_logs"

    log_id = Column(String, primary_key=True)
    timestamp = Column(DateTime, nullable=False)
    user_query = Column(Text, nullable=False)
    processed_query = Column(Text, nullable=False)
    retrieval_source = Column(String, nullable=False)   # "rag" | "web"
    retrieved_chunks = Column(JSON, nullable=False)
    similarity_scores = Column(JSON, nullable=False)
    generated_answer = Column(Text, nullable=False)
    sources_cited = Column(JSON, nullable=False)
    response_time_ms = Column(Integer, nullable=False)
    top_score = Column(Float, nullable=True)
    user_feedback = Column(JSON, nullable=True)
    metrics = Column(JSON, nullable=True)   # full QueryMetrics dump


class LogStore:
    def __init__(self, db_url: str | None = None) -> None:
        self._engine = create_engine(db_url or settings.LOG_DB_URL, future=True)
        Base.metadata.create_all(self._engine)

    def record(self, payload: dict[str, Any]) -> str:
        log_id = payload.get("log_id") or str(uuid.uuid4())
        row = QueryLog(
            log_id=log_id,
            timestamp=payload.get("timestamp") or datetime.now(timezone.utc),
            user_query=payload["user_query"],
            processed_query=payload["processed_query"],
            retrieval_source=payload["retrieval_source"],
            retrieved_chunks=_jsonable(payload.get("retrieved_chunks", [])),
            similarity_scores=_jsonable(payload.get("similarity_scores", [])),
            generated_answer=payload["generated_answer"],
            sources_cited=_jsonable(payload.get("sources_cited", [])),
            response_time_ms=int(payload.get("response_time_ms", 0)),
            top_score=payload.get("top_score"),
            user_feedback=payload.get("user_feedback"),
            metrics=_jsonable(payload.get("metrics")),
        )
        with Session(self._engine) as session:
            session.add(row)
            session.commit()
        return log_id

    def get(self, log_id: str) -> dict[str, Any] | None:
        with Session(self._engine) as session:
            row = session.get(QueryLog, log_id)
            if row is None:
                return None
            return _row_to_dict(row)

    def attach_feedback(self, log_id: str, feedback: dict[str, Any]) -> bool:
        with Session(self._engine) as session:
            row = session.get(QueryLog, log_id)
            if row is None:
                return False
            row.user_feedback = feedback
            session.commit()
            return True


def _jsonable(value: Any) -> Any:
    if value is None:
        return None
    if is_dataclass(value):
        return asdict(value)
    if isinstance(value, (list, tuple)):
        return [_jsonable(v) for v in value]
    if isinstance(value, dict):
        return {k: _jsonable(v) for k, v in value.items()}
    if isinstance(value, (str, int, float, bool)):
        return value
    # Fall back to str so we never fail to log because of an exotic value.
    try:
        return json.loads(json.dumps(value, default=str))
    except Exception:
        return str(value)


def _row_to_dict(row: QueryLog) -> dict[str, Any]:
    return {
        "log_id": row.log_id,
        "timestamp": row.timestamp.isoformat() if row.timestamp else None,
        "user_query": row.user_query,
        "processed_query": row.processed_query,
        "retrieval_source": row.retrieval_source,
        "retrieved_chunks": row.retrieved_chunks,
        "similarity_scores": row.similarity_scores,
        "generated_answer": row.generated_answer,
        "sources_cited": row.sources_cited,
        "response_time_ms": row.response_time_ms,
        "top_score": row.top_score,
        "user_feedback": row.user_feedback,
        "metrics": row.metrics,
    }
