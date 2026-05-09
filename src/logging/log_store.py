"""SQLAlchemy-backed log store for query/answer cycles.

명세 5.1 — 직접 구현해보세요.
"""

from __future__ import annotations

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
    """명세 5.1 의 로그 스키마 (+ metrics JSON 컬럼)."""

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
    metrics = Column(JSON, nullable=True)   # QueryMetrics.to_dict() 통째로 저장


class LogStore:
    def __init__(self, db_url: str | None = None) -> None:
        """create_engine + create_all 로 테이블 자동 생성.

        TODO:
          - self._engine = create_engine(db_url or settings.LOG_DB_URL, future=True)
          - Base.metadata.create_all(self._engine)
        """
        raise NotImplementedError("LogStore.__init__")

    def record(self, payload: dict[str, Any]) -> str:
        """한 사이클을 영속화. log_id 가 없으면 UUID 로 생성해 반환.

        TODO:
          - log_id = payload.get("log_id") or str(uuid.uuid4())
          - timestamp 기본값: datetime.now(timezone.utc)
          - retrieved_chunks / similarity_scores / sources_cited / metrics 는
            _jsonable() 로 직렬화 (dataclass / 비-JSON 객체 모두 안전하게)
          - QueryLog 인스턴스를 만들어 session.add + commit
          - log_id 반환
        """
        raise NotImplementedError("LogStore.record")

    def get(self, log_id: str) -> dict[str, Any] | None:
        """단일 로그를 dict 로 반환. 없으면 None.

        TODO:
          - Session(self._engine).get(QueryLog, log_id)
          - _row_to_dict 로 변환
        """
        raise NotImplementedError("LogStore.get")

    def attach_feedback(self, log_id: str, feedback: dict[str, Any]) -> bool:
        """추후 사용자 피드백을 부착 (5.2 의 future-learning hook).

        TODO:
          - 해당 row.user_feedback = feedback; commit
          - 성공 True, row 없으면 False
        """
        raise NotImplementedError("LogStore.attach_feedback")


def _jsonable(value: Any) -> Any:
    """dataclass / 비-JSON 값까지 안전하게 JSON 직렬화 가능한 형태로 변환.

    TODO (방어적 처리):
      - None → None
      - dataclass → asdict
      - list/tuple → 재귀
      - dict → 재귀
      - 원시 타입 (str/int/float/bool) → 그대로
      - 그 외 → json.dumps(default=str) 후 loads, 실패하면 str()
    """
    raise NotImplementedError("_jsonable")


def _row_to_dict(row: QueryLog) -> dict[str, Any]:
    """QueryLog row → dict 변환.

    TODO: 컬럼들을 그대로 dict 에 담아 반환 (timestamp 는 isoformat).
    """
    raise NotImplementedError("_row_to_dict")
