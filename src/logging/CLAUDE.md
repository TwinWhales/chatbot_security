# src/logging/ — Layer 5 (Logging & Future Learning)

명세 5.1 / 5.2. 모든 질의-응답 사이클을 SQL 에 영속화하고, 그 위에서
"향후 강화학습 데이터" 로 활용 가능한 분석 뷰를 만든다.

> 패키지 이름이 stdlib `logging` 과 같지만, 모든 import 는 `src.logging.*`
> 절대경로라 충돌하지 않는다. 내부 코드에서도 `import logging` 같은 라인은
> 두지 않는다.

## 모듈

### `log_store.py` — 5.1 (로그 DB 저장)

#### 무엇을 구현했나
SQLAlchemy 2.0 ORM 으로 한 테이블 (`query_logs`) 을 운용. 명세에 나온
모든 필드 + 측정값(`metrics` JSON) 까지 저장한다.

#### 세부 구현
- ORM 모델 `QueryLog` 컬럼:
  - `log_id` (PK, UUID 문자열)
  - `timestamp` (UTC datetime)
  - `user_query`, `processed_query`, `generated_answer` (Text)
  - `retrieval_source` ("rag" | "web")
  - `retrieved_chunks`, `similarity_scores`, `sources_cited` (JSON)
  - `response_time_ms` (Integer), `top_score` (Float, nullable)
  - `user_feedback` (JSON, nullable) — 명세의 향후 학습 hook
  - `metrics` (JSON, nullable) — `QueryMetrics.to_dict()` 통째로 저장
- `LogStore.__init__` — `create_engine(db_url)` + `Base.metadata.create_all`.
  최초 호출 시 테이블이 자동 생성된다.
- `record(payload)` — UUID 생성, datetime 기본값 보정, `_jsonable()` 로
  dataclass / 비-JSON 객체를 모두 직렬화해 저장. 로그 실패가 파이프라인을
  깨지 않도록 defensive 한 직렬화.
- `get(log_id)` — 단일 row 를 dict 로 반환.
- `attach_feedback(log_id, feedback)` — 추후 사용자 피드백을 부착 (5.2 가
  필요로 하는 데이터 보강 경로).

### `analytics.py` — 5.2 (집계 / 분석 뷰)

#### 무엇을 구현했나
저장된 로그 위에서 시스템 운영에 필요한 정량 지표를 모두 계산한다.
이 모듈을 읽으면 시스템이 어떤 수치로 평가받는지 한눈에 보인다.

#### 세부 구현
- `RouteBreakdown` — RAG / Web 카운트.
- `LatencyStats` — `count, mean_ms, p50_ms, p95_ms, p99_ms, min_ms, max_ms`.
  percentile 계산은 `src.observability.metrics.percentile` (linear interp).
- `route_counts(store)` — `GROUP BY retrieval_source` SQL.
- `fallback_queries(store, limit=50)` — 웹 폴백된 질문 목록 (KB 보강 후보).
- `latency_stats(store)` — 전체 응답시간의 통계.
- `stage_latency_stats(store)` — `metrics.stage_ms` 를 풀어 노드별 평균/
  p50/p95/p99 까지 계산. Ingestion 그래프 / Query 그래프 양쪽 모두의
  stage 가 한 dict 안에 섞여 들어온다 (이름이 안 겹치므로 OK).
- `quality_stats(store)` — `threshold_met_rate`, `rag_rate`, `web_rate`,
  `avg_top_score`, `avg_chunks_retrieved`, `rewritten_rate`.
- `full_report(store)` — CLI `python main.py metrics` 가 출력하는 통합 리포트.
  totals + latency + per-stage latency + quality 를 한 dict 로 묶어 반환.

`Session(store._engine)` 식으로 LogStore 의 private 엔진을 직접 쓰는데,
analytics 는 LogStore 의 privileged consumer 라는 의도된 결합이다.

## 의존 흐름
```
log_store.QueryLog (스키마) ←─ analytics 의 모든 집계 함수
LogStore (CRUD)                ↑
  └─ src/graphs/query_graph.py 의 node_log 가 호출
```
