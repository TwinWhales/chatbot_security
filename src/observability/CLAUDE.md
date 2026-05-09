# src/observability/ — 측정 (cross-cutting)

피드백 메모리에 등록된 원칙 ("수치/성능에 대한 모든 것을 측정 가능하게")
의 구현체. 모든 그래프 노드는 이 모듈의 primitive 만 가지고도 자기 시간을
잴 수 있다.

## 파일

### `metrics.py`

#### 무엇을 구현했나
타이머 + 누적기 + 통계 dataclass + percentile 함수의 한 묶음.
JSON 직렬화 가능하므로 그대로 SQL 의 JSON 컬럼에 저장된다.

#### 세부 구현

**Stopwatch**
- `with Stopwatch() as sw: ...; sw.elapsed_ms` 패턴.
- 단일 측정용. `__exit__` 에서 `time.perf_counter()` 차이를 ms 로 저장.

**StageTimings (dict 서브클래스)**
- 그래프 노드별 ms 누적용. 같은 stage 가 여러 번 진입해도 합산되도록
  `dict.get(name, 0) + elapsed` 로 더한다.
- `with timings.time("stage_name") as _: ...` 헬퍼 컨텍스트.

**ScoreStats**
- `from_values(list[float])` — `count, top, mean, median, min, max, stdev`.
  `statistics.fmean / median / pstdev` 사용. 빈 입력은 모두 0.
- query 사이클의 similarity 분포 측정에 쓰인다.

**LengthStats**
- 문자열 리스트의 char 길이 분포. `count, total_chars, mean_chars, min_chars, max_chars`.
- ingest 의 chunk 분포, query 의 retrieved chunk 분포 양쪽에서 사용.

**IngestMetrics**
- 한 ingest 사이클의 모든 측정값:
  - 식별: `source_file, file_type, file_size_bytes, used_ocr`
  - 카운트: `pages_extracted, pages_after_clean, chunks_written`
  - 분포: `chunk_lengths` (LengthStats), `embedding_dimension`
  - 시간: `stage_ms` (StageTimings), `total_ms`
- `to_dict()` 가 JSON 직렬화 가능한 dict 반환.

**QueryMetrics**
- 한 query 사이클의 모든 측정값:
  - 입력: `query_chars, processed_chars, rewritten`
  - 검색 정책: `embedding_dimension, top_k, threshold`
  - 검색 결과: `chunks_retrieved, threshold_met, similarity` (ScoreStats),
    `retrieved_chunk_lengths` (LengthStats)
  - 라우팅: `retrieval_source` ("rag" | "web"), `web_results_raw, web_results_kept`
  - 답변: `answer_chars, prompt_chars, llm_provider, llm_model`
  - 시간: `stage_ms`, `total_ms`

**percentile(values, p)**
- numpy 의 linear-interpolation 동작과 동일. `p in [0, 100]`.
- analytics 의 p50/p95/p99 계산 backbone.

#### 사용자
- ingestion_graph 의 모든 노드가 `_stage(state, name, fn)` 헬퍼로 stage_ms 누적.
- query_graph 도 동일 패턴.
- log_store 가 `metrics.to_dict()` 결과를 JSON 컬럼에 저장.
- analytics 가 저장된 metrics JSON 으로부터 stage 별 / 전체 통계 계산.
