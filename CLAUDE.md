# RAG 시스템 — 전체 개요

관리자가 업로드한 문서를 벡터 DB 에 저장하고, 사용자 질문에 대해 의미론적
검색 + LLM 답변을 생성하는 **5-Layer RAG 파이프라인**이다.
유사도가 임계치 미만이면 자동으로 웹 검색 폴백으로 분기하며, 모든 사이클은
로그 DB 에 기록된다.

전체 실행 흐름은 두 개의 **LangGraph StateGraph** 로 구현되어 있어 노드/엣지/
조건부 분기가 코드에 그대로 드러난다.

---

## 시스템 구성 (5-Layer ↔ LangGraph 매핑)

| 명세 Layer | 역할 | 디렉토리 | 그래프 노드 |
|---|---|---|---|
| L1 — Data Ingestion | 업로드 → 추출 → 정제 → 청킹 → 임베딩 → 저장 | `src/ingestion/` | `src/graphs/ingestion_graph.py` 의 노드들 |
| L2 — User Query Processing | 전처리 → 임베딩 | `src/query/` | `preprocess`, `embed_query` |
| L3 — Central Knowledge Engine | 벡터 DB / KB / Top-K + Threshold | `src/knowledge/` | `retrieve` |
| L4 — AI Response Intelligence | RAG / Web Fallback / 답변 조합 | `src/response/` | `rag_generate` / `web_search` → `web_filter` → `web_generate` / `build_response` |
| L5 — Logging & Future Learning | 모든 사이클 영속화, 분석 | `src/logging/` | `log` |
| (cross-cutting) | 측정 (시간/카운트/스코어) | `src/observability/` | 모든 노드에서 stage_ms 누적 |

---

## 두 개의 그래프

### 1. Ingestion Graph — `src/graphs/ingestion_graph.py`

```
START → load_file → classify
                       │
        (PDF?)─┬──→ pdf_extract ─(추출 성공?)─→ clean ─→ chunk ─→ embed ─→ tag ─→ store ─→ END
               │                       └─→ ocr ─┘
               └──→ text_read ────────────────→ clean
```

- 분기 1 (`classify`): 파일 타입에 따라 PDF 경로 / 비-PDF 경로
- 분기 2 (`pdf_extract` 후): pdfplumber 결과가 사실상 비어 있으면 OCR 폴백

### 2. Query Graph — `src/graphs/query_graph.py`

```
START → preprocess → embed_query → retrieve
                                      │
                  (threshold 충족?)─┬─→ rag_generate ──┐
                                    │                  ├─→ build_response → log → END
                                    └─→ web_search → web_filter → web_generate ─┘
```

- 분기 (`retrieve` 후): top_score ≥ SIMILARITY_THRESHOLD 이면 RAG, 아니면 웹

각 노드는 `IngestState` / `QueryState` (TypedDict) 를 부분 갱신하는 순수 함수다.
무거운 의존성(pdfplumber, pytesseract, anthropic, tavily)은 노드 내부에서 lazy import.

---

## 디렉토리 인덱스

| 경로 | 책임 | CLAUDE.md |
|---|---|---|
| `config/` | 전역 설정 (env-override 가능) | [`config/CLAUDE.md`](config/CLAUDE.md) |
| `src/ingestion/` | Layer 1 모듈들 (file_loader, pdf_extractor, ocr_processor, text_reader, text_cleaner, chunker, embedder, metadata_tagger) | [`src/ingestion/CLAUDE.md`](src/ingestion/CLAUDE.md) |
| `src/query/` | Layer 2 모듈들 (전처리, 임베딩) | [`src/query/CLAUDE.md`](src/query/CLAUDE.md) |
| `src/knowledge/` | Layer 3 모듈들 (vector_store, knowledge_base, retriever) | [`src/knowledge/CLAUDE.md`](src/knowledge/CLAUDE.md) |
| `src/response/` | Layer 4 모듈들 (rag_generator, web_search_agent, web_filter, response_builder) | [`src/response/CLAUDE.md`](src/response/CLAUDE.md) |
| `src/logging/` | Layer 5 모듈들 (log_store, analytics) | [`src/logging/CLAUDE.md`](src/logging/CLAUDE.md) |
| `src/observability/` | Stopwatch, Metrics dataclass, percentile | [`src/observability/CLAUDE.md`](src/observability/CLAUDE.md) |
| `src/graphs/` | LangGraph StateGraph 두 개 | [`src/graphs/CLAUDE.md`](src/graphs/CLAUDE.md) |
| `seed_docs/` | 초기 지식 베이스용 원본 문서 모음 (사람이 손으로 채움) | [`seed_docs/CLAUDE.md`](seed_docs/CLAUDE.md) |
| `seed_docs/tryhackme/` | TryHackMe Learn 크롤러 산출물 트리 (크롤러가 덮어씀) | [`seed_docs/tryhackme/CLAUDE.md`](seed_docs/tryhackme/CLAUDE.md) |
| `scripts/` | 런타임이 아닌 보조 도구 (크롤러 등) | [`scripts/CLAUDE.md`](scripts/CLAUDE.md) |
| `data/raw/` | `file_loader.load()` 가 자동 복사하는 원본 사본 | (settings.RAW_DIR) |
| `data/chroma_db/` | ChromaDB persist 디렉토리 (벡터 + 메타) | (settings.CHROMA_PERSIST_DIR) |
| 루트 | `main.py`, `smoke_test.py`, `requirements.txt`, `README.md` | (이 파일) |

---

## 실행 방법

```bash
pip install -r requirements.txt           # langgraph 포함
python main.py ingest path/to/doc.pdf     # 파일 1개 인덱싱
python main.py ingest seed_docs/          # 디렉토리 통째 인덱싱 (초기 시드)
python main.py ask "질문"                  # query_graph.invoke()
python main.py stats                      # 간단 요약
python main.py metrics                    # 전체 성능 / 품질 리포트
```

API 키 (ANTHROPIC_API_KEY, TAVILY_API_KEY) 가 없을 때도 그래프 자체는 동작하며,
LLM 노드는 stub 답변을, 웹 검색 노드는 빈 결과를 반환한다 — 오프라인 개발과
스모크 테스트에 활용된다.

### 데이터 흐름 (어느 디렉토리에 무엇이 쌓이나)

```
seed_docs/  ─(사람)─→  ingest 명령  ─→  data/raw/  ─→  파이프라인  ─→  data/chroma_db/
(원천 입력)            (file_loader가 복사)  (원본 사본)                  (벡터 + 메타)
```

- `seed_docs/` — 초기 지식 베이스 시드. 사람이 직접 PDF/MD/DOCX 를 넣어두는 자리.
  자세한 컨벤션은 [`seed_docs/CLAUDE.md`](seed_docs/CLAUDE.md) 참고.
- `data/raw/` — `file_loader.load()` 가 ingest 시점에 자동으로 복사한 원본 사본.
  재인덱싱 / citation 원문 추적에 사용된다.
- `data/chroma_db/` — ChromaDB persist 디렉토리. 청크 [텍스트 + 임베딩 + metadata]
  가 cosine 거리 인덱스로 저장된다.

관리자 페이지를 통한 단건 업로드는 ingest 명령 한 번에 대응되고,
시스템 초기화 / 일괄 보강은 `seed_docs/` 를 통째로 ingest 하는 식으로 한다.

---

## 측정 (Observability)

피드백 메모리에 기록한 원칙: **수치/성능을 처음부터 끝까지 측정 가능하게 한다.**

각 그래프 노드는 시작/종료 시각을 측정해 `metrics.stage_ms` 에 누적한다.
한 사이클이 끝나면 `metrics.total_ms` 와 함께 다음이 모두 채워진다:

- 시간: 노드별 ms, 전체 ms
- 카운트: 파일 바이트, 페이지 수, 청크 수, 임베딩 차원, 답변/프롬프트 char
- 품질: similarity {top, mean, median, min, max, stdev}, threshold_met, route
- 폴백: web_results {raw, kept}

이 모든 값은 `QueryLog.metrics` JSON 컬럼에 영속화되고, `analytics.full_report()`
가 latency p50/p95/p99 와 stage 별 평균까지 계산해 CLI `metrics` 명령으로 노출된다.

---

## 스모크 테스트

```bash
python smoke_test.py
```

LangGraph 가 설치되어 있으면 실행 가능. 다음을 검증한다:

1. `ingestion_graph.run()` 의 모든 노드 (`file_load → text_read → clean → chunk → embed → tag → store_write`) 가 metric 에 등장
2. `query_graph.run()` 의 RAG 경로 노드 (`preprocess → query_embed → retrieve → llm_generate`)
3. 임계치를 인위적으로 올렸을 때 web 경로 노드 (`web_search → web_filter → llm_generate`) 로 분기
4. 로그 DB 가 metrics JSON 까지 round-trip
5. analytics 가 stage 별 latency 와 route 비율을 집계

오프라인용 stub 임베더 (32-d 해시 기반) 로 무거운 ML 의존성 없이 동작한다.
