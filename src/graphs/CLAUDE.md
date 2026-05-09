# src/graphs/ — LangGraph StateGraph 구현체

명세의 5-Layer 흐름을 LangGraph StateGraph 두 개로 표현한 모듈.
Ingestion 흐름과 Query 흐름이 각각 별개의 그래프이며, 한 그래프 안의
조건부 분기 (PDF 여부 / OCR 필요 / 임계치 충족) 는 모두 `add_conditional_edges`
로 명시되어 있다.

> 일반적인 호출 경로는 이 두 그래프이며, `src/ingestion/pipeline.py` 와
> `src/response/response_builder.py` 의 절차적 진입점은 자료형 정의 + 호환
> 용도로 남겨둔 legacy 다.

## 파일

### `ingestion_graph.py` — Layer 1 그래프

#### 그래프 구조
```
START → load_file → classify
                       ├──(PDF)──→ pdf_extract ──(추출 성공)──→ clean
                       │                       └──(빈 결과)──→ ocr → clean
                       └──(비-PDF)──→ text_read ─────────────→ clean
clean → chunk → embed → tag → store → END
```

#### State (TypedDict, total=False)
- `source` (입력), `store` (의존성 주입)
- 노드별 산출물: `loaded, file_type, pages, cleaned, chunks, texts,
  embeddings, metadatas, chunk_ids, used_ocr`
- 측정: `metrics: IngestMetrics`, `started_at`

#### 노드
| 노드 | 명세 단계 | 책임 |
|---|---|---|
| `load_file` | 1.1 | 원본을 `data/raw/` 로 복사하고 file_type 결정 |
| `classify` | 1.2 | 분기점 (실제 결정은 conditional edge 가 함) |
| `pdf_extract` | 1.3 | pdfplumber 추출 |
| `ocr` | 1.4 | pdfplumber 결과가 비어 있을 때만 진입 |
| `text_read` | 1.5 | TXT/MD/DOCX 직접 읽기 |
| `clean` | 1.6 | 정제 |
| `chunk` | 1.7 | RecursiveCharacterTextSplitter |
| `embed` | 1.8 | 공유 embedder 사용 |
| `tag` | 1.9 | 메타데이터 부착 |
| `store` | 1.10 | VectorStore.add |

#### 조건부 분기
- `_route_by_type(state)` → `"pdf_extract"` / `"text_read"`
- `_route_by_extract_success(state)` → `"clean"` / `"ocr"`

#### 측정
모든 노드는 `_stage(state, name, fn)` 헬퍼로 자기 작업 시간을 `metrics.stage_ms`
에 누적. 그래프 invoke 가 끝나면 `run()` 이 `total_ms` 를 채운다.

#### 진입점
`run(source, store=None) -> IngestState` — 모듈 싱글턴 그래프를 invoke.

---

### `query_graph.py` — Layer 2 ~ 5 그래프

#### 그래프 구조
```
START → preprocess → embed_query → retrieve
                                      ├──(threshold met)──→ rag_generate ──┐
                                      └──(미달)──→ web_search → web_filter → web_generate ──┐
                                                                                              ↓
                                                                  build_response → log → END
```

#### State (TypedDict, total=False)
- 입력: `user_query, rewrite, retriever, log_store`
- 산출물: `pre, embedding, retrieval, chunks_for_prompt, web_raw, web_filtered,
  answer_text, answer_provider, answer_model, response, log_id`
- 측정: `metrics: QueryMetrics`, `started_at`

#### 노드
| 노드 | 명세 단계 | 책임 |
|---|---|---|
| `preprocess` | 2.1 / 2.2 | 정규화 + (선택) Query Rewriting |
| `embed_query` | 2.3 | 동일 임베딩 모델로 벡터화 |
| `retrieve` | 3.3 | Top-K + threshold 판정 |
| `rag_generate` | 4.1 | 검색된 chunk 로 LLM 답변 |
| `web_search` | 4.2-1 | Tavily / SerpAPI 호출 |
| `web_filter` | 4.2-2 | 스팸/중복/짧은 스니펫 제거 |
| `web_generate` | 4.2-3 | 웹 컨텍스트로 LLM 답변 |
| `build_response` | 4.3 | citations + FinalResponse 패키징 |
| `log` | 5.1 | 한 사이클 영속화 |

#### 조건부 분기
- `_route_by_threshold(state)` —
  `retrieval.threshold_met and retrieval.chunks` 면 `"rag_generate"`,
  그렇지 않으면 `"web_search"`.

#### 측정
- 노드 진입/종료마다 `_stage` 헬퍼가 `metrics.stage_ms` 에 누적.
- `build_response` 노드가 `metrics.total_ms` 를 채운다 (노드별 누적 + 전체 +
  similarity 분포 + retrieval_source + answer/prompt char 까지).
- 다음 노드인 `log` 가 metrics 를 그대로 SQLite/PostgreSQL JSON 컬럼에 저장.

#### 진입점
`run(user_query, *, rewrite=False, store=None, retriever=None, log_store=None)
-> QueryState` — 의존성을 주입받지 않으면 default 인스턴스를 만들어 사용.

---

## 그래프를 두 개로 나눈 이유

명세의 데이터 흐름이 둘 이다:
1. 관리자 → ingestion 한 번 (배치)
2. 사용자 → query 매 요청마다

두 흐름의 입력 / state / 라이프사이클이 서로 다르므로, 단일 거대 그래프
보다 책임이 분리된 두 그래프가 디버깅 / 재사용에 유리하다. 두 그래프는
`config/settings.py`, `src/ingestion/embedder.py` (공유 임베딩 모델),
`src/knowledge/vector_store.py` (공유 컬렉션) 으로만 연결된다.
