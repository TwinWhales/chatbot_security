# src/response/ — Layer 4 (AI Response Intelligence)

명세 4.1 ~ 4.3. RAG 경로 (Path A) 와 웹 검색 폴백 (Path B) 두 갈래의 답변 생성을
담당. 어느 경로를 탈지는 query_graph 의 conditional edge 가 결정하므로,
이 디렉토리의 모듈들은 자기 책임만 알고 있으면 된다.

## 모듈

### `rag_generator.py` — 4.1 (RAG Context Injection)

#### 무엇을 구현했나
검색된 chunk 를 LLM 프롬프트로 묶어 답변을 생성한다. provider 추상화로
Anthropic / OpenAI / offline-stub 셋 중 하나가 호출된다.

#### 세부 구현
- `GeneratedAnswer(text, model, provider)` — 외부에 노출되는 결과.
- `_format_context(chunks)` — 청크마다 `[Context i] (source: ..., p.X)\n{본문}`
  형식의 블록을 만들고 빈 줄로 구분.
- `build_prompt(query, chunks)` — 명세 4.1 의 한국어 템플릿 그대로 사용
  ("다음은 관련 문서에서 검색된 내용입니다 ... 답변에 사용한 출처를 반드시 표기").
- `_call_anthropic` / `_call_openai` — 각 provider SDK 의 message API 호출.
- `_call_stub(prompt, chunks)` — 키가 없을 때의 폴백. `[stub answer ...]` 와
  첫 청크 미리보기를 반환해 파이프라인 통합 테스트가 가능하게 한다.
- `generate(query, chunks)` — provider 에 따라 위 셋 중 하나를 호출. 키가
  없으면 자동으로 stub 으로 떨어진다.

### `web_search_agent.py` — 4.2-1 (Web Search Agent)

#### 무엇을 구현했나
임계치 미달 시 호출되는 웹 검색. Tavily / SerpAPI 두 backend.

#### 세부 구현
- `WebResult(title, url, snippet, score)` dataclass.
- `_search_tavily` — `tavily-python` SDK 의 `search(max_results, search_depth='basic')`.
  결과의 `title / url / content / score` 를 매핑.
- `_search_serpapi` — `requests` 로 `serpapi.com/search` 호출, `organic_results`
  파싱.
- 키가 없거나 SDK 가 없으면 빈 리스트 반환 — query_graph 가 이를
  `web_results_raw=0` 로 받아 stub 답변 경로로 자연스럽게 흘러간다.

### `web_filter.py` — 4.2-2 (웹 결과 필터링)

#### 무엇을 구현했나
스팸/광고/짧은 스니펫/중복 URL 제거.

#### 세부 구현
- `_BLOCKED_DOMAINS` — `pinterest.com`, `quora.com` 같은 노이즈 도메인.
- `filter_results(results, min_snippet_chars=40)` —
  1. URL/snippet 비어 있으면 제외
  2. snippet 길이 < 40 이면 제외 (광고 / placeholder 거름)
  3. 차단 도메인 (서브도메인 포함) 이면 제외
  4. 동일 URL 중복 제거 (set 으로 traceck)

### `response_builder.py` — 4.3 (최종 응답 조합) [legacy]

#### 무엇을 구현했나
LangGraph 도입 전의 절차적 응답 빌더. RAG vs Web 분기, citation 생성,
metrics 채움을 한 함수에서 한다. 현재는 **자료형 정의 모듈** 로서의 역할이
주력 — `Citation`, `FinalResponse` dataclass 가 query_graph 에서 그대로
재사용된다.

#### 세부 구현
- `Citation(kind, label, locator)` — `kind="doc"` 또는 `"web"`.
- `FinalResponse` — `answer`, `retrieval_source`, `citations`, `chunks`,
  `web_results`, `similarity_scores`, `response_time_ms`, `model`, `provider`,
  `metrics` 까지 통합.
- `_doc_citations` — (source_file, page_number) 튜플로 중복 제거된 citation.
- `_web_citations` — 필터된 WebResult 마다 한 줄.
- `_format_web_context` — WebResult 를 RetrievedChunk 모양으로 변환해
  rag_generator.build_prompt 가 그대로 재사용 가능하게 한다.
- `build(user_query, retrieval, metrics=None)` — 절차적 진입점. LangGraph
  버전 (`src/graphs/query_graph.py`) 이 같은 자료형을 사용하므로 호환된다.
