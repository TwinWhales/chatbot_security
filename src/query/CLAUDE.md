# src/query/ — Layer 2 (User Query Processing)

명세 2.1 ~ 2.3 — 사용자가 입력한 질문을 검색 가능한 형태로 만든다.
실제 호출 순서는 `src/graphs/query_graph.py` 의 `preprocess`, `embed_query`
두 노드가 결정한다.

## 모듈

### `query_preprocessor.py` — 2.1 / 2.2 (전처리 + Query Rewriting)

#### 무엇을 구현했나
질문 정규화 + (선택) LLM 기반 query rewriting. 결과는
`PreprocessedQuery(original, processed, rewritten)` dataclass.

#### 세부 구현
- `_normalize(text)` — 유니코드 NFKC 후 공백을 단일 스페이스로 축약.
- `_rewrite_with_llm(query)` — `ANTHROPIC_API_KEY` 가 있고 anthropic SDK 가
  설치되어 있으면 LLM 으로 검색 친화적 형태로 재구성. 그 외에는 `None` 을
  반환해 원본 사용.
- `preprocess(query, rewrite=False)` — rewrite 플래그가 True 일 때만 LLM
  을 시도한다. 빈 문자열 입력은 `ValueError`.
- 어떤 실패도 파이프라인을 중단시키지 않는다 — rewriting 은 best-effort.

### `query_embedder.py` — 2.3 (질문 임베딩)

#### 무엇을 구현했나
질문을 벡터로 변환. 매우 얇은 래퍼.

#### 세부 구현
- 한 줄짜리 함수: `embed_query(text) -> embedder.embed_text(text)`.
- **명세의 "문서 임베딩과 질문 임베딩은 반드시 같은 모델을 사용해야"
  요구를 코드 구조로 보장**한다 — `src.ingestion.embedder` 를 직접 호출하므로
  설정이 어긋날 여지가 없다.

## 의존성
- `query_preprocessor` 는 anthropic SDK 가 설치되지 않아도 import 만으로는
  실패하지 않는다 (try/except ImportError + key check).
- `query_embedder` 는 ingestion 의 embedder 캐시를 그대로 사용한다.
