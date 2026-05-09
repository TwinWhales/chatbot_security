# src/knowledge/ — Layer 3 (Central Knowledge Engine)

명세 3.1 ~ 3.3. 벡터 저장 / 메타데이터 필터 / Top-K + 임계치 분기를 담당.
설계 원칙은 **"저장은 storage 가, 정책은 retrieval 이"** — 임계치 판정 같은
정책 결정은 vector_store 가 아니라 retriever 에 있다.

## 모듈

### `vector_store.py` — 3.1 (VectorDB Repository)

#### 무엇을 구현했나
ChromaDB 단일 컬렉션 위의 얇은 CRUD 래퍼. cosine 거리를 명시적으로 지정해
명세의 "Cosine Similarity" 요구사항과 일치.

#### 세부 구현
- `RetrievedChunk(chunk_id, content, metadata, similarity_score)` —
  외부에 노출되는 결과 자료형.
- `VectorStore.__init__` — `chromadb.PersistentClient` + `get_or_create_collection`,
  `metadata={"hnsw:space": "cosine"}` 로 거리 척도 고정.
- `add(contents, embeddings, metadatas, ids=None)` — 셋 길이 일치 검증, ids
  없으면 UUID 생성, metadata 는 `_sanitize_metadata` 로 ChromaDB 가 받지 않는
  타입 (None, list, dict) 을 정리.
- `query(embedding, top_k, where=None)` — Chroma 의 parallel-list 응답을
  풀어 `RetrievedChunk` 목록으로 변환. 거리 → 유사도 변환은
  `_distance_to_similarity` 가 `1 - distance` 후 [0, 1] 로 clamp.
- `delete(ids)` / `reset()` / `count()` — 운영 / 테스트용 보조 API.

### `knowledge_base.py` — 3.2 (Knowledge Base)

#### 무엇을 구현했나
vector_store 위에 메타데이터 필터링 계층을 추가. 호출자가 raw Chroma
`where` 절을 직접 다루지 않게 한다.

#### 세부 구현
- `Filter(file_types, source_files, created_after)` dataclass.
- `Filter.to_where()` — 비어 있으면 `None`, 한 절이면 그대로, 여러 절이면
  `{"$and": [...]}` 로 묶음.
- `KnowledgeBase.search(embedding, top_k, filt)` — vector_store 호출 + 필터
  변환을 한 번에. `size()` 는 컬렉션 크기.

### `retriever.py` — 3.3 (Top-K + Threshold)

#### 무엇을 구현했나
검색 결과의 **정책 판정**: 가장 높은 similarity 가 임계치 이상인지, 즉
"이 문서들로 답할 수 있는가?" 의 결정.

#### 세부 구현
- `RetrievalResult(chunks, threshold_met, top_score)` dataclass.
- `Retriever(kb, top_k, threshold)` — settings 의 default 를 사용하지만
  생성 시 override 가능 (테스트에서 임계치를 인위적으로 -1.0 / 2.0 로
  세팅해 분기를 검증함).
- `retrieve(query_embedding, filt=None)` — kb 검색 → top_score 계산 →
  `threshold_met = top_score >= self.threshold`. 빈 결과는
  `threshold_met=False, top_score=0.0` 로 반환.

## 의존 흐름
```
vector_store ←─ knowledge_base ←─ retriever
```
RetrievalResult 는 `src/graphs/query_graph.py` 의 `_route_by_threshold` 가
읽어 RAG / Web 분기를 결정한다.
