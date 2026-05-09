# config/

전역 설정 패키지. 모든 모듈이 여기서 값을 읽으며, 환경변수가 있으면
환경변수가 default 보다 우선한다.

## 파일

### `settings.py`

#### 무엇을 구현했나
프로젝트 전체에서 공유되는 단일 설정 모듈. 코드 어디서도 매직넘버를 두지
않기 위해 chunk 크기, 임계값, 모델 이름, DB URL, API 키, OCR 설정까지
한곳에 모았다.

#### 세부 구현
- `PROJECT_ROOT / DATA_DIR / RAW_DIR / PROCESSED_DIR` — `pathlib.Path` 로
  계산된 절대 경로. 임포트 시점에 `mkdir(parents=True, exist_ok=True)` 로
  필요한 디렉토리를 생성하므로 다른 모듈에서 별도 부트스트랩이 필요 없다.
- **Chunk** — `CHUNK_SIZE=500`, `CHUNK_OVERLAP=50` (명세 1.7).
- **Embedding** — 기본값은 SBERT 다국어 미니 모델 (384-d). `openai:` 접두사로
  지정하면 `embedder.py` 가 OpenAI 백엔드로 라우팅한다.
- **Retrieval** — `SIMILARITY_THRESHOLD=0.7`, `TOP_K=5` (명세 2.4 / 3.3).
- **VectorDB** — Chroma persist 디렉토리, 컬렉션 이름.
- **LLM** — provider (`anthropic` | `openai`), 모델 ID, max_tokens.
- **Web Search** — provider (`tavily` | `serpapi`), top_k.
- **Logging** — SQLAlchemy DB URL (기본 SQLite, 운영 시 PostgreSQL 권장).
- **OCR** — `TESSERACT_CMD` 가 비어 있으면 PATH 의 tesseract 사용.
  `OCR_LANGUAGES` 기본값은 `eng+kor`.
- **API 키** — Anthropic / OpenAI / Tavily / SerpAPI. 비어 있으면 해당 노드는
  빈 결과 또는 stub 답변으로 graceful degradation.

#### 호출 관계
- `import` 만 가져가고 다른 모듈에 의존하지 않는다 (cycle-free).
- 거의 모든 src/* 모듈이 이 모듈을 읽는다.
