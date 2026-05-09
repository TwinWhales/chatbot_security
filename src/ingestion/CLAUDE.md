# src/ingestion/ — Layer 1 (Data Ingestion)

명세 1.1 ~ 1.10 의 파이프라인 모듈. 각 모듈은 단일 책임을 갖고, 실제 실행
순서는 `src/graphs/ingestion_graph.py` 의 StateGraph 가 결정한다.

## 모듈

### `file_loader.py` — 1.1 / 1.2 (업로드 + 분류)
- `load(source)` — 입력 경로의 파일을 `data/raw/` 로 복사 (이미 거기 있으면
  복사하지 않음) 하고 `LoadedFile(path, file_type)` 반환.
- `classify(path)` — 확장자 기반: `pdf` / `docx` / `md` / `txt` / `unknown`.
- 파일이 존재하지 않으면 `FileNotFoundError`.

### `pdf_extractor.py` — 1.3 (PDF 텍스트 추출)
- `extract(path) -> list[PageText]` — pdfplumber 의 `pages` 를 순회하며
  page-별로 텍스트를 뽑아낸다. 페이지마다 try/except 로 감싸 일부 파손
  페이지가 전체 추출을 막지 않는다.
- `looks_empty(pages)` — 모든 페이지의 strip 한 길이 합이 20 미만이면 True.
  StateGraph 의 conditional edge 가 이 결과로 OCR 분기를 결정한다.
- `pdfplumber` 는 함수 내부 lazy import — TXT/MD/DOCX 만 처리할 때 import
  비용을 피하기 위함.

### `ocr_processor.py` — 1.4 (OCR 폴백)
- `extract(path, dpi=200)` — `pdf2image` 로 페이지를 래스터화 → `pytesseract` 로
  OCR. 결과 형식은 `pdf_extractor.PageText` 와 동일하므로 이후 노드는 OCR/
  비-OCR 을 구분할 필요가 없다.
- `_configure_tesseract` — `TESSERACT_CMD` 가 설정되어 있으면 그 경로를 사용.
- 모든 외부 의존성은 함수 내부 lazy import.

### `text_reader.py` — 1.5 (비-PDF 직접 읽기)
- `read(path, file_type)` — TXT/MD/DOCX 를 모두 단일 페이지(page_number=1)
  의 `PageText` 로 변환해 PDF 경로와 같은 자료형을 보장한다.
- DOCX 는 `python-docx` 로 paragraph + table cell 을 줄바꿈으로 join.

### `text_cleaner.py` — 1.6 (정제)
- `clean_pages(pages)` —
  1. 유니코드 NFKC 정규화
  2. 제어문자 (form-feed, BEL 등) 제거
  3. 페이지 수 ≥ 3 일 때 첫/끝 3줄 중 60% 이상 페이지에서 반복되는 라인을
     header/footer 로 간주해 제거
  4. 연속 공백/탭 단일 공백으로, 3줄 이상 연속된 빈 줄 → 2줄로 축약
- 페이지가 빈 결과로 정제되면 출력에서 제외.

### `chunker.py` — 1.7 (Chunk Split)
- LangChain 의 `RecursiveCharacterTextSplitter` 를 사용.
- separators 우선순위: `\n\n` → `\n` → `。` → `.` → `?` → `!` → ` ` → 빈문자.
  한국어 문서를 의식해 `。` 를 끼워 넣었다.
- 결과는 `Chunk(text, page_number, chunk_index)`. `chunk_index` 는 문서 전역
  순번이라 이후 metadata 에서 그대로 사용된다.

### `embedder.py` — 1.8 (Embedding)
- 두 백엔드: `_SentenceTransformerBackend` (로컬), `_OpenAIBackend` (API).
- `EMBEDDING_MODEL` 가 `openai:` 로 시작하면 OpenAI 로 라우팅, 아니면 SBERT.
- `@lru_cache(1)` 로 백엔드 인스턴스를 프로세스 단위 싱글턴화 — 모델 로딩
  비용은 한 번만 지불.
- `embed_texts(list[str])` 는 배치 호출, `embed_text(str)` 은 그 위에 build.
- **이 모듈은 ingestion 과 query 가 공유한다** — 명세 2.3 의 "동일한 임베딩
  모델" 요구를 코드 레벨에서 강제하는 핵심.

### `metadata_tagger.py` — 1.9 (메타데이터)
- `tag(chunks, source_path, file_type)` — 청크마다 다음 dict 를 만든다:
  - `source_file`, `source_path`, `page_number`, `chunk_index`
  - `created_at` (UTC ISO-8601), `file_type`, `content_preview` (앞 100자, 줄
    바꿈은 공백으로 치환).
- 출력은 list[dict] 이며 `vector_store.add` 에 그대로 넘긴다.

### `pipeline.py` (legacy 절차적 진입점)
- LangGraph 도입 전부터 있던 함수형 진입점. 같은 모듈들을 그래프 없이 순차
  호출하며 `IngestMetrics` 를 채운다.
- 호환성과 디버깅 용도로 남겨두었다. 일반적인 호출 경로는
  `src/graphs/ingestion_graph.run()` 사용 권장.

## 의존 흐름

```
file_loader → pdf_extractor → (ocr_processor) ↘
                                                clean → chunk → embed → tag → store
              text_reader ────────────────────↗
```

모든 모듈은 `config/settings.py` 만 가로지르고, ingestion 내부 모듈끼리는
PageText / Chunk dataclass 만으로 통신한다 (느슨한 결합).
