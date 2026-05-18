# seed_docs/

초기 지식 베이스에 들어갈 문서를 모아두는 자리.
관리자 페이지를 통한 업로드와는 별개로, 시스템 셋업 시 / 일괄 보강 시
운영자가 손으로 채우는 디렉토리다.

## 어떻게 쓰는가

1. 여기에 PDF / TXT / MD / DOCX 파일을 그대로 넣어둔다.
2. 한 번에 인덱싱:

   ```bash
   python main.py ingest seed_docs/
   ```

   `main.py ingest` 는 경로가 디렉토리면 안의 지원 파일을 모두 순회하며
   ingestion_graph 를 N 번 호출한다.

3. 처리되면 원본은 자동으로 `data/raw/` 에 복사되고, 벡터화된 결과는
   `data/chroma_db/` 에 누적된다.

## `data/` 와의 차이

| 디렉토리 | 누가 채우나 | 언제 |
|---|---|---|
| `seed_docs/` | 사람이 손으로 | 초기 셋업 / 일괄 추가 시 |
| `data/raw/` | `file_loader.load()` 가 자동으로 | 매 ingest 마다 |
| `data/chroma_db/` | `vector_store.add()` 가 자동으로 | 매 ingest 의 마지막 |

`seed_docs/` 는 "원천 입력", `data/raw/` 는 "파이프라인이 받아쓴 복사본"
이라고 생각하면 된다. 그래서 `seed_docs/` 의 파일을 지워도 이미 인덱싱된
벡터 DB 는 영향받지 않는다 (재인덱싱 시에만 의미).

## 새 문서 추가 워크플로우

```bash
# 1. 문서를 여기 떨군다
cp ~/Downloads/보안정책_v4.pdf seed_docs/

# 2. 인덱싱
python main.py ingest seed_docs/보안정책_v4.pdf

# 3. (선택) 통계 확인
python main.py stats
```

디렉토리 통째로 다시 돌려도 `file_loader.load()` 가 이미 `data/raw/` 에
있는 파일은 복사를 생략하므로 안전하지만, **중복 청크가 쌓일 수 있으니**
재인덱싱 전엔 `VectorStore.reset()` 또는 해당 source_file 의 chunk 를
지우는 정책을 따로 둬야 한다 (현재 미구현).
