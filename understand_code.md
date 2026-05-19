# 코드 읽는 순서 — forensicagent 이해 가이드

이 프로젝트는 *길지* 않지만 *깊다*. 24 개 파이썬 파일이 5 개 레이어로 쪼개져
있고, 각 레이어의 contract 가 dataclass 한 묶음으로 굳어 있다. 처음 보는
사람은 어디부터 들어가야 하는지 막막할 수 있어 권장 동선을 적어둔다.

> **TL;DR**: `README.md` → `CLAUDE.md` → `forensicagent/cli/main.py` →
> 5 개 모듈을 데이터 흐름 순서로 → 마지막으로 보조 스크립트.

---

## 0. 먼저 한눈에

```
[sample.txt URL 1085]
       ↓ (오프라인 단계, 사람이 가끔 실행)
   scripts/run_all.py
       ↓
   ┌──────────────────────┬─────────────────────────┐
   │  scripts/             │  forensicagent/          │  ← 진짜 제품
   │   ingest_sample.py    │   cli/                   │
   │   yaml_seeder.py      │   scanner/               │
   │   extract_indicators  │   selector/              │
   │   build_goldenset     │   executor/              │
   └──────────────────────│   analyzer/              │
                          │   reporter/              │
                          │   rag/   llm/   tools/   │
                          │   observability/         │
                          └──────────────────────────┘
                                    ↓
                          $ forensicagent  (CWD 분석)
```

`forensicagent/` 가 **제품 본체** 이고, `scripts/` 는 **시드 데이터 + 도구 메타데이터를 만들어 주는 보조 라인** 이다. 두 라인은 서로 독립적으로 돌릴 수 있다.

---

## 1단계: 의도 파악 (15 분)

이 두 문서만 읽어도 "왜 이렇게 짰는지" 90% 이해된다.

| 순서 | 파일 | 왜 읽나 |
|---|---|---|
| 1 | [`README.md`](README.md) | 시나리오, 비목적, 5단계 흐름 다이어그램, 설계 결정 근거 |
| 2 | [`CLAUDE.md`](CLAUDE.md) | 6 모듈 명세 + 현재 진행 상태 + 다음 세션 재개 노트 |
| 3 | `git log --oneline cf867c7..HEAD` | 커밋 메시지가 "왜 이 작업을 했는지" 의 진실 원천 |

여기서 멈춰서 "아 이 시스템은 *triage* 다 (전체 사고 재구성이 아니다)" 가 머리에 박혀야 다음 단계가 편하다.

---

## 2단계: 진입점부터 따라가기 (30 분)

명령 한 번이 어떤 함수들을 거치는지를 따라가는 흐름.

### 2.1 CLI 가 무엇을 호출하나

| 순서 | 파일 | 보는 것 |
|---|---|---|
| 4 | `forensicagent/cli/main.py` | `root()` 함수 — Scanner → Selector → 사용자 승인 → Executor → Analyzer → Reporter 의 직선 흐름이 이 한 함수에 다 있다. 약 200 줄. |
| 5 | `forensicagent/cli/ui.py` | `render_inventory` (Rich Table) — UI 의 작은 디테일 |
| 6 | `forensicagent/cli/doctor.py` | 환경 점검. Python / chromadb / 임베딩 백엔드 / libmagic / Ollama 다섯 가지 핵심 의존성을 *진짜 호출해서* 검증. 다른 모듈과 어떻게 결합하는지 가장 간단한 사례. |

> 팁: 4 번을 읽을 때 import 한 줄씩 따라 들어가 보면 자연스럽게 모든 모듈을 한 번씩 만난다.

### 2.2 측정 인프라 (작지만 어디나 나타남)

| 순서 | 파일 | 보는 것 |
|---|---|---|
| 7 | `forensicagent/observability/metrics.py` | `Stopwatch`, `StageTimings`, `ScoreStats`. 60 줄짜리 primitive. 모든 단계가 이걸로 시간 잰다. |

`stage_ms` 라는 dict 가 어디서 채워지고 어디서 소비되는지가 명확해지면 후속 모듈 읽기 편하다.

---

## 3단계: 데이터 흐름 따라가기 (1.5 ~ 2 시간)

명령 한 번 = 5 stage. 각 stage 는 출력 dataclass 가 다음 stage 의 입력이다. **types.py 를 먼저 보고 본체를 보는 게 정석.**

### 3.1 Scanner — 무엇이 있는가?

| 순서 | 파일 | 보는 것 |
|---|---|---|
| 8  | `forensicagent/scanner/types.py` | `Evidence`, `Inventory` dataclass (출력 스키마) |
| 9  | `forensicagent/scanner/detectors.py` | 9 magic + 22 ext + 6 정규식 + 6 디렉토리. 우선순위로 한 번에 하나만 매치 |
| 10 | `forensicagent/scanner/scanner.py` | 깊이 제한 BFS, 심볼릭 미추적, 헤더 32 바이트만 |

> 읽으면 알게 되는 것: "큰 메모리 덤프 파일도 통째로 안 읽는다" 의 디테일 (`detect_by_magic` 이 헤더 32 바이트만 읽음).

### 3.2 Tools / RAG — 도구를 어떻게 표현하나?

forensicagent 의 *진짜 RAG* 는 도구 메타데이터 lookup 이다. 의미 검색이 주가 아니다.

| 순서 | 파일 | 보는 것 |
|---|---|---|
| 11 | `forensicagent/tools/schema.py` | `ToolMetadata` Pydantic 클래스. **YAML 한 파일이 Selector/Executor/Analyzer/LLM 프롬프트를 다 구동한다** 는 사실을 여기서 확실히 본다. |
| 12 | `forensicagent/tools/loader.py` | `load_all_tools` — 디렉토리 일괄 로드 |
| 13 | `tools_metadata/chainsaw.yaml` | 실제 YAML 한 개를 보면 추상이 구체가 된다 |
| 14 | `forensicagent/rag/vector_store.py` | ChromaDB cosine 컬렉션 wrapper. Selector/Analyzer 의 lookup 백엔드 |
| 15 | `forensicagent/rag/embedder.py` | SentenceTransformer / OpenAI 라우팅 |
| 16 | `forensicagent/rag/indexer.py` | 크롤된 도메인 문서를 청크 → 임베딩 → 컬렉션 저장 (Stage 3) |

### 3.3 LLM — Ollama 호출 패턴

| 순서 | 파일 | 보는 것 |
|---|---|---|
| 17 | `forensicagent/llm/ollama_client.py` | `json_chat()` 의 1 회 재시도 + `JsonRetryFailed` 예외. Selector/Analyzer 의 LLM 호출이 전부 이걸 통과한다. |

### 3.4 Selector — 무엇을 돌릴까?

| 순서 | 파일 | 보는 것 |
|---|---|---|
| 18 | `forensicagent/selector/types.py` | `Plan`, `ToolSelection` |
| 19 | `forensicagent/selector/filter.py` | **Stage 1** : evidence_type 결정론 매칭 |
| 20 | `forensicagent/selector/llm_rank.py` | **Stage 2** : LLM 우선순위. JSON 깨지면 Stage 1 결과 그대로 fallback |
| 21 | `forensicagent/selector/selector.py` | 오케스트레이션 + `--quick / --tools` 처리 |

> 읽으면 알게 되는 것: "LLM 이 도구를 *선택* 하지 않고 *순위* 만 매긴다" 의 의도. hallucinate 한 도구가 실행되지 않게 하는 가드.

### 3.5 Executor — 어떻게 돌리나?

| 순서 | 파일 | 보는 것 |
|---|---|---|
| 22 | `forensicagent/executor/types.py` | `ExecutionResult`, `ExecutionBundle`. stdout 은 inline 이 아니라 **파일 경로** 로만. |
| 23 | `forensicagent/executor/adapter.py` | `GenericAdapter` — YAML 만으로 동작. `validate_prerequisites` 가 `install_check` 를 실제로 실행해서 검증. |
| 24 | `forensicagent/executor/runner.py` | `subprocess.Popen` + timeout + stdout/stderr 를 파일로. timeout/FileNotFound/OSError 모두 `ExecutionResult` 의 status 로 흡수 |
| 25 | `forensicagent/executor/executor.py` | parallelizable 별 ThreadPool / serial 라우팅 + Rich Progress. 한 도구 실패해도 다른 도구는 계속. |

### 3.6 Analyzer — 의심항목 추출

| 순서 | 파일 | 보는 것 |
|---|---|---|
| 26 | `forensicagent/analyzer/types.py` | `Finding`, `Severity`, `SEVERITY_RANK` |
| 27 | `forensicagent/analyzer/rules.py` | 룰 매처. **id 기반 specific matcher 가 우선**, 미등록 indicator 는 키워드 AND fallback. |
| 28 | `forensicagent/analyzer/llm_extract.py` | `format=json` + severity 가이드라인 + known_false_positives 시스템 프롬프트. "확실하지 않으면 low" 룰. |
| 29 | `forensicagent/analyzer/analyzer.py` | Case A / B / C 분기. dedup + severity 내림차순. |

> 읽으면 알게 되는 것: "큰 출력을 LLM 에 통째로 던지지 않는다" 의 안전망 (Case B/C).

### 3.7 Reporter — 한 묶음으로

| 순서 | 파일 | 보는 것 |
|---|---|---|
| 30 | `forensicagent/reporter/types.py` | `Report`, `Summary`. JSON 직렬화 가능. |
| 31 | `forensicagent/reporter/builder.py` | tool_id 별로 bundle 만들어 모음 + summary 집계 |
| 32 | `forensicagent/reporter/terminal.py` | Rich Panel + severity 색 |
| 33 | `forensicagent/reporter/json_out.py` + `md_out.py` | 파일 직렬화 |
| 34 | `forensicagent/reporter/reporter.py` | `write()` — 한 번 호출에 terminal + JSON + MD 다 출력 |

---

## 4단계: 보조 라인 — sample.txt 처리 (1 시간)

여기는 **forensicagent 본체와 무관한 ETL** 이다. forensicagent 가 사용할
도구 메타데이터 / RAG 코퍼스 / 골든 셋을 만드는 라인.

| 순서 | 파일 | 보는 것 |
|---|---|---|
| 35 | `scripts/run_all.py` | 마스터 오케스트레이터. 5 stage 의 동시성 다이어그램이 여기 있다 (RAG 가 background thread, LLM 들이 직렬 큐). |
| 36 | `scripts/ingest_sample.py` | **Stage 1**. 도메인 분류 → ThreadPool × 4 → 캐시 + manifest. URL_REWRITES 트릭 (book.hacktricks.xyz → wiki) 도 여기. |
| 37 | `forensicagent/rag/indexer.py` (재방문) | **Stage 3**. 청킹 + 임베딩 + 컬렉션 별 저장 |
| 38 | `scripts/yaml_seeder.py` | **Stage 2**. EZTools 매뉴얼 → Pydantic-검증된 YAML 초안 + 실패 raw 보존 |
| 39 | `scripts/extract_indicators.py` | **Stage 4a**. CyberDefenders 블로그 → indicator 후보 YAML |
| 40 | `scripts/build_goldenset.py` | **Stage 4b**. DFIR Report → Phase 6 평가 정답 후보 |

> 읽으면 알게 되는 것: "LLM 학습 (fine-tuning) 이 아니라 LLM 으로 정보를 *추출* 한다" 는 본 설계 의도. 모델은 안 건드리고 데이터만 키운다.

---

## 5단계: 깊게 — 자주 다시 보게 되는 곳

이 파일들은 한 번 읽어도 다음에 또 보게 된다. 책갈피 둘 가치 있음.

- `forensicagent/config.py` — env var 이름 정리. `FORENSICAGENT_LLM_MODEL` 같은 게 전부 여기 정의.
- `forensicagent/tools/schema.py` — 새 도구 YAML 작성 시 항상 참조.
- `forensicagent/analyzer/rules.py` 의 `_SPECIFIC_MATCHERS` dict — 새 indicator id 등록 위치.
- `forensicagent/executor/adapter.py` 의 `register_adapter()` — 새 specialized adapter 추가 hook.

---

## 6단계: 안 읽어도 되는 것 (첫 패스에서)

처음 훑을 때는 건너뛰어도 좋은 것들:

- `scripts/crawlers/*` — 구버전 도메인 페이지 크롤러. 현재는 `scripts/ingest_sample.py` 가 sample.txt 기반으로 동작하므로 이쪽은 보조.
- `forensicagent/__main__.py` — 두 줄짜리 module 진입점.
- `seed_docs/*` 의 실제 데이터 — 결과물이지 코드 아님.

---

## 동작 시키며 이해하기 (옵션)

코드를 읽기만 하지 말고 한 번 돌려 보면 머리에 더 잘 박힌다.

```bash
# 1. 의존성
pip install -r requirements.txt
pip install -e .

# 2. 환경 점검
forensicagent doctor

# 3. 빈 디렉토리에 fake evidence 만들어서 dry-run
mkdir /tmp/case
python -c "open('/tmp/case/Security.evtx','wb').write(b'ElfFile\x00' + b'\x00'*100)"
forensicagent --path /tmp/case --no-llm --dry-run

# 4. sample.txt 일부만 처리해보기 (실제 다운로드 / 임베딩 실행)
python scripts/run_all.py sample.txt --limit 3 --skip-llm
ls seed_docs/
```

---

## 시간 예상

| 단계 | 분량 | 비고 |
|---|---|---|
| 1단계 의도 파악 | 15 분 | README + CLAUDE 만 |
| 2단계 진입점 | 30 분 | main.py 따라가며 import 1차 훑기 |
| 3단계 데이터 흐름 | 1.5 ~ 2 시간 | types 먼저, 그 다음 본체 |
| 4단계 보조 라인 | 1 시간 | 필요할 때만 |
| 5단계 책갈피 | 수시 | 새 기능 추가하기 전마다 |

총 첫 패스 약 3 시간이면 *어디서 어떻게 변경하면 되는지* 가 머리에 들어온다.

---

## 부록: 1차 인제스션 실행 결과 (2026-05-19)

코드가 어떻게 동작하는지 *읽는* 것과 *실제로 돌려본 것* 은 다른 지식이라
한 번 돌려보며 부딪힌 실제 이슈와 통계를 남긴다.

**산출물 수치**

```
seed_docs/
├── cyberdefenders/  69 docs   →  1379 RAG chunks  ✅
├── dfirreport/      14 docs   →   598 RAG chunks  ✅ (재크롤 후)
├── eztools/         32 docs   →   522 RAG chunks  ✅
└── hacktricks/     828 docs   →   828 RAG chunks  ⚠️ (105자 404 placeholder)
                  --------------- ----------
                    943 docs        3327 chunks 인덱싱됨

tools_metadata/_draft/             0 YAML (Stage 2 진행 중)
seed_docs/_indicator_candidates/   0 YAML (Stage 4a 대기 중)
eval/goldenset/                    0 JSON (Stage 4b 대기 중)
```

**1차 시도에서 부딪힌 4 개의 실패와 그 의미**

1. `ModuleNotFoundError: forensicagent` — `subprocess.Popen` 으로 띄운
   `scripts/*.py` 는 패키지 모듈이 아니라 sys.path 에 repo root 가 없다.
   `run_all.py:_run_module()` 에서 PYTHONPATH 를 명시 주입해 해결. 코드 변경
   = `subprocess.Popen(..., env=env)` 한 줄.

2. DFIR Report 본문 미추출 (424 chars placeholder) — 1차 파서는 `<article>`
   / `<main>` 만 찾았는데 DFIR Report 는 WordPress 의 `div.entry-content-wrapper`
   안에 본문이 있다. `_strip_html` 의 선택자 우선순위에 WordPress 클래스를
   prepend. 재크롤 후 평균 30K chars 로 회복.

3. HackTricks 도메인 이전 — `book.hacktricks.xyz` → `book.hacktricks.wiki`
   변경 + 동시에 URL 경로 구조도 변경 (`/src/AI/...` 페이지가 wiki 에는 다른
   곳에 있음). 우리는 도메인만 rewrite 했고 경로는 그대로라 828 페이지 전부
   404 받음. RAG 인덱스에 들어가긴 했지만 내용이 "Document not found" 라
   실질 가치 0. 향후 wiki 의 sidebar 트리를 분석해서 URL 매핑이 필요.

4. Ollama python lib 0.6.2 의 응답 shape — `client.list()` 가 dict 가 아니라
   Pydantic `ListResponse` 를 반환. 0.4 시절 dict 코드는 빈 모델 이름 리스트를
   만들어 `is_available()` 가 잘못된 경고를 냈다. 양쪽 모두 지원하도록 보강
   (`getattr(m, "model", None) or getattr(m, "name", None) or ...`).

**그리고 결정적 한계: Ollama 의 기본 `num_ctx=4096`**

7B 모델 + CPU 추론은 단순히 *느린 게* 아니라, 기본 4096 토큰 컨텍스트로 로드
되어 14KB EZTools 매뉴얼 + 시스템 프롬프트가 거의 다 차고 출력에 여유가 없다.
실제 첫 호출 결과가 `json_chat parse attempt 1/2 failed: Unterminated string
starting at line 88 column 18 (char 3510)` — 모델이 JSON 의 string 값을 쓰는
도중 토큰 한도에 도달해서 응답이 잘렸다.

수정: `OllamaClient` 에 `num_ctx` / `num_predict` 매개변수 추가. 기본값
`num_ctx=16384`, `num_predict=2048`. env var `FORENSICAGENT_LLM_NUM_CTX` 로
GPU/RAM 상황에 맞춰 조정 가능. **다음 재실행부터 적용됨** (현재 백그라운드
실행은 수정 전 코드라 의미 있는 결과 안 나올 가능성 큼).

**얻은 교훈**

- 크롤러는 단순해 보여도 사이트별로 0~3 개의 미세한 셀렉터 함정이 있다.
  HackTricks 처럼 SPA + 도메인 이전이 겹치면 단순 substring rewrite 로는
  부족.
- 로컬 LLM 으로 강제 JSON 추출을 할 때 첫 번째 적이 컨텍스트 길이다. Ollama
  의 기본 4096 은 RAG 가 아니라 *short prompt* 에 맞춰져 있어, ETL 용으로는
  반드시 늘려야 한다.
- subprocess 로 ETL stage 를 분리하면 import 격리는 얻지만 sys.path 가 함정.
- *Stage 1 (크롤) + Stage 3 (RAG) 자체는 GPU 없이도 30분 안에 끝난다* —
  포렌식 도메인 코퍼스를 한 번에 인덱싱하는 인프라는 이미 동작 가능.
  Stage 2/4 (LLM 추출) 만 GPU 가 강력하게 권장됨.

---

## 변경할 때 어디부터 손대나 (cheatsheet)

| 하고 싶은 일 | 손대는 파일 |
|---|---|
| 새 도구 추가 | `tools_metadata/<tool>.yaml` 만 작성. 코드 변경 0. |
| 새 indicator 룰 추가 (정교한 매처) | `forensicagent/analyzer/rules.py` 의 `_SPECIFIC_MATCHERS` 에 함수 등록 |
| 도구별 어댑터 커스터마이즈 | `forensicagent/executor/adapter.py` 에서 `GenericAdapter` 상속 + `register_adapter()` |
| 새 evidence 타입 인식 | `scanner/types.py` 의 `EvidenceType` literal + `scanner/detectors.py` 시그니처 |
| 새 LLM 백엔드 (Ollama 외) | `llm/` 에 새 클라이언트 + Selector/Analyzer 가 받는 client 의존성 주입 |
| CLI 새 옵션 | `cli/main.py` 의 `root()` typer Option |
| 리포트 포맷 추가 (예: HTML) | `reporter/html_out.py` + `reporter.py` 의 `formats` 튜플 |
