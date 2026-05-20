# 프로젝트 투어 — 결과물 + 코드 이해 가이드

지금까지의 forensicagent 작업이 만든 **결과물**이 무엇이고, 그것들을
**어떤 순서로 보면 이해가 빠른지** 한 문서에 정리한 가이드.

> 이미 있는 문서와의 관계:
> - [`README.md`](README.md) — 프로젝트 소개, 시나리오, 설계 결정 *이유*
> - [`CLAUDE.md`](CLAUDE.md) — Claude/세션이 보는 명세 + 다음 세션 재개 노트
> - [`understand_code.md`](understand_code.md) — *코드 파일* 읽는 순서 (이 문서가 가벼운 버전)
> - 이 문서 (`PROJECT_TOUR.md`) — **결과물 인벤토리 + 빠른 투어**

---

## 0. 한눈에 — 무엇을 만들었나

```
forensicagent/   ← 제품 본체 (Phase 1-5 완료, end-to-end 동작)
├── 8 모듈      cli / scanner / selector / executor / analyzer / reporter / rag / llm
├── ~30 py 파일  각 모듈 평균 3-5 파일
└── observability + tools 보조 패키지

tools_metadata/  ← 도구 카탈로그 (Selector / Analyzer 의 진실 원천)
├── 8 도구 YAML  chainsaw / volatility3 / regripper / mftecmd / evtxecmd / recmd / pecmd / amcacheparser
└── 40 indicators + 24 command templates

seed_docs/       ← 외부 도메인 자료 (sample.txt 1085 URL 크롤 결과)
├── cyberdefenders/   69 SOC 블로그
├── dfirreport/       14 침해 사건 상세
├── eztools/          32 도구 매뉴얼
└── hacktricks/      828 백과사전 페이지 (95% 본문 회수)

ChromaDB         ← RAG 인덱스 (4 컬렉션 / 15,161 chunks)
├── seed_cyberdefenders  1,379
├── seed_dfirreport        598
├── seed_eztools           522
└── seed_hacktricks     12,662

seed_docs/_indicator_candidates/  ← LLM 추출 indicator 후보 (Stage 4a)
├── 69 YAML 파일  → 299 indicators
└── _merge_plan.yaml  병합 계획 (20 자동 매핑, 279 사람 검수 대기)

eval/goldenset/  ← Phase 6 평가 baseline (Stage 4b)
└── 14 JSON   case_summary + tools_used + ttps + key_iocs

tests/           ← 89 단위 테스트 (1.94s 통과)
├── test_detectors.py  46
├── test_filter.py     11
├── test_rules.py      11
└── test_chunks.py     21

scripts/         ← 보조 라인 (런타임 X)
├── ingest_sample.py        Stage 1 크롤 오케스트레이터
├── yaml_seeder.py          Stage 2 EZTools → YAML (LLM)
├── extract_indicators.py   Stage 4a CD → indicators (LLM)
├── build_goldenset.py      Stage 4b DFIR → goldenset (LLM)
├── analyze_indicators.py   Stage 4a 결과 분석/병합 헬퍼
├── run_all.py              마스터 오케스트레이터
└── crawlers/               이전 세대 도메인 크롤러들
```

---

## 1. 수치로 본 결과

| 항목 | 숫자 |
|---|---:|
| forensicagent 패키지 모듈 | 8 |
| Python 파일 (코드) | ~38 |
| 도구 YAML | 8 |
| 도구별 평균 indicators | 5.0 |
| 도구별 평균 command_templates | 3.0 |
| 단위 테스트 | 89 (1.94s 통과) |
| 크롤 URL (sample.txt) | 1,085 |
| 크롤 성공 doc | 943 (87%) |
| RAG chunks 인덱싱 | 15,161 |
| Stage 4a indicator 후보 | 299 (69 YAML) |
| Stage 4b goldenset case | 14 |
| Git 커밋 (forensicagent line) | 10 |
| Stage 4a/4b 의 누적 Ollama CPU time | 30+ 시간 |
| 전체 풀 파이프라인 실행 시간 | 24.5 시간 |

---

## 2. 코드 읽는 순서 (3 시간 코스)

### 2-1 (15 분) **목적 파악**

| 순서 | 파일 | 보는 것 |
|---|---|---|
| 1 | `README.md` § 목적과 비목적 | 왜 만드는가, 안 푸는 것 |
| 2 | `README.md` § 어떤 흐름으로 만들었나 | 5 단계 + 설계 결정 이유 |
| 3 | `git log --oneline cf867c7..HEAD` | 10 커밋 메시지 = 변경 이유의 원천 |

### 2-2 (30 분) **CLI 진입점 따라가기**

| 순서 | 파일 | 핵심 라인 |
|---|---|---|
| 4 | `forensicagent/cli/main.py` | `root()` 함수 — 전 파이프라인 직선 흐름 |
| 5 | `forensicagent/cli/doctor.py` | 모든 의존성을 *진짜* 호출해 검증 |
| 6 | `forensicagent/observability/metrics.py` | `Stopwatch` / `StageTimings` — 다른 모듈 들어가기 전 60 줄짜리 primitive |

### 2-3 (1.5 ~ 2 시간) **5 단계 데이터 흐름**

각 단계는 **types.py 먼저 → 본체** 순서로.

| 단계 | types | 본체 | 핵심 아이디어 |
|---|---|---|---|
| Scanner | `scanner/types.py` | `scanner/detectors.py`, `scanner/scanner.py` | magic / ext / 파일명 / 부모 디렉토리 4단 우선순위 |
| Tools | `tools/schema.py` | `tools/loader.py`, `tools_metadata/chainsaw.yaml` | YAML 1개가 4 모듈을 다 구동한다 |
| RAG | `rag/vector_store.py` | `rag/embedder.py`, `rag/indexer.py` | ChromaDB cosine + per-domain 컬렉션 |
| LLM | (없음) | `llm/ollama_client.py` | `json_chat()` + `format_schema=` + 1회 재시도 |
| Selector | `selector/types.py` | `selector/filter.py`, `selector/llm_rank.py`, `selector/selector.py` | 결정론 Stage 1 → LLM Stage 2, fallback 자동 |
| Executor | `executor/types.py` | `executor/adapter.py`, `executor/runner.py`, `executor/executor.py` | subprocess 격리 + 파일 출력 + 어댑터 패턴 |
| Analyzer | `analyzer/types.py` | `analyzer/rules.py`, `analyzer/llm_extract.py`, `analyzer/analyzer.py` | Case A/B/C 분기, id 기반 specific matcher + fallback |
| Reporter | `reporter/types.py` | `reporter/builder.py`, `reporter/terminal.py`, `reporter/json_out.py`, `reporter/md_out.py`, `reporter/reporter.py` | terminal + JSON + MD 동시 |

### 2-4 (1 시간) **데이터 ETL 라인 (sample.txt 처리)**

forensicagent 본체와 **분리된** ETL. 도구 메타데이터, RAG 코퍼스, 골든셋을 생산하는 라인.

| 순서 | 파일 | 보는 것 |
|---|---|---|
| 35 | `scripts/run_all.py` | 마스터 오케스트레이터 — 4 stage 자원별 동시성 |
| 36 | `scripts/ingest_sample.py` | Stage 1 — 도메인 분류 + ThreadPool × 4 + URL_REWRITES |
| 37 | `forensicagent/rag/indexer.py` | Stage 3 — 청킹 + 임베딩 + 컬렉션 저장 |
| 38 | `scripts/yaml_seeder.py` | Stage 2 — Pydantic schema 강제 (`format_schema=`) |
| 39 | `scripts/extract_indicators.py` | Stage 4a — 6 필드 indicator 추출 |
| 40 | `scripts/build_goldenset.py` | Stage 4b — case meta 추출 |
| 41 | `scripts/analyze_indicators.py` | Stage 4a 결과 분석 + 병합 계획 |

### 2-5 (수시) **자주 다시 보는 위치**

| 파일 | 왜 자주 보나 |
|---|---|
| `forensicagent/config.py` | env var 이름 (`FORENSICAGENT_LLM_MODEL`, `_NUM_CTX`, `_NUM_PREDICT`, ...) |
| `forensicagent/tools/schema.py` | 새 도구 YAML 작성 시 항상 참조 |
| `forensicagent/analyzer/rules.py` 의 `_SPECIFIC_MATCHERS` | 새 indicator id 등록 |
| `forensicagent/executor/adapter.py` 의 `register_adapter()` | 새 specialized adapter 추가 hook |

---

## 3. 결과물 둘러보기 — 어디 무엇이 있나

코드 외에 **실제로 디스크에 떨어진 데이터**들. 다음에 무엇을 할지 결정할 때 참고.

### 3-1 `tools_metadata/*.yaml` — 8 도구 카탈로그

각 YAML 1 파일이 `ToolMetadata` Pydantic 클래스 하나. 5 필드 정도만 봐도 그 도구가 어떻게 시스템에 흡수되는지 보인다.

```yaml
tool_id: chainsaw                          # 식별자, YAML 파일명과 일치
applicable_evidence_types: [evtx_log]      # Selector Stage 1 의 결정론 필터 키
command_templates:                          # Executor 가 이걸로 실제 명령 빌드
  - template: "chainsaw hunt {evidence_path} -s {sigma_path} --json"
suspicious_indicators:                      # Analyzer 가 finding 추출에 사용
  - id: sigma_rule_hit
    pattern: "JSON 출력에 rule_name 필드"
    severity_baseline: medium
```

샘플로 보기 좋은 도구:
- `chainsaw.yaml` — 가장 짧고 직관적 (2 templates / 4 indicators)
- `recmd.yaml` — 가장 깊이 있게 작성 (3 templates / 7 indicators, 모두 실전 persistence 패턴)
- `mftecmd.yaml` — applicable_evidence_types 가 여러 개인 케이스 (disk_image + registry_hive)

### 3-2 `seed_docs/<domain>/*.json` — 크롤 원본

```json
{
  "url": "https://thedfirreport.com/2025/05/19/...",
  "title": "Another Confluence Bites the Dust...",
  "content": "(30,757 chars 본문 markdown-ish 텍스트)"
}
```

가장 가치 있는 본문은:
- `seed_docs/eztools/<tool>.json` — Eric Zimmerman 도구 매뉴얼. **사람이 YAML 작성하기 좋은 원천 자료.**
- `seed_docs/dfirreport/*.json` — 실제 침해 사건 분석. **TTP/IoC 가 본문에 있음, 골든셋의 원천.**
- `seed_docs/hacktricks/*.json` — 95% 가 실제 본문 (재크롤 후). RAG 컨텍스트로 가장 풍부.
- `seed_docs/cyberdefenders/*.json` — SOC 분석 기법 블로그. indicator 패턴의 원천.

### 3-3 ChromaDB (`~/.forensicagent/chroma/`) — RAG 인덱스

이건 직접 보기 어려우니 (binary), 다음 코드로 둘러본다:

```python
from forensicagent.rag.vector_store import VectorStore
from forensicagent import config
vs = VectorStore(persist_dir=config.CHROMA_PERSIST_DIR,
                 collection_name="seed_dfirreport")
print(vs.count())  # 598
# (forensicagent 런타임이 Analyzer LLM 호출 시 자동으로 top-K 컨텍스트로 주입)
```

### 3-4 `seed_docs/_indicator_candidates/*.yaml` — 69 후보

LLM (qwen2.5:7b) 이 CyberDefenders 블로그 1편당 indicator 6-필드 JSON 으로 추출한 결과. **사람이 검수 후 기존 도구 YAML 에 병합** 하는 흐름.

```yaml
topic: Active Directory Monitoring for SOC Analysts
indicators:
  - id: ad-privileged-group-change
    pattern: Changes to privileged group memberships (Domain Admins, ...)
    severity_baseline: medium
    description: Detects unauthorized changes to high-privilege user groups.
    tool_hint: evtx                            # → Selector 가 chainsaw / evtxecmd 매핑
    applicable_evidence_types: [evtx_log]
```

`_merge_plan.yaml` 가 다음을 보여줌:
- 20 indicators 가 기존 8 도구에 자동 매핑 가능 (chainsaw 15 / regripper 4 / volatility3 1)
- 279 indicators 는 `tool_hint: other` 또는 알 수 없는 hint — 수동 검토 대상
- duplicate id 1건

### 3-5 `eval/goldenset/*.json` — 14 Phase 6 baseline

```json
{
  "case_name": "confluence_elpaco",
  "case_summary": "A threat actor exploited CVE-2023-22527...",
  "evidence_types_present": ["sysmon_log", "pcap", "batch_file"],
  "tools_used": [
    {"tool_id": "suricata", "purpose": "Detecting network anomalies"},
    {"tool_id": "sysmon",   "purpose": "Monitoring system events..."}
  ],
  "ttps": ["T1059.003", "T1047", "T1543.003", "T1016"],
  "key_iocs": ["..."]
}
```

용도: forensicagent 가 같은 case 디렉토리를 받았을 때 *어떤 도구를 선택했는지* 의 정답. precision/recall 측정의 기준.

### 3-6 `tests/` — 89 결정론 테스트

| 파일 | 검증 대상 | 통과 |
|---|---|---:|
| test_detectors.py | 9 magic 시그니처 + 22 확장자 + 6 정규식 + 6 디렉토리 + composite priority | 46 |
| test_filter.py | Selector Stage 1 evidence_type 교집합 + multi-evidence union | 11 |
| test_rules.py | sigma_rule_hit / run_key_unusual / fallback substring + 룰 격리 | 11 |
| test_chunks.py | RAG `_chunks` / `_doc_id` / `classify` / `slug_for` | 21 |

LLM / 네트워크 / GPU 의존성 없이 1.94초 안에 통과. 코드 변경 후 안전성 빠르게 확인용.

---

## 4. 커밋 타임라인 — *왜* 이렇게 만들어졌나

| Commit | 핵심 |
|---|---|
| `cf867c7` | refactor: pivot from RAG chatbot → forensicagent CLI |
| `4c53835` | feat: Phase 1 (CLI/Ollama/doctor) + Scanner + rag TODO 채움 |
| `af437ce` | feat: Phase 3-5 (Selector/Executor/Analyzer/Reporter + 3 YAML) |
| `95a327d` | docs: README + CLAUDE.md resume notes |
| `659f820` | feat: sample.txt ingestion pipeline (4 stages, parallel) |
| `601d0c7` | fix: 4 ingestion bugs (PYTHONPATH / WP selector / Ollama Pydantic / num_ctx) |
| `5d8595b` | fix+test: Stage 2 JSON Schema 강제 + 89 단위 테스트 + Stage 4a 분석기 + HackTricks URL 매핑 |
| `cb87549` | feat: hand-written 5 EZTools YAMLs - 도구 풀 3 → 8 |
| `93ba8ab` | docs: 밤샘 작업 후 README/CLAUDE 상태 갱신 |
| `96aeec2` | docs: HackTricks 재크롤 + 재인덱싱 결과 반영 |
| `c90c3a5` | docs: 24.5시간 full pipeline 종료 - Stage 4a/4b 완료 반영 |

`git log --oneline cf867c7..HEAD` 가 forensicagent 작업분 전체.

---

## 5. 설치와 실행 — `forensicagent` 명령이 어떻게 동작하나

### 5-1 처음 설치 (0 → 작동)

```bash
# 0. (선택) 가상환경 — 시스템 파이썬을 더럽히지 않으려면
python -m venv .venv
.venv\Scripts\activate     # Windows
source .venv/bin/activate  # macOS/Linux

# 1. 런타임 의존성
pip install -r requirements.txt

# 2. 패키지 자체 설치 — 두 가지 모드 중 하나 선택
pip install -e .   # 개발자 모드 (코드 수정이 즉시 반영, 권장)
# pip install .    # 정식 설치 (파일 사본을 site-packages 로 복사)
```

설치 직후 다음 두 명령이 동작하면 OK:

```bash
forensicagent --version   # → forensicagent 0.0.1
forensicagent --help      # → 사용법 출력
```

### 5-2 `forensicagent` 명령이 어디서 오나 (메커니즘)

`pip install -e .` (또는 `pip install .`) 가 다음을 한다:

1. `pyproject.toml` 의 다음 항목을 읽음:
   ```toml
   [project.scripts]
   forensicagent = "forensicagent.cli.main:app"
   ```
2. 파이썬의 `<venv>/Scripts/` (Windows) 또는 `<venv>/bin/` (Unix) 에
   **shim 실행파일** `forensicagent.exe` (또는 `forensicagent`) 를 생성.
3. 이 shim 은 본질적으로 `python -c "from forensicagent.cli.main import app; app()"` 와 같다.

그래서 셸에서 `forensicagent` 만 쳐도 어디서든 동작. 다음 두 명령은 **완전히 동치**:

```bash
forensicagent --path /case/03
python -m forensicagent --path /case/03   # __main__.py 가 같은 app() 호출
```

설치 안 한 상태에서도 `python -m forensicagent` 는 동작 (모듈 직접 실행).

### 5-3 명령이 안 보일 때 — `forensicagent: command not found`

흔한 원인 3 가지:

| 원인 | 진단 | 해결 |
|---|---|---|
| pip install 안 했음 | `pip show forensicagent` 가 비어 있음 | `pip install -e .` 재실행 |
| venv 활성화 안 됨 | `where forensicagent` (Win) / `which forensicagent` (Unix) 가 빈 결과 | venv 활성화 또는 `python -m forensicagent` 사용 |
| Windows 의 PATH 우선순위 | shim 은 venv/Scripts/ 에 있는데 PATH 가 다른 forensicagent 를 먼저 잡음 | `where.exe forensicagent` 로 충돌 확인 |

설치 없이 임시로 돌리려면:

```bash
python -m forensicagent --help        # PYTHONPATH 가 정확하면 동작
# 또는
PYTHONPATH=. python -m forensicagent --help
```

### 5-4 Ollama 준비 (LLM 사용하려면)

forensicagent 의 Selector Stage 2 와 Analyzer LLM 추출은 Ollama 서버가 필요. 없으면 `--no-llm` 으로 우회.

```bash
# 1. Ollama 설치 (https://ollama.com/download)

# 2. 데몬 띄우기 (기본 http://localhost:11434)
ollama serve     # 별도 터미널에서

# 3. 모델 받기
ollama pull qwen2.5:7b    # 기본값. 14b 가 더 좋지만 7b 가 노트북 CPU 에서 현실적
# 또는 GPU 가 작으면:
ollama pull qwen2.5:3b    # 1.9GB, 2GB VRAM 에 들어감
ollama pull gemma:2b      # 1.7GB

# 4. forensicagent 가 어떤 모델을 쓸지 설정 (env var)
export FORENSICAGENT_LLM_MODEL=qwen2.5:7b
# Windows PowerShell:
$env:FORENSICAGENT_LLM_MODEL = "qwen2.5:7b"

# 5. 동작 확인
forensicagent doctor
```

`doctor` 가 ollama 줄에 `OK` 가 뜨면 준비 완료.

### 5-5 첫 분석 실행 — 5 분 코스

```bash
# 1. 합성 증거 디렉토리 만들기 (실제 EVTX 없이도 테스트 가능)
mkdir C:\tmp\case
python -c "open(r'C:\tmp\case\Security.evtx','wb').write(b'ElfFile\x00'+b'\x00'*100)"
python -c "open(r'C:\tmp\case\NTUSER.DAT','wb').write(b'regf'+b'\x00'*100)"

# 2. 계획만 먼저 보기 (도구는 실행 안 함)
forensicagent --path C:\tmp\case --dry-run

# 3. LLM 없이 결정론적으로 (Ollama 없어도 동작)
forensicagent --path C:\tmp\case --no-llm --auto

# 4. LLM 포함 인터랙티브 (사용자 승인 단계 포함)
forensicagent --path C:\tmp\case

# 5. 리포트 저장 위치 확인
ls C:\tmp\case\forensicagent_output\
# report_YYYYMMDD_HHMMSS.json    기계 가독
# report_YYYYMMDD_HHMMSS.md      사람 가독
# raw/                            도구 stdout/stderr
```

### 5-6 자주 쓰는 옵션 cheatsheet

```bash
# 기본 흐름 변형
forensicagent                                    # 인터랙티브 (기본)
forensicagent --auto                              # 승인 없이 자동
forensicagent --no-llm                            # 결정론만 (Stage 2 LLM + Analyzer LLM 스킵)
forensicagent --dry-run                           # 계획까지만, 도구 실행 안 함
forensicagent --quick                             # estimated_runtime: short 만 실행

# 범위 제어
forensicagent --path /case/03                     # 다른 디렉토리 분석
forensicagent --tools chainsaw,evtxecmd           # 특정 도구만 강제 (Selector 우회)
forensicagent --max-depth 3                       # 깊이 제한
forensicagent --output-dir /reports               # 결과 저장 위치
forensicagent --timeout 600                       # 도구당 타임아웃 (초)

# 진단
forensicagent doctor                              # 환경 점검
forensicagent doctor --skip-optional              # 포렌식 도구 PATH 체크 건너뛰기
forensicagent tools list                          # 도구 카탈로그
forensicagent tools info chainsaw                 # 특정 도구 YAML 출력
forensicagent --version                           # 버전
forensicagent -v                                  # verbose (INFO 로깅)

# 환경 변수 (config.py 의 기본값 override)
FORENSICAGENT_LLM_MODEL=qwen2.5:3b forensicagent     # 다른 모델
FORENSICAGENT_LLM_BASE_URL=http://...:11434          # 원격 Ollama
FORENSICAGENT_LLM_NUM_CTX=16384                      # 컨텍스트 윈도우
FORENSICAGENT_TOOLS_DIR=/custom/tools forensicagent  # 도구 YAML 디렉토리 변경
FORENSICAGENT_CHROMA_DIR=/data/chroma                # RAG DB 위치 변경
```

### 5-7 보조 스크립트 실행 (sample.txt ETL)

이건 *런타임* 이 아니라 forensicagent 가 쓸 데이터를 만드는 **빌드 단계**.
한 번 돌려 두고 결과를 forensicagent 가 활용한다.

```bash
# 전체 4 stage 일괄 (병렬)
python scripts/run_all.py sample.txt

# 단계별 실행 (자원 충돌 피하려면)
python scripts/ingest_sample.py sample.txt              # Stage 1 (크롤, 네트워크)
python -m forensicagent.rag.indexer                     # Stage 3 (임베딩, CPU/GPU)
python scripts/yaml_seeder.py                           # Stage 2 (Ollama 직렬)
python scripts/extract_indicators.py                    # Stage 4a (Ollama 직렬)
python scripts/build_goldenset.py                       # Stage 4b (Ollama 직렬)

# 분석 헬퍼 (LLM 0회)
python scripts/analyze_indicators.py                    # Stage 4a 결과 통계 + 병합 계획
```

`run_all.py` 의 옵션:

```bash
python scripts/run_all.py sample.txt --skip-crawl       # 이미 크롤된 거 재활용
python scripts/run_all.py sample.txt --skip-llm         # Ollama 단계 모두 스킵
python scripts/run_all.py sample.txt --skip-rag         # RAG 인덱싱 스킵
python scripts/run_all.py sample.txt --overwrite        # 캐시 무시하고 재실행
python scripts/run_all.py sample.txt --crawl-workers 6  # 도메인당 동시연결 수
python scripts/run_all.py sample.txt --limit 5          # 도메인당 5 개씩만 (스모크 테스트)
```

### 5-8 패키징 / 배포 — 다른 머신에 설치 가능한 형태로

다른 컴퓨터에 가서 `pip install <foo>.whl` 한 번에 동작하는 wheel 을 만들고 싶다면:

```bash
# 1. build 도구 설치
pip install build

# 2. wheel + sdist 생성
python -m build
# → dist/forensicagent-0.0.1-py3-none-any.whl
# → dist/forensicagent-0.0.1.tar.gz

# 3. 다른 머신에 가서 설치
pip install dist/forensicagent-0.0.1-py3-none-any.whl

# 4. 확인
forensicagent --version
```

**주의**: wheel 에는 `tools_metadata/*.yaml` 같은 *데이터 파일* 이 안 들어간다 (현재 `pyproject.toml` 는 패키지만 wheel 에 포함하도록 설정). 도구 카탈로그는:

- 옵션 A: 사용자가 직접 `tools_metadata/` 디렉토리를 만들고 YAML 을 거기 둠.
  forensicagent 는 `FORENSICAGENT_TOOLS_DIR` env var 또는 `~/.forensicagent/tools/` 또는 CWD/tools_metadata/ 의 fallback 순서로 찾는다.
- 옵션 B: 향후 `pyproject.toml` 의 `[tool.hatch.build.targets.wheel]` 에
  `include = ["tools_metadata/*.yaml"]` 추가하면 wheel 에 동봉 가능.

### 5-9 자주 발생하는 문제 / 해결

| 증상 | 원인 | 해결 |
|---|---|---|
| `forensicagent: command not found` | shim 등록 안 됨 | `pip install -e .` 재실행 또는 `python -m forensicagent` 사용 |
| `doctor` 가 ollama 줄에 FAIL | 데몬 미실행 또는 모델 미설치 | `ollama serve` 백그라운드 + `ollama pull qwen2.5:7b` |
| `doctor` 가 libmagic FAIL | Windows 에 libmagic 백엔드 없음 | `pip install python-magic-bin` (Win 전용) |
| 한글이 깨짐 (`���`) | cp949 codepage + pipe 출력 | 정상. 터미널에서 직접 보면 멀쩡함. 또는 `chcp 65001` 로 UTF-8 변경 |
| Stage 2 가 schema_failed | LLM 이 strict schema 안 따라옴 (옛 코드 + small model) | 최신 코드에는 `format_schema=` 적용됨. 더 큰 모델 (qwen2.5:7b) 사용 |
| `UnicodeEncodeError: 'cp949' ... '—'` | em-dash 가 print 문에 있음 | 이미 모두 hyphen 으로 교체됨. 새 스크립트 추가 시 주의 |
| `ModuleNotFoundError: forensicagent` (스크립트 실행 시) | sys.path 에 repo root 없음 | `PYTHONPATH=. python scripts/foo.py` 또는 `python -m foo` |
| `--no-llm --dry-run` 도 한글이 안 보임 | Rich Console 이 redirect 감지하면 ASCII fallback | 정상. 인터랙티브 터미널에서 직접 보면 컬러풀 |

### 5-10 한 줄 요약

```
설치   →  pip install -e .                       (shim 등록: forensicagent.exe)
점검   →  forensicagent doctor                   (의존성 다 OK 인지)
연습   →  forensicagent --path /tmp/case --no-llm --dry-run
본격   →  forensicagent                          (인터랙티브, LLM 포함)
빌드   →  python -m build                        (배포용 wheel)
```

---

## 6. 다음에 무엇을 할지 — 우선순위 cheatsheet

| 작업 | 난이도 | 가치 | 손대는 파일 |
|---|---|---|---|
| Stage 4a 의 20개 자동 매핑 indicators 를 도구 YAML 에 병합 | 사람 손, 1-2시간 | 즉시 가치 (forensicagent indicator 풀 확장) | `tools_metadata/{chainsaw,regripper,volatility3}.yaml` 의 `suspicious_indicators:` 섹션 |
| Stage 2 재시도 (`format_schema=` 적용된 새 코드로) | 코드 변경 0, Ollama 시간 ~5 시간 | 도구 풀 8 → ~30 (자동 시드) | `python scripts/yaml_seeder.py --overwrite` |
| 더 작은 모델로 GPU 추론 시도 | qwen2.5:3b 또는 gemma:2b 로 `FORENSICAGENT_LLM_MODEL` 변경 | LLM 작업 5-10배 가속 | env var 1줄 변경 |
| Phase 6 평가 실행 | 골든셋 14건이 정답. forensicagent 가 같은 evidence 받았을 때 비교 | precision/recall 첫 수치 | `eval/goldenset/*.json` vs forensicagent 출력 |
| HackTricks 의 39개 wiki 미존재 페이지 정리 | 105 char placeholder 인덱스에서 제거 | RAG 노이즈 감소 | `seed_docs/hacktricks/` 에서 size<200 byte 삭제 + RAG 재인덱싱 |
| Stage 4a 의 unmapped 279 indicators 의 tool_hint 수동 재라벨링 | 사람 손, 노가다 | indicator 풀 6배 확장 가능 | `seed_docs/_indicator_candidates/*.yaml` 의 `tool_hint` 필드 |
| 새 도구 YAML 추가 (yara, plaso, tshark, ...) | 사람 손, 도구당 30분 | 도구 풀 확장 | `tools_metadata/<new>.yaml` |
| specialized adapter (Volatility 같이 출력 비표준) | 코드 중 | Executor 정확도 ↑ | `forensicagent/executor/adapter.py` + `register_adapter()` |

---

## 7. 한 줄 결론

forensicagent 는 **이미 동작하는** CLI agent 다. 남은 일은 거의 *데이터 노가다* + *평가* 와 *모델 가속* 의 영역이지, 코드 추가가 아니다. 그래서 다음 세션은 어디서든 자연스럽게 이어 갈 수 있다.
