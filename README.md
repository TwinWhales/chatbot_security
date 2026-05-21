# forensicagent

> 포렌식 자동 분류 CLI 에이전트 — 로컬 LLM 이 증거를 식별하고, 적절한
> 분석 도구를 RAG 로 선별·실행해서, 도구별 의심 항목을 자동 추출해 리포트로
>제시한다.

```
$ cd ~/ctf/forensics-challenge-03/
$ forensicagent

[*] 작업 디렉토리: ~/ctf/forensics-challenge-03/
[*] 증거 스캔 중...
[+] 발견: memory.raw (메모리 덤프, 2.1GB)
[+] 발견: Security.evtx (Windows 이벤트 로그)
[+] 발견: NTUSER.DAT (레지스트리 하이브)

[*] 적용 가능한 도구 7 개 선별됨:
    1. volatility3 (pslist, netscan, malfind)
    2. chainsaw (Sigma hunt)
    3. regripper (userassist, run keys)
    ...
계속 진행할까요? [Y/n] y

[*] [1/7] volatility3 pslist 실행 중... ✓ (12.3s)
    └─ 의심항목 2 개 발견
...

[chainsaw] 의심항목 5건
  - 비업무시간 RDP 로그온 (이벤트 4624 Type 10), 외부 IP 185.x.x.x
  - PowerShell 인코딩된 명령 실행 (이벤트 4104)
  ...
```

---

## 목적과 비목적

**해결하려는 문제.** 포렌식 분석가가 50+ 개 도구를 머리에 외워두고 매번
직접 결정 (어떤 증거에 어떤 도구를) 하는 것은 비효율이고, 신입에게는 진입
장벽이다. 동시에 "전부 다 돌리기" 도 분명 낭비 (메모리 덤프에 RegRipper
를 돌릴 필요는 없다).

**우리가 푸는 좁은 문제.** CWD 디렉토리만 보고 → 어떤 도구를 → 어떤 증거에
→ 어떤 순서로 돌릴지 결정하고, 도구 출력에서 **알려진 의심 패턴** 만 자동
으로 뽑아 리포트로 묶는 **triage** 단계.

**의도적으로 안 하는 것.**
- 침해 사고 전체 시나리오 자동 재구성 (분석가가 리포트 보고 판단)
- 도구 결과 간 상관관계 분석 (도구별 finding 만 노출, 머지 안 함)
- 새로운 익스플로잇/악성코드 탐지 (알려진 패턴만)
- 증거 무결성 검증 / chain of custody (격리 랩 가정)
- 실시간 모니터링 (사후 분석 전용)

---

## 어떤 흐름으로 만들었나

전체 사이클을 5 단계로 쪼개고, 각 단계가 다음 단계에 dict 한 묶음만 넘기는
**순수 함수 + 데이터클래스** 구조로 만들었다. 그래서 어느 단계든 stub 으로
교체해도 다른 단계의 코드가 깨지지 않는다 (테스트/오프라인 개발 가능).

```
Scanner → Selector → (사용자 승인) → Executor → Analyzer → Reporter
   ↑                                                            ↓
   └────────────── observability (Stopwatch / stage_ms) ────────┘
```

| 단계 | 책임 | 디렉토리 |
|---|---|---|
| **Scanner** | CWD 의 파일을 magic bytes + 확장자 + 파일명 + 부모 디렉토리 힌트로 식별. 9 magic 시그니처 + 22 확장자 + 6 정규식 + 6 디렉토리 키워드. | `forensicagent/scanner/` |
| **Selector** | 2 단계 하이브리드. **Stage 1** = 결정론 매칭 (evidence_type ∩ applicable_evidence_types). **Stage 2** = LLM 에게 후보들의 우선순위 + 보강된 reason 만 JSON 으로 요청. 파싱 실패 시 Stage 1 결과 그대로 fallback. | `forensicagent/selector/` |
| **Executor** | 어댑터 패턴. `GenericAdapter` 가 YAML 의 `command_templates` 와 `install_check` 만으로 동작. `subprocess.Popen` + 타임아웃, `shell=False` (인젝션 차단), stdout/stderr 는 메모리가 아니라 **파일로**. `parallelizable=true` 면 ThreadPool, 아니면 직렬. | `forensicagent/executor/` |
| **Analyzer** | 출력 크기에 따라 분기 — **Case A** (≤100 KB, rules + LLM 둘 다) / **Case B** (≤4 MB, rules 가 추리고 LLM 으로 자연어 보강) / **Case C** (>4 MB, rules only, LLM 안 부름). `suspicious_indicators.id` 별 specific matcher + 미등록은 키워드 AND fallback. dedup + severity 내림차순. | `forensicagent/analyzer/` |
| **Reporter** | terminal (Rich 표) + JSON (기계 가독) + Markdown (사람 가독) 동시 출력. 한 파일이 한 포맷, 정해진 디렉토리. | `forensicagent/reporter/` |

### 왜 이렇게 쪼갰나

- **Scanner / Selector 분리**: "무엇이 있는가" 와 "무엇을 돌릴까" 는 다른
  결정이다. Selector 는 Scanner 결과 + 도구 메타데이터만 보면 되고, 파일
  시스템에 다시 접근하지 않는다.
- **Selector 의 2 단계**: 결정론 필터 단계가 50 → 10~15 개로 줄여주므로,
  LLM 컨텍스트가 작아지고 비용/속도가 보존된다. LLM 은 우선순위만 정한다
  (도구를 직접 호출하지 않으니 LLM 이 hallucinate 한 도구가 실행될 위험 없음).
- **Executor 의 어댑터 패턴**: 도구마다 출력 포맷이 다 다르므로, 새 도구를
  추가하는 비용 = YAML 1 개 작성 (혹은 어댑터 클래스 1 개) 수준이다.
- **Analyzer 의 Case A/B/C**: 로컬 LLM 의 컨텍스트 길이 제약을 코드 흐름에
  녹였다. Volatility pslist 같은 대용량 출력을 LLM 에 통째로 넣지 않는다.
- **Reporter 의 3 포맷 동시 출력**: 분석가의 워크플로우 — 터미널에서 보고,
  JSON 으로 후속 처리하고, Markdown 으로 보고서에 붙인다.

### 왜 로컬 LLM (Ollama) 인가

- 포렌식 증거는 외부 API 로 보내면 안 되는 경우가 많다 (사내 사고, 격리 랩).
- 도구별 의심 지표는 RAG (`suspicious_indicators` 섹션) 로 주입할 수 있어,
  도메인 지식 자체는 모델이 아닌 YAML 에 있다.
- 비용/속도/JSON 신뢰성 트레이드오프는 코드가 흡수한다 — `format="json"`,
  1 회 재시도, 그래도 실패하면 룰 fallback.

---

## 도구 메타데이터 (RAG 의 진실 원천)

각 도구는 `tools_metadata/<tool_id>.yaml` 한 파일로 표현된다. Pydantic
스키마 (`forensicagent/tools/schema.py`) 로 strict 검증.

```yaml
tool_id: chainsaw
display_name: Chainsaw
category: log_analysis
applicable_evidence_types: [evtx_log]      # Selector 결정론 필터의 키
platform: [windows, linux, macos]
output_format: json
output_size_estimate: small                # Case A 로 라우팅
parallelizable: true
estimated_runtime: short

install_check:                              # Executor 가 prerequisites 검증
  command: "chainsaw --version"
  expected_pattern: "chainsaw"

command_templates:                          # Executor 가 build_command 에 사용
  - name: "Sigma hunt with bundled rules"
    template: "chainsaw hunt {evidence_path} -s {sigma_path} ..."
    when: "evtx 에서 알려진 위협 패턴 탐지가 필요할 때"

usage_description: |
  ... (LLM 시스템 프롬프트에 들어가는 자연어 설명)

suspicious_indicators:                      # Analyzer 의 룰 dispatch + 프롬프트
  - id: sigma_rule_hit
    pattern: "JSON 출력에 rule_name 필드가 존재하는 항목"
    severity_baseline: medium
  - id: rdp_logon_offhours
    pattern: "EventID 4624 + LogonType 10 + 비업무 시간"
    severity_baseline: high

known_false_positives:                      # LLM 시스템 프롬프트에 음성 제약
  - "관리자가 PowerShell 로 정상 작업"
```

이 YAML 한 파일이 Selector / Executor / Analyzer / LLM 프롬프트 모두를
구동한다. 새 도구를 추가하는 비용 = YAML 1 개 작성.

현재 reference 3 개: **chainsaw**, **volatility3**, **regripper**.
규모 확장 (→ 50 개) 은 사람 노가다 — 코드 변경 없이 YAML 만 추가하면 된다.

---

## 측정 (Observability)

모든 단계가 `Stopwatch` / `StageTimings` 에 ms 를 누적해 리포트에 박힌다.
"수치/성능을 처음부터 끝까지 측정 가능하게" 라는 설계 원칙의 구현체.

각 사이클 끝에 리포트의 `stage_ms` 키에 들어가는 값:
- `scan_walk`, `scan_detect` — Scanner
- `select_filter`, `select_rank`, `select_force` — Selector
- `execute` — Executor 전체 (도구별 duration_seconds 는 ExecutionResult)
- `analyze_rules:<tool_id>`, `analyze_llm:<tool_id>` — Analyzer 도구별

JSON 리포트의 `summary.total_ms` 가 모든 stage 의 합.

---

## 현재 진행 상태

| Phase | 명세 책정 | 실제 |
|---|---|---|
| 1. 기초 인프라 (CLI / Ollama / doctor) | 2주 | ✅ 완료 |
| 2. Scanner | 1주 | ✅ 완료 |
| 3. 도구 메타데이터 스키마 + 우선 5개 | 2~3주 | ✅ 스키마 + 3개 reference |
| 4. 단일 도구 end-to-end | 2주 | ✅ 완료 (echo_tool 합성으로 검증) |
| 5. 다중 도구 확장 (5→20→50) | 3~4주 | ⏳ 코드는 완성, YAML 3개 |
| 6. 평가 / 튜닝 | 2주 | ⏳ 미시작 |

**커밋 타임라인**

| Commit | 내용 |
|---|---|
| `cf867c7` | refactor: pivot from RAG chatbot to forensicagent CLI — 챗봇 폐기, 재사용 자산 (observability, vector_store, embedder, crawler) 만 forensicagent/ 로 이전 |
| `4c53835` | feat: Phase 1 + Scanner + RAG TODOs — pyproject, Typer CLI, Ollama 래퍼, doctor, Scanner, rag/{vector_store,embedder} TODO 채움 |
| `af437ce` | feat: Phase 3-5 — Pydantic 도구 스키마 + 3 YAML, Selector, Executor, Analyzer, Reporter, CLI 본 파이프라인 연결 |
| `659f820` | feat: sample.txt ingestion pipeline (4 stages, parallel) — Stage 1 크롤 + Stage 3 RAG + Stage 2/4 LLM 추출 |
| `601d0c7` | fix: 4 ingestion bugs (PYTHONPATH / WP selector / Ollama Pydantic shape / num_ctx) |
| `5d8595b` | fix+test: Stage 2 JSON Schema 강제 + 89 단위 테스트 + Stage 4a 분석기 + HackTricks URL 매핑 |
| `cb87549` | feat: hand-written 5 EZTools YAMLs (mftecmd / evtxecmd / recmd / pecmd / amcacheparser) — 도구 풀 3 → 8 |

## 1차 인제스션 실행 결과 (2026-05-19)

`sample.txt` 1085 URL 을 처음으로 돌린 결과:

| Stage | 상태 | 산출물 |
|---|---|---|
| 1 (crawl) | ✅ 성공 | seed_docs/{cd:69, dfir:14, eztools:32, hacktricks:828} = **943 docs** |
| 3 (RAG) | ✅ 성공 | ChromaDB collections seed_*: cd=1379, dfir=598, eztools=522, hacktricks=828 = **3327 chunks** |
| 2/4a/4b (LLM) | ⏳ pending | qwen2.5:7b 가 CPU 추론 + `num_ctx=4096` 기본값 → 출력 잘림 + 호출당 1시간. 코드 수정 (`num_ctx=16384`, `num_predict=2048` 옵션 주입) 후 GPU 있는 환경에서 재시도 필요 |

발견된 한계와 처리:
- **HackTricks 도메인 이전**: `book.hacktricks.xyz` → `book.hacktricks.wiki`. URL_REWRITES 로 도메인은 맞췄지만 wiki 의 URL 구조가 달라 828개 모두 404 placeholder (105 chars). 페이지 수는 많지만 본문이 비어 RAG 컨텐츠로서의 가치는 없음. 향후 wiki 구조 매핑 필요.
- **DFIR Report WordPress selector**: 1차 시도 시 `<article>` / `<main>` 으로는 본문이 안 잡혀 424 chars placeholder 만 추출. `div.entry-content-wrapper` 선택자 추가 후 재크롤 → 평균 30K chars 정상 추출.
- **Ollama python lib 0.6.2 의 Pydantic 응답**: `client.list()` 가 dict 가 아닌 `ListResponse` 객체를 반환. `is_available()` 가 잘못 빈 모델 리스트를 만들어 경고가 났음. 양쪽 모두 지원하도록 수정.
- **subprocess PYTHONPATH**: scripts/*.py 는 패키지가 아니라 `python scripts/foo.py` 호출 시 repo root 가 sys.path 에 없음. run_all.py 가 env 에 PYTHONPATH 명시 주입하도록 수정.

---

## 빠른 시작

### 1. 의존성 설치

```bash
pip install -r requirements.txt
pip install -e .       # 'forensicagent' 명령 등록
```

### 2. Ollama 데몬 + 모델 준비

```bash
# 한 번만
ollama pull qwen2.5:14b      # 또는 llama3.1:8b 등
ollama serve                  # http://localhost:11434
```

다른 모델/엔드포인트는 env 로:
```bash
export FORENSICAGENT_LLM_MODEL=llama3.1:8b
export FORENSICAGENT_LLM_BASE_URL=http://localhost:11434
```

### 3. 환경 점검

```bash
forensicagent doctor
```

설치 안 된 의존성 / Ollama 미접속 / 포렌식 도구(volatility3, chainsaw, ...)
PATH 미등록을 모두 보여준다. 각 missing 도구 옆에 install 방법 (pip 명령
또는 다운로드 URL) 이 같이 뜬다.

### 3-A. 포렌식 도구 설치 도우미

`doctor` 가 잡은 missing 도구를 자동으로 채워주는 헬퍼:

```bash
forensicagent install                       # 인터랙티브: missing 순회하며 y/n
forensicagent install chainsaw              # 특정 도구만
forensicagent install --all                 # 자동 가능한 거 (pip + zip) 한 번에
```

- **pip 가능** (`volatility3`, `binwalk`) → `pip install <pkg>` 실행
- **zip 다운로드** (`chainsaw`) → GitHub releases 에서 받아
  `~/.forensicagent/tools_bin/<tool>/` 로 풀고 `doctor` 의 PATH 검색에 자동 등록
- **수동 설치 필요** (`yara`, `exiftool`, `tshark`, `plaso`, `regripper`,
  `strings`, `tcpdump`) → 다운로드 URL + `curl` 예시를 출력
  (라이선스 마법사 / MSVC Build Tools / 버전 매번 바뀌는 URL 등이라 자동 불가)

zip 도구는 PATH 에 추가 안 해도 forensicagent 가 알아서 발견한다 (
`~/.forensicagent/tools_bin/*/` 을 자체 검색).

### 4. 분석 실행 — 두 가지 방식

#### (A) 인터랙티브 REPL — 탐색적 분석

```bash
cd /path/to/evidence
forensicagent                          # 인자 없이 + TTY 면 자동 REPL 진입
# 또는 명시적으로
forensicagent shell --path /case-03

# REPL 안에서
forensic> /help                        # 슬래시 명령 목록
forensic> /scan                        # Scanner
forensic> /plan                        # Selector
forensic> /run                         # Executor
forensic> /analyze                     # Analyzer
forensic> /report                      # Reporter (JSON+MD)
forensic> /auto                        # scan -> plan -> run -> analyze -> report 한 번에
forensic> /show findings               # 직전 결과 다시 보기
forensic> /set no_llm true             # 옵션 토글
forensic> /quit

# 자연어도 가능 (LLM 가용 시 — 첫 호출 5~20초)
forensic> 이 폴더 스캔하고 빠른 도구만 돌려줘
forensic> 발견된 high severity 만 다시 보여줘
```

REPL 의 자연어 라우터는 입력을 `{"actions":[...], "message":"..."}` JSON 으로
변환해 같은 슬래시 핸들러를 호출한다. `--no-llm` 또는 Ollama 부재면 슬래시
명령 모드로 자동 폴백.

#### (B) One-shot 파이프라인 — 배치 / CI

```bash
forensicagent --auto                   # 승인 없이 자동
forensicagent --quick                  # estimated_runtime: short 만
forensicagent --tools chainsaw,volatility3   # 특정 도구 강제
forensicagent --dry-run                # 계획만 출력
forensicagent --no-llm                 # 결정론만 (Selector/Analyzer LLM off)
forensicagent --path /case-03 --output-dir /reports
```

> **결정 규칙**: 인자 없이 + TTY = REPL. 플래그 하나라도 있거나 stdin 이
> 파이프 = one-shot. `forensicagent shell` 은 무조건 REPL.

#### 보조 명령

```bash
forensicagent tools list               # 사용 가능한 도구
forensicagent tools info chainsaw      # YAML 상세
forensicagent doctor                   # 환경 점검
forensicagent --version
```

LLM 이 없어도 (Ollama 미설치) `--no-llm` 으로 결정론적으로 돌릴 수 있다 —
Selector Stage 2 + Analyzer LLM 만 건너뛰고 룰 매처는 그대로 작동.

---

## 도구 추가하기

```bash
# 1. YAML 작성
$EDITOR tools_metadata/yara.yaml

# 2. 검증
python -c "from forensicagent.tools import load_tool; print(load_tool('tools_metadata/yara.yaml'))"

# 3. 끝. CLI 가 다음 실행 때 자동으로 픽업.
```

기본 `GenericAdapter` 로는 부족하다면 (예: 도구 출력이 매우 특이한 포맷)
어댑터 서브클래스를 만들어 `register_adapter("yara", YaraAdapter)` 호출.

---

## 프로젝트 구조

```
forensicagent/
├── cli/                  # Typer 진입점, Rich UI, doctor
│   ├── main.py           # 전 파이프라인 default 명령
│   ├── doctor.py         # 환경 점검
│   └── ui.py             # render_inventory, human-readable size
├── scanner/              # Layer 1 — CWD 증거 식별
│   ├── detectors.py      # magic / ext / filename / parent dir 시그니처
│   ├── scanner.py        # 깊이 제한 BFS, 심볼릭 미추적, 헤더만 읽음
│   └── types.py          # Evidence, Inventory
├── selector/             # Layer 3 — 도구 선택 (2단계)
│   ├── filter.py         # Stage 1 결정론
│   ├── llm_rank.py       # Stage 2 LLM
│   └── selector.py       # 오케스트레이션 + --quick/--tools
├── executor/             # Layer 4 — 도구 실행
│   ├── adapter.py        # GenericAdapter + register_adapter
│   ├── runner.py         # subprocess + timeout + 파일 저장
│   └── executor.py       # ThreadPool / serial 라우팅 + Rich Progress
├── analyzer/             # Layer 4 — 의심항목 추출
│   ├── rules.py          # id 기반 specific matcher + fallback
│   ├── llm_extract.py    # format=json + severity 가이드라인
│   └── analyzer.py       # Case A/B/C 분기 + dedup
├── reporter/             # Layer 5 — 리포트
│   ├── builder.py        # 단계 결과를 Report 로 묶기
│   ├── terminal.py       # Rich 출력
│   ├── json_out.py       # JSON 직렬화
│   ├── md_out.py         # Markdown 직렬화
│   └── reporter.py       # 오케스트레이션
├── rag/                  # 도구 메타데이터 ChromaDB (lookup-heavy)
│   ├── vector_store.py   # PersistentClient + cosine hnsw
│   └── embedder.py       # SentenceTransformer + OpenAI 라우팅
├── llm/                  # Ollama 클라이언트
│   └── ollama_client.py  # chat / json_chat (재시도 + 예외 분리)
├── observability/        # cross-cutting
│   └── metrics.py        # Stopwatch / StageTimings / percentile
├── tools/                # 도구 메타데이터 스키마/로더
│   ├── schema.py         # Pydantic ToolMetadata
│   └── loader.py         # load_tool, load_all_tools
├── config.py             # env-override 가능한 전역 설정
├── __init__.py           # __version__
└── __main__.py           # `python -m forensicagent`

tools_metadata/           # 도구 YAML (사용자가 손으로 채움)
├── chainsaw.yaml
├── volatility3.yaml
└── regripper.yaml

scripts/crawlers/         # 도구 카탈로그 보강용 (TryHackMe, CyberDefenders,
                          # DFIR Report, EZTools, HackTricks)
seed_docs/                # 크롤러 산출물 (도메인 자료)
```

---

## 평가 / 측정 계획 (Phase 6)

명세대로:

1. **도구 선택 precision/recall** — 30~50 개 (증거, 정답 도구 셋) 쌍을 직접
   만들고, Selector 출력과 비교.
2. **의심항목 탐지율** — 공개 CTF (CyberDefenders, BlueTeamLabs) 의 분석가
   workup 과 자동 finding 을 매칭, recall 측정.
3. **False Positive 비율** — `severity ≥ medium` 으로 보고된 finding 중
   실제 정상이었던 비율.
4. **실행 시간** — JSON 리포트의 `summary.total_ms` 와 `stage_ms` 분포.

비교 베이스라인:
- (A) 분석가가 수동으로 50 개 도구 다 돌렸을 때 (시간/품질)
- (B) 단순 "선택 없이 전부 자동" (시간/false positive)
- (우리) 그 사이 어디에 위치하는지

---

## 알려진 한계

- **로컬 LLM JSON 신뢰성**: `json_chat` 이 1 회 재시도하고 그래도 실패하면
  `JsonRetryFailed` 를 던지는데, 호출자(Selector/Analyzer)가 잡아 룰
  fallback 으로 분기한다. 그래도 LLM 의 우선순위 보강이 빠지는 경우는 생긴다.
- **컨텍스트 길이**: Case C (>4 MB) 에서는 LLM 을 아예 부르지 않는다. 자연어
  보강 없이 룰만 작동. 더 큰 모델 (128K) 도입 시 재조정 가능.
- **도구 metadata 의 인덱싱 부담**: 50 개 도구 YAML 은 사람 노가다이고, 이
  부분은 코드로 해결 못 한다. (그래서 `scripts/crawlers/` 가 도메인 자료
  수집을 보조하지만, YAML 변환은 수작업.)
- **specialized adapter 부재**: 현재 모든 도구가 `GenericAdapter`. 출력
  포맷이 매우 비표준인 도구는 서브클래스가 필요할 수 있다.
- **단위 테스트 부재**: `tests/` 디렉토리는 비어 있다. 통합 동작은 합성
  evidence + echo_tool 어댑터로 검증했지만, 회귀 방지용 테스트는 미작성.

---

## 다음 세션에서 시작할 만한 것

자세한 다음-액션 메모는 [`CLAUDE.md`](CLAUDE.md) 의 "다음 세션 재개 노트"
섹션 참조.

짧게:
1. 도구 YAML 3 → 10~20 개 확장 (yara, plaso/log2timeline, tshark, exiftool,
   binwalk, strings, ... 우선)
2. `tests/` 작성 — scanner detectors, selector filter, analyzer rules 의
   단위 테스트
3. 도구 출력 포맷이 비표준인 도구의 specialized adapter
4. Phase 6 — 공개 CTF 데이터셋 1~2 개로 precision/recall 측정
