# forensicagent — 포렌식 자동 분류 CLI 에이전트

사용자가 포렌식 문제 디렉토리에서 `forensicagent` 를 실행하면, 로컬 LLM
(Ollama) 이 증거를 식별하고 적절한 분석 도구를 RAG 로 선별·실행해서
도구별 의심 항목을 자동 추출, 리포트로 제시한다.

분석가가 50+ 개 포렌식 도구를 다 외워서 돌릴 필요 없이, **"증거 → 도구 →
의심 항목 → 리포트"** 의 triage 사이클을 한 명령으로 끝내는 것이 목표.

---

## 시스템 구성 (6 모듈 + 측정)

| 모듈 | 역할 | 디렉토리 |
|---|---|---|
| CLI | Typer + Rich 진입점, 인터랙티브 UX, 모듈 오케스트레이션 | `forensicagent/cli/` |
| Scanner | CWD 재귀 스캔. magic bytes + 확장자 + 파일명 패턴으로 증거 식별 | `forensicagent/scanner/` |
| Selector | 2단계 하이브리드. (1) 결정론 메타데이터 필터 → (2) LLM 우선순위 | `forensicagent/selector/` |
| Executor | subprocess 격리 실행, 타임아웃, 도구별 어댑터, 결과 파일 저장 | `forensicagent/executor/` |
| Analyzer | 도구 출력 → suspicious_indicators 룰 + LLM 하이브리드 추출 | `forensicagent/analyzer/` |
| Reporter | Rich 터미널 + JSON/MD 동시 저장 | `forensicagent/reporter/` |
| RAG | 도구 YAML 메타데이터 인덱싱 + lookup (ChromaDB) | `forensicagent/rag/` |
| (cross-cutting) | Stopwatch, StageTimings, percentile — 모든 모듈에서 측정 | `forensicagent/observability/` |

각 모듈은 다른 모듈의 출력 dict 를 입력으로 받는 순수 함수 위주이고,
**무거운 의존성 (ollama 클라이언트, magic, sentence-transformers, chromadb)
은 함수 내부에서 lazy import** 한다 (CLI 부팅 속도 보존).

---

## 흐름

```
$ cd ~/ctf/forensics-challenge-03/
$ forensicagent

CWD 표시 → Scanner (증거 인벤토리)
        → Selector (실행 계획)        ─ 사용자 승인
        → Executor (도구 N 개 실행, 진행 상황 실시간)
        → Analyzer (도구별 의심 항목 추출, 병렬 가능)
        → Reporter (터미널 + JSON + MD)
```

전 사이클의 시간/카운트/severity 분포는 observability 가 한 곳에 모아
리포트에 그대로 영속화된다 (메모리 원칙: **수치/성능은 처음부터 끝까지
측정 가능하게**).

---

## 디렉토리 인덱스

| 경로 | 책임 |
|---|---|
| `forensicagent/` | 런타임 패키지 (6 모듈 + observability + rag) |
| `forensicagent/config.py` | env-override 가능한 전역 설정 (Ollama URL, 임베딩 모델, 타임아웃, 경로) |
| `scripts/crawlers/` | 도구 메타데이터 작성용 도메인 자료 크롤러 (TryHackMe, CyberDefenders, DFIR Report, EZTools, HackTricks) |
| `tools_metadata/` | 50+ 개 도구의 YAML 메타데이터 (사람이 작성). 인덱싱 입력 |
| `seed_docs/` | 크롤러 산출물 (보조 도메인 자료 — 도구 카탈로그 보강용) |

---

## Ollama 로컬 LLM 제약 (반드시 인지)

- **JSON 출력 신뢰성**: `format: "json"` 강제. 파싱 실패 시 1회 재시도 → 룰 fallback.
- **컨텍스트 길이**: 8K~128K. Volatility/대용량 출력은 사전 필터링 후 LLM 투입.
- **속도**: 8B 기준 분석 1건당 5~30초. 도구 7 개면 1~5분 — 병렬 + spinner UX 로 체감 개선.
- **도메인 지식 약함**: 포렌식 지식은 RAG (suspicious_indicators) 로 보강.
- 모델 후보: `qwen2.5:14b` (KR + 추론 균형), `llama3.1:8b/70b`, `mistral-nemo:12b`.

---

## 실행 방법 (Phase 1 완료 후 활성화)

```bash
pip install -r requirements.txt
pip install -e .            # (Phase 1 에서 pyproject.toml 작성 후)

forensicagent              # 인터랙티브 분석 (기본)
forensicagent --auto       # 승인 없이 자동
forensicagent --quick      # estimated_runtime: short 만
forensicagent --tools t1,t2 # 특정 도구 강제
forensicagent --dry-run    # 계획만 출력
forensicagent doctor       # 환경 점검 (도구 설치 여부)
forensicagent tools list   # 사용 가능한 도구
```

---

## 비목표

이 프로젝트가 **하지 않는** 것:
- 침해 사고 전체 시나리오 자동 재구성 (분석가가 리포트 보고 판단)
- 도구 결과 간 상관관계 분석
- 새로운 익스플로잇/악성코드 탐지 (알려진 의심 패턴만)
- 증거 무결성 검증 (격리 랩 가정)
- 실시간 모니터링 (사후 분석 전용)

---

## 현재 상태 (2026-05-21, Phase 1-5 완료 + 1차 인제스션 + 인터랙티브 REPL)

Phase 1-5 의 모든 코드가 들어왔고 전 파이프라인이 end-to-end 로 동작한다
(Scanner → Selector → Executor → Analyzer → Reporter, JSON + MD 리포트
생성까지). README.md / understand_code.md / PROJECT_TOUR.md 가 사용자/협업자용
정식 문서.

**2026-05-21 추가**: Claude Code 식 인터랙티브 REPL 을 얹었다. 진입점은
2 갈래 — 인자 없이 + TTY 면 `forensic>` 셸 진입 (`cli/repl.py` 의 슬래시
명령 디스패처), 플래그 있거나 stdin 이 파이프면 기존 one-shot 파이프라인.
자연어 입력은 `cli/nl_router.py` 가 `json_chat(format_schema=...)` 로
`{"actions":[...]}` JSON 으로 변환해 같은 슬래시 핸들러를 호출한다 (`--no-llm`
또는 Ollama 부재면 자동 폴백).

추가로 sample.txt (1085 URL) 의 1차 인제스션을 실행했다 — Stage 1 (크롤) +
Stage 3 (RAG) 는 성공, Stage 2/4 (LLM 추출) 는 Ollama 가 GPU 없는 환경
이라 진행 중인 채로 백그라운드 큐에 남아 있음.

**커밋 타임라인**

| Commit | 내용 |
|---|---|
| `cf867c7` | refactor: pivot from RAG chatbot to forensicagent CLI |
| `4c53835` | feat: Phase 1 (CLI/Ollama/doctor) + Scanner + rag TODO 채움 |
| `af437ce` | feat: Phase 3-5 (Selector/Executor/Analyzer/Reporter + 3 YAML) |
| `95a327d` | docs: README + CLAUDE.md resume notes |
| `659f820` | feat: sample.txt ingestion pipeline (4 stages, parallel) |
| `601d0c7` | fix: 4 ingestion bugs (PYTHONPATH / WP selector / Ollama Pydantic / num_ctx) |
| `5d8595b` | fix+test: Stage 2 JSON Schema 강제 + 89 단위 테스트 + Stage 4a 분석기 + HackTricks URL 매핑 |
| `cb87549` | feat: 5 hand-written EZTools YAMLs - 도구 풀 3 → 8 |
| (uncommitted) | feat: 인터랙티브 REPL (cli/repl.py + session.py + nl_router.py) + docs |

**실제로 동작 검증된 흐름**
- `python -m forensicagent --help / doctor / tools list / tools info <id>`
- `python -m forensicagent --no-llm --auto --path <dir>` end-to-end 실행 →
  도구 미설치라 skipped 이지만 Reporter 가 정상 JSON+MD 생성
- 합성 `echo_tool` 어댑터로 success 경로 + Analyzer Case A 검증
- 룰 매처 (`sigma_rule_hit` specific + 키워드 AND fallback) 단위 검증
- **REPL**: `/help /status /tools /scan /plan /auto /show /quit` 슬래시 + NL
  라우터의 no_llm 폴백. 라이브 LLM 호출 검증 1회 (qwen2.5:3b @ CPU).
  Windows cp949 stdin 경계의 surrogate 인코딩 이슈는 `_strip_surrogates`
  로 방어함.

**1차 인제스션 산출물 (in seed_docs/ + ChromaDB + eval/)**

| 도메인 | 크롤 docs | RAG chunks | 상태 |
|---|---:|---:|---|
| cyberdefenders | 69 | 1,379 | ✅ 정상 |
| dfirreport | 14 | 598 | ✅ WP selector 수정 후 재크롤 |
| eztools | 32 | 522 | ✅ raw github text |
| hacktricks | 828 | **12,662** | ✅ wiki URL 매핑 수정 후 재크롤 + 재인덱싱 (95% 본문 회수) |
| **RAG 합계** | **943** | **15,161** | |

**LLM 추출 산출물**

| Stage | 결과 | 비고 |
|---|---|---|
| 2 (EZTools → YAML) | 0/32 valid | LLM 이 strict 22-필드 schema 안 따라옴. `format_schema=` 수정 후 재시도 필요 |
| 4a (CD blog → indicators) | **69/69 candidates** | 299 indicators 추출, 20개 자동 매핑 (chainsaw 15 / regripper 4 / volatility3 1) |
| 4b (DFIR → goldenset) | **14/14 cases** | Phase 6 평가용. case_summary + tools_used + ttps (MITRE) + key_iocs |
| Stage 4b 평균 추출 결과 | 3 tools / 4 ttps / 3 iocs per case | qwen2.5:7b @ CPU, 25분/건, 5.8 시간 소요 |

**도구 풀 (tools_metadata/)**

| 도구 | 카테고리 | indicators | 작성자 |
|---|---|---:|---|
| chainsaw | log_analysis | 4 | 사람 (Phase 3-5 reference) |
| volatility3 | memory_analysis | 4 | 사람 |
| regripper | registry_analysis | 4 | 사람 |
| mftecmd | disk_analysis | 5 | 사람 (밤샘 보강) |
| evtxecmd | log_analysis | 6 | 사람 |
| recmd | registry_analysis | 7 | 사람 |
| pecmd | disk_analysis | 5 | 사람 |
| amcacheparser | registry_analysis | 5 | 사람 |
| **합계** | **8 도구** | **40** | |

**테스트 커버리지**

- `tests/` 89 통과 (1.94s): detectors (46) + filter (11) + rules (11) + chunks (21)
- LLM / 네트워크 / GPU 의존성 없는 결정론 단위 테스트만

**남은 큰 덩어리** (코드 아닌 노가다 / 실험)
- Stage 2/4 LLM 추출 — 백그라운드 큐 진행 중이지만 CPU 추론이라 비현실적
  소요 (호출당 ~1시간). GPU 환경에서 `num_ctx=16384` 설정 후 재실행 필요.
- HackTricks wiki URL 구조 매핑 (828 docs 의 실제 본문 회수)
- 도구 YAML 3 → 50 개 (Stage 2 가 성공하면 +32 자동, 나머지는 사람 손)
- `tests/` 비어 있음 — 단위 테스트 미작성
- 모든 도구가 `GenericAdapter` 사용. 출력이 매우 비표준인 도구는 specialized
  adapter 필요할 수 있음
- Phase 6: CyberDefenders / BlueTeamLabs 평가 데이터셋 실험

---

## 다음 세션 재개 노트

다음 세션을 열면 바로 다음 중 하나로 진입하면 된다 (우선순위 순):

0. **REPL 자체 다듬기** (가벼움). 라이브 LLM 호출은 1회 검증됨 (영어 + 한국어
   둘 다 `/scan` 액션으로 잘 라우팅). 추가로 더 다듬을 수 있는 것:
   - 도메인-특화 시스템 프롬프트 보강 (지금은 일반적 — "memory_dump 가 보이면
     volatility3 우선 추천" 같은 휴리스틱 주입 가능)
   - `prompt_toolkit` 로 입력 히스토리/탭 완성/멀티라인 (현재 plain `input()`)
   - `/show` 가 LLM 으로 자연어 요약 한 줄 만들어주기
   - `cli/repl.py` + `cli/nl_router.py` 단위 테스트 (`OllamaClient.json_chat`
     mock 으로). 핸들러 라우팅 + 인자 파싱 + 에러 복귀 확인.

1. **도구 YAML 확장**. 현재 `tools_metadata/{chainsaw,volatility3,regripper}.yaml`
   3 개. 다음 후보 (포렌식 도메인 가치 높은 순):
   - `yara` — 메모리 / 파일 시그니처 매칭. `applicable_evidence_types:
     [memory_dump, disk_image, unknown]` 다양.
   - `plaso` (log2timeline.py + psort.py) — 슈퍼 타임라인.
   - `tshark` — pcap 분석. wireshark 대체 CLI.
   - `exiftool` — 파일 메타데이터, 디스크 이미지 안의 사진 등.
   - `binwalk` — 펌웨어/디스크 임베디드 객체 추출.
   - `strings` + `floss` — 바이너리 문자열 추출.
   - `KAPE` — Windows artifact collector.
   - `bulk_extractor` — 디스크 이미지에서 PII/네트워크 정보.
   - `MFTECmd` (EZTools) — NTFS MFT 파싱.
   - `RECmd` (EZTools) — 레지스트리 batch.
   YAML 1 개 추가 = 코드 변경 없이 CLI 가 자동 인지. `scripts/crawlers/` 에
   이미 EZTools / HackTricks 크롤러가 있어 도메인 자료는 끌어올 수 있다.

2. **단위 테스트 작성** (`tests/` 디렉토리).
   - `tests/test_detectors.py` — 9 magic 시그니처 + 정규식 매처 (bytes
     fixture 로).
   - `tests/test_filter.py` — 합성 Inventory + ToolMetadata 로 evidence_type
     교집합 검증.
   - `tests/test_rules.py` — `sigma_rule_hit` specific matcher, `run_key_unusual_binary`,
     fallback substring matcher (이미 직접 검증 통과한 케이스를 픽스 처리).
   - `tests/test_runner.py` — `subprocess.Popen` 을 mock 또는 `cmd /c echo` /
     `bash -c "sleep 999"` 로 timeout 분기 확인.
   - `pyproject.toml` 에 `[tool.pytest.ini_options]` 이미 설정됨.

3. **specialized adapter 추가**. 출력이 비표준인 도구가 나오면
   `executor/adapter.py` 의 `GenericAdapter` 를 상속해 `parse_output`
   오버라이드. `register_adapter("tool_id", MyAdapter)` 로 부팅 시 등록 —
   `forensicagent/__init__.py` 에 등록 hook 한 줄 추가하는 형태가 깔끔.

4. **Phase 6 평가**. CyberDefenders Blue Team Labs 같은 공개 케이스 1~2 개
   다운로드해서 `forensicagent --auto --path <case>` 돌리고, JSON 리포트의
   findings 를 분석가 workup 과 매칭. precision/recall 30~50 건 골든 셋
   만들기.

**자주 잊는 것 / 함정**

- 사용자 머신 (Windows) 의 콘솔 codepage 는 **cp949**. Rich 출력이 `|`
  pipe 로 리다이렉트되면 한글이 깨진다. 정상 동작이고 인터랙티브
  터미널에서는 멀쩡함. em-dash (`—`) 같은 비-cp949 문자를 출력 경로 (Table
  title 등) 에 넣으면 `UnicodeEncodeError` 로 실제 크래시 — docstring 안에는
  자유롭게 써도 됨.
- `forensicagent doctor` 는 ollama / sentence-transformers / python-magic /
  chromadb 가 다 깔려야 OK. 그냥 코드 import 검증만 하려면 `pip install
  pyyaml pydantic typer rich` 만 있으면 충분. 전 파이프라인 `--no-llm` 으로는
  돌아간다.
- `TOOLS_METADATA_DIR` 의 우선순위: env var → `~/.forensicagent/tools` →
  repo cwd 의 `tools_metadata/`. CLI 의 fallback 로직이 자동.
- `git log --oneline cf867c7..HEAD` 가 forensicagent 작업분 전체.

**최근 메모리 (외부 메모리 시스템)**
- `project_forensicagent_pivot.md` — 프로젝트 전환 (2026-05-19)
- `feedback_metrics.md` — "수치/성능을 처음부터 끝까지 측정 가능하게" 원칙
- `project_data_collection_sprint.md` — TryHackMe 수집 sprint (5/25 마감,
  승환 담당). 도구 메타데이터 작성 보조로 재활용 가능.
