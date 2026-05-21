# forensicagent — 사용자 가이드

> "이 도구가 지금 뭘 할 수 있고, 어떻게 켜고, 어디까지 검증됐는가" 를
> 한 문서에 정리한 가이드. 코드 구조와 설계 의도는 [`PROJECT_TOUR.md`](PROJECT_TOUR.md),
> 짧은 시나리오는 [`README.md`](README.md), 진행 상태/명세는 [`CLAUDE.md`](CLAUDE.md).

---

## 0. 한 줄 정의

**"폴더 가리키면, 그 안의 파일들을 자동 분류해서, 적절한 보안 도구를
선별·실행하고, 의심 사항을 리포트로 정리해주는 CLI 에이전트."**

같은 5 단계 파이프라인 (Scanner → Selector → Executor → Analyzer → Reporter)
이 폴더 안 내용에 따라 다른 도구 그룹을 호출한다.

---

## 1. 두 가지 분석 분야 (하이브리드)

| 폴더에 뭐가 있느냐 | 호출되는 도구 | 찾는 것 |
|---|---|---|
| `.evtx` `.raw` `NTUSER.DAT` `.pcap` `$MFT` 등 | chainsaw, volatility3, regripper, mftecmd, evtxecmd, recmd, pecmd, amcacheparser (8 개) | **침해 흔적 (DFIR)** — RDP 비업무 로그온, 의심 프로세스, persistence, brute force |
| `.py` `.js` `.ts` `.jsx` `.go` `.java` 등 | **bandit, semgrep, gitleaks** (3 개) | **코드 취약점 (SAST)** — SQL 인젝션, 시크릿 노출, weak crypto, shell injection |
| 둘 다 섞여 있음 | 양쪽 다 자동 매칭 | 둘 다 |
| 아무것도 매칭 안 됨 | 0 개 → "적용 가능한 도구 없음" | — |

도구는 `tools_metadata/*.yaml` 한 파일 = 한 도구로 등록되어 있고, 새 도구는
YAML 한 개 추가만으로 시스템에 자동 인지된다 (코드 변경 0).

---

## 2. 한 명령이 일으키는 일 — 5 단계 흐름

`python -m forensicagent --auto --path <폴더>` 한 줄이 만드는 흐름.

```
1. Scanner    폴더 재귀 스캔 (깊이 5)
              파일 1개씩: magic bytes → 확장자 → 파일명 → 부모 디렉토리 순서로 분류
              결과: Evidence 객체 N개 (type, path, size, confidence)
              ─────────────────────────────────────────────────
2. Selector   Stage 1 (결정론): tool.applicable_evidence_types ∩ inventory.evidence_types
              Stage 2 (LLM): 후보의 우선순위 보강 + 자연어 reason (Ollama json_chat, 옵션)
              결과: Plan = 선택된 도구 N개 + 각각의 target_evidence
              ─────────────────────────────────────────────────
3. Executor   parallelizable=true → ThreadPool, 아니면 직렬
              각 도구 × 각 evidence 파일 = subprocess (shell=False, 타임아웃)
              stdout/stderr 는 메모리가 아닌 파일 (raw/01_chainsaw_security.stdout 식)
              결과: ExecutionBundle (success / failed / timeout / skipped 분류)
              ─────────────────────────────────────────────────
4. Analyzer   도구 출력 크기 따라 Case A/B/C 분기
                Case A (≤100KB): rules + LLM 둘 다 적용 후 머지
                Case B (≤4MB):   rules + 짧은 LLM 요약
                Case C (>4MB):   rules only (LLM 컨텍스트 초과 방지)
              rules: tool.suspicious_indicators 의 id 별 specific matcher
                     (현재 9개: sigma_rule_hit / bandit_issue / gitleaks_secret 등),
                     미등록 id 는 키워드 AND fallback
              결과: Finding 리스트 (severity / category / title / description / source_file)
              ─────────────────────────────────────────────────
5. Reporter   터미널 Rich 표 + JSON (기계 가독) + Markdown (사람 가독)
              저장 위치: forensicagent_output/report_YYYYMMDD_HHMMSS.{json,md}
              raw/ 디렉토리에 도구 stdout/stderr 그대로 보존
              모든 단계의 소요 ms 가 stage_ms 에 누적되어 JSON 으로 영속화
```

각 단계는 dataclass 한 묶음만 다음 단계로 넘긴다 (순수 함수 + 데이터 흐름).
어느 단계든 stub 으로 갈아끼워도 다른 단계의 코드는 안 깨진다.

---

## 3. 세 가지 진입 방식

### (A) 인터랙티브 REPL — 탐색적 분석 (권장)

```powershell
python -m forensicagent          # 인자 없이 + TTY → 자동 REPL 진입
# 또는 명시적으로
python -m forensicagent shell

forensic> /help                  # 16 개 슬래시 명령 목록
forensic> /scan ./mycase         # 단계별 진행
forensic> /plan
forensic> /run
forensic> /report

forensic> /auto                  # 5 단계 한 번에

forensic> 이 폴더 분석해줘       # 자연어 (LLM 라우터가 /scan + /plan + /run 시퀀스로 변환)
forensic> 발견된 high 만 다시 보여줘
forensic> /quit
```

REPL 의 자연어 입력은 Ollama `json_chat(format_schema=...)` 으로
`{"actions":[...], "message":"..."}` JSON 을 강제 받아 같은 슬래시 핸들러를
호출한다. `--no-llm` 또는 Ollama 부재면 슬래시 명령 모드로 자동 폴백.

### (B) One-shot 파이프라인 — 스크립트 / CI

```powershell
python -m forensicagent --auto --path /case                      # 5 단계 자동
python -m forensicagent --auto --path /case --no-llm             # LLM 없이 결정론
python -m forensicagent --dry-run --path /case                   # 계획만 보고 실행 X
python -m forensicagent --tools bandit,chainsaw --path /case     # 특정 도구만 강제
python -m forensicagent --quick --path /case                     # short-runtime 도구만
python -m forensicagent --auto --path /case --output-dir /reports
```

> **결정 규칙**: 인자 없이 + TTY = REPL. 플래그 하나라도 있거나 stdin 이
> 파이프 = one-shot. `forensicagent shell` 은 항상 REPL.

### (C) 보조 명령

```powershell
python -m forensicagent doctor               # 환경 점검 (의존성/Ollama/도구 PATH)
python -m forensicagent install              # 미설치 도구 인터랙티브 설치
python -m forensicagent install --all        # pip+zip 가능한 거 자동 설치
python -m forensicagent install bandit       # 특정 도구만
python -m forensicagent tools list           # 도구 카탈로그
python -m forensicagent tools info chainsaw  # 도구 YAML 상세
```

---

## 4. 도구 설치 도우미 (`forensicagent install`)

`doctor` 가 잡은 missing 도구를 registry 기반으로 채워준다. 3 가지 종류:

| kind | 도구 | 동작 |
|---|---|---|
| **pip** | volatility3, binwalk, **bandit**, semgrep | `pip install <pkg>` subprocess 호출 |
| **zip** | **chainsaw** | GitHub `/releases/latest/download/` 에서 받아 `~/.forensicagent/tools_bin/<tool>/` 로 풀고 자동 발견 |
| **manual** | plaso, yara, exiftool, tshark, regripper, gitleaks, strings, tcpdump | 라이선스/MSVC/Wireshark 인스톨러/버전 매번 바뀌는 URL 등으로 자동 불가. URL + `curl` 예시만 안내 |

`doctor` 가 보여주는 모습:

```
|   OK   | bandit                  | ...\Scripts\bandit.EXE
|   OK   | chainsaw                | ~/.forensicagent/.../chainsaw.exe
|  miss  | semgrep                 | not installed - `forensicagent install semgrep` (pip semgrep)
|  miss  | gitleaks                | not installed - 수동: https://github.com/gitleaks/gitleaks/releases
```

zip 으로 설치된 도구는 PATH 추가 없이도 forensicagent 가 알아서 발견한다
(`~/.forensicagent/tools_bin/*/` 을 자체 검색).

---

## 5. 처음 켜는 5 분 코스

```powershell
# 1. 의존성 (한 번만)
pip install -r requirements.txt
pip install -e .

# 2. (Windows) libmagic 백엔드
pip install python-magic-bin       # requirements.txt 에 이미 있음

# 3. Ollama (LLM 쓸 거면)
ollama pull qwen2.5:3b             # MX450 2GB 같은 작은 GPU 에 들어감
$env:FORENSICAGENT_LLM_MODEL = "qwen2.5:3b"   # config 기본 14b 를 override

# 4. 환경 점검
python -m forensicagent doctor
# → core 5/5 OK 떠야 정상

# 5. 코드 보안 도구 1개 설치
python -m forensicagent install bandit

# 6. 진짜로 한 번 돌려보기 — forensicagent 자체 코드를 SAST 분석
python -m forensicagent --no-llm --auto --path forensicagent/cli

# 결과:
#   Scanner: 8 .py 식별
#   Selector: bandit + semgrep + gitleaks 자동 선택
#   Executor: bandit 8 success, 나머지 skipped (미설치)
#   Analyzer: 3 finding (B310 MEDIUM / B404 LOW / B603 LOW)
#   Reporter: forensicagent_output/report_*.json + .md
#   총 4 초
```

---

## 6. 현재 동작 상태 (정량)

| 메트릭 | 수치 | 비고 |
|---|---:|---|
| 코드 패키지 | 47 .py / 5,076 LOC | `forensicagent/` |
| 도구 풀 | **11 YAML** | 8 forensic + 3 code-security |
| Indicator 패턴 | **46** | YAML 의 suspicious_indicators 합 |
| Analyzer specific matcher | **9** | rules.py 의 `_SPECIFIC_MATCHERS` |
| REPL 슬래시 명령 | 16 | |
| 단위 테스트 | **89/89 통과 (0.53s)** | `pytest tests/` |
| 설치 검증된 도구 | **5** | vol, chainsaw, binwalk, bandit, file |
| RAG 인덱스 | 15,161 chunks | 4 컬렉션 (HackTricks 12,662 위주) |
| Git 커밋 | 16 | |

### 라이브 검증된 시나리오 (이번 세션)

| 시나리오 | 결과 |
|---|---|
| **bandit 자동 설치 → forensicagent/cli SAST 분석** | ✅ 3 finding (B310/B404/B603) 정확히 추출, JSON+MD 리포트 저장 |
| **REPL 자연어 입력** ("please scan this folder" / "이 폴더 스캔해줘") | ✅ LLM 라우터가 `/scan` 액션 JSON 으로 변환 → 정상 실행 (영어 + 한국어) |
| **`forensicagent install chainsaw` zip 자동 다운** | ✅ `~/.forensicagent/tools_bin/chainsaw/chainsaw/chainsaw.exe` 추출 → doctor OK |
| **doctor 핵심 의존성** | ✅ 5/5 OK (python, chromadb, embedding, libmagic, ollama) |

### 아직 안 한 것

- **진짜 포렌식 evidence (.evtx 또는 .raw) 로 chainsaw/volatility3 라이브 실행 검증**: 0 회.
  도구는 깔렸고 코드 경로는 동작 검증됐지만, 실제 침해 사고 evidence (수십 MB
  EVTX, GB 단위 메모리덤프) 로 한 번도 안 돌렸음. CTF 챌린지 1 개 받아서
  `forensicagent --auto --path <case>` 1 회 = "데모 종료" 기준 (PROJECT_TOUR §7-3).
- **Phase 6 평가 스크립트**: `eval/goldenset/*.json` 14 case 의
  `tools_used` / `evidence_types_present` 와 forensicagent 출력의
  precision/recall 비교. 미작성.
- **specialized adapter**: 모든 도구가 GenericAdapter. 출력 포맷이 매우 비표준인
  도구가 나오면 서브클래스가 필요할 수 있음.

---

## 7. 자주 발생하는 문제 / 해결

| 증상 | 원인 | 해결 |
|---|---|---|
| `forensicagent` 명령 안 먹음 | shim 미등록 또는 PATH 문제 | `pip install -e .` 또는 `python -m forensicagent` 사용 |
| `doctor` 가 libmagic FAIL | Windows 백엔드 미설치 | `pip install python-magic-bin` (requirements.txt 에 이미 있음) |
| `doctor` optional 도구 다수 miss | 포렌식/SAST 도구 미설치 | `forensicagent install` (인터랙티브) 또는 `install --all` |
| `forensicagent` 쳤는데 REPL 안 뜨고 파이프라인이 돔 | 플래그가 끼었거나 stdin 이 파이프 (TTY 아님) | 인자/리다이렉트 빼고 `forensicagent` 만, 또는 `forensicagent shell` |
| REPL 에서 자연어 입력시 "no_llm 모드" 뜸 | `--no-llm` 으로 진입했거나 `/set no_llm true` 였음 | `/set no_llm false` |
| 한글 출력이 깨짐 (`���`) | cp949 codepage + pipe 리다이렉트 | 정상 (직접 터미널에서는 멀쩡). 또는 `chcp 65001` |
| 코드 SAST 가 0 finding | (1) 진짜 깨끗하거나 (2) 출력 JSON 파싱 실패 | `forensicagent_output/raw/*.stdout` 직접 확인. parser 가 잡지 못한 형태면 `analyzer/rules.py` 매처 추가 |
| `--no-llm --dry-run` 도 한글이 안 보임 | Rich Console 이 redirect 감지 시 ASCII fallback | 정상. 인터랙티브 터미널에서 직접 보면 컬러풀 |

---

## 8. 한 줄

> **"코드 폴더 가리키면 SAST 자동 분석 + 리포트" 는 ✅ 라이브 검증 끝.
> "Forensic evidence 폴더 가리키면 DFIR 자동 분석" 은 도구는 깔렸고 코드는
> 동작 검증됐지만 진짜 evidence 로는 아직 안 돌렸음.**

지금 바로 시연하려면:

```powershell
python -m forensicagent --auto --path C:\Users\user\OneDrive\Desktop\chatbot_security\forensicagent
# 47 .py 파일에 bandit 자동 실행 → finding 누적 → JSON+MD 리포트
```

이 한 줄로 끝.
