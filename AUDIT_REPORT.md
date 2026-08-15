# ForensicAgent 코드 감사 보고서

작성 기준: 현재 작업 트리의 코드와 테스트. 이 문서는 정적 코드 검토와 자동화 테스트 결과를 설명하며, 실제 사건 증거에 대한 포렌식 감정서나 탐지 성능 인증서가 아니다.

## 1. 결론

이 프로젝트는 증거 파일을 직접 판정하는 단일 탐지기가 아니라, **증거 분류 → 도구 선택 → 외부 도구 실행 → 결과 정규화·규칙 분석 → 보고서 생성**을 연결하는 자동 트리아지 오케스트레이터다.

이번 검토에서 작동 불량의 가장 큰 원인은 다음 세 가지였다.

1. 도구가 CSV·JSON을 별도 파일로 생성해도 executor가 `stdout`만 결과로 취급해 실제 분석 입력이 사라졌다.
2. 증거 타입만 맞으면 파일 형식과 관계없이 도구를 선택하고, 여러 command template 중 첫 번째 것만 실행해 잘못된 도구·플러그인이 호출될 수 있었다.
3. Analyzer가 구현되지 않은 indicator도 자연어 단어 포함 여부로 추정해 finding을 만들 수 있어 오탐 위험이 있었다.

현재 코드는 이 세 경로를 구조적으로 보완했다. 다만 이것이 “완전 탐지”를 의미하지는 않는다. 외부 도구 설치 상태, 실제 EVTX·레지스트리·메모리·NTFS 증거에 대한 검증, 위협 인텔리전스 연동, 한국어 RAG 평가 등은 여전히 별도 검증이 필요하다.

## 2. 실제 폴더 구조와 역할

```text
chatbot_security/
├─ forensicagent/
│  ├─ cli/             명령행 진입점, REPL, 세션, doctor/install, 화면 출력
│  ├─ scanner/         파일 순회, magic/확장자/이름/부모 경로 기반 증거 분류
│  ├─ tools/           도구 YAML 스키마·로더와 실행 파일 공용 resolver
│  ├─ selector/        타입+입력 형식 필터, RAG/LLM 순위, per-target RunSpec
│  ├─ executor/        adapter, 우선순위 스케줄러, subprocess, 산출물 manifest
│  ├─ analyzer/        CSV/JSON/text 스트리밍, 명시적 규칙, LLM 보조 추출
│  ├─ reporter/        통합 Report, 터미널·JSON·Markdown 출력
│  ├─ rag/             tool metadata 및 seed corpus 인덱싱·Chroma 검색
│  ├─ llm/             Ollama 호출, JSON 재시도와 오류 변환
│  ├─ observability/   단계별 시간 측정
│  └─ config.py        경로·RAG·LLM·실행 설정의 단일 진입점
├─ tools_metadata/     현재 실행 가능한 도구 정의 YAML
├─ tests/              단위·통합·회귀 테스트
├─ bench/              합성 golden set과 deterministic/RAG/LLM 순위 평가
├─ scripts/            수집 문서 가공, indicator 후보·golden set 생성 보조
├─ data/raw/           크롤러 원본 데이터
├─ seed_docs/          도메인별 정규화 RAG 문서 corpus
├─ eval/goldenset/     외부 보고서 기반 평가 자료
└─ forensicagent_output/
                         과거 실행 산출물. 현재 기본 출력 위치와는 별개
```

`data/raw`, `seed_docs`, `bench/**/raw`, `forensicagent_output`에는 이미 추적되는 파일이 다수 있다. 이들은 실행 코드가 아니며, 저장소 루트를 증거 경로로 스캔하면 일부가 분석 대상으로 오인될 수 있다. 사건별 전용 디렉터리를 `--path`로 지정하는 것이 안전하다.

## 3. 실제 5단계 데이터 흐름

```text
사용자 경로/시나리오
        │
        ▼
1. Scanner ───────────────► Inventory
        │                    파일 경로·크기·타입·탐지 근거·confidence
        ▼
2. Selector ──────────────► Plan
        │                    ToolSelection + target + 구체적 RunSpec
        ▼
3. Executor ──────────────► ExecutionBundle
        │                    status + stdout/stderr + generated artifacts
        ▼
4. Analyzer ──────────────► ToolAnalysis / Finding
        │                    rule_id·근거 excerpt·fingerprint·confidence
        ▼
5. Reporter ──────────────► 터미널 + JSON + Markdown

횡단 입력: config.py, tools_metadata/*.yaml
선택 입력: Chroma RAG index, Ollama
```

| 단계 | 입력 | 핵심 동작 | 출력 |
|---|---|---|---|
| Scanner | 단일 파일 또는 디렉터리 | symlink를 따라가지 않고 깊이 제한 순회. magic → 확장자 → 파일명 → 부모 경로 순으로 분류 | `Inventory` |
| Selector | Inventory + 도구 metadata | `evidence_type`과 `input_format`을 모두 만족하는 후보만 통과. 선택적으로 RAG와 LLM이 순위만 보강 | `Plan`, `RunSpec` |
| Executor | Plan + metadata | target별 격리 job 생성, preflight, 우선순위·병렬 정책 적용, `shell=False` 실행, 생성 파일 manifest | `ExecutionBundle` |
| Analyzer | 실행 산출물 + indicator metadata | 생성 artifact 우선 분석, CSV/NDJSON/text 스트리밍, 명시적 matcher 적용, 선택적 LLM 보조 | `ToolAnalysis`, `Finding` |
| Reporter | 앞 단계 전체 결과 | 도구별 실행·분석 병합, fingerprint 중복 제거, 상태·요약·단계 시간 직렬화 | terminal, `report_*.json`, `report_*.md` |

### Scanner의 중요한 경계

- 기본 CLI는 `include_unknown=False`이므로 미식별 파일을 `evidence_list`에 넣지 않지만 `unidentified_files`는 증가시킨다.
- 식별됐지만 소비할 등록 도구가 없는 파일은 `Plan.unhandled_evidence`에 남는다. 미식별 파일은 이 목록을 폭증시키지 않도록 제외된다.
- 기본 출력 디렉터리는 증거 트리 밖의 사용자 상태 디렉터리에 생성되고, 현재 실행의 출력 경로는 scan 대상에서 제외된다.
- `.git`, `.pytest_cache`, `build`, `dist`, `forensicagent_output` 등은 기본적으로 순회하지 않는다. 반대로 `data`, `seed_docs`, `bench`는 자동 제외 대상이 아니다.

## 4. 근본 원인과 이번 수정

여기서 P0는 핵심 결과 누락·오탐·증거 오염처럼 분석 신뢰도를 직접 훼손하는 문제, P1은 탐지 정확도·운영 안정성·재현성을 크게 낮추는 문제를 뜻한다.

| 우선순위 | 근본 원인과 영향 | 현재 수정 내용 | 남는 조건 |
|---|---|---|---|
| P0 | Executor가 `stdout`만 결과로 간주했다. EZTools처럼 `{output_dir}`에 CSV를 쓰는 도구는 성공으로 표시돼도 Analyzer가 실제 결과를 보지 못했다. | job별 `generated/` 격리, 재귀 artifact 수집, format·size·SHA-256 manifest, 생성 파일이 없을 때 `output_missing` 상태를 추가했다. Analyzer는 generated artifact를 우선 소비한다. | 실제 도구 버전별 출력 디렉터리·파일명은 실증 검증이 필요하다. |
| P0 | `ToolSelection` 하나에 command 하나만 있어 첫 template가 모든 target에 적용됐다. Volatility·RegRipper의 중요한 plugin과 hive별 실행이 빠졌다. | target별 `RunSpec`을 추가했다. Volatility는 `pslist`와 `cmdline`을 기본 실행하고 scenario에 따라 `netscan`·`malfind`·`pstree`를 추가한다. RegRipper는 hive별 plugin/profile을 결정한다. 선택 template도 실행 결과에 기록한다. | scenario→plugin 매핑은 결정론적 키워드 기반이며 모든 OS/profile 조합을 다루지 않는다. |
| P0 | 구현되지 않은 suspicious indicator를 자연어 substring으로 추정해 finding을 생성할 수 있었다. 정상 문장도 오탐으로 승격될 위험이 있었다. | concrete matcher registry에 등록된 ID만 실행한다. 미지원 ID는 warning을 남기고 finding을 만들지 않는다. Bandit·Semgrep·Gitleaks는 구조화 row를 기준으로 처리한다. | metadata에 선언됐지만 matcher가 없는 indicator가 남아 있으며 이는 의도적으로 0 finding이다. |
| P0 | 출력이 증거 디렉터리 안에 생성되면 다음 scan이 자체 출력물을 다시 증거로 읽고 사건 디렉터리를 변경했다. | 기본 출력은 `~/.forensicagent/output/<case>_<hash>` 아래로 이동했다. 현재 output 경로를 scan에서 prune하고 생성 디렉터리도 기본 ignore한다. | 저장소에는 과거 tracked 출력이 남아 있다. 사용자가 `--output-dir`을 사건 폴더 내부로 강제하면 운용상 주의가 필요하다. |
| P1 | `.raw`를 모두 메모리로, SQLite를 모두 브라우저로 보는 등 분류가 실제 포맷보다 과장됐다. Prefetch·PCAP signature도 일부 빠졌다. | `ntfs_metadata`, `sqlite_database`, `text_document`, `unclassified`를 추가했다. 일반 `.raw` 자동 메모리 분류를 제거하고, 명명 패턴이 있는 dump만 메모리로 본다. SCCA offset 4와 ns-PCAP 양 endian, Amcache·NTFS 이름을 보강했다. | raw disk image는 이름만으로 확정하지 않으므로 별도 탐지기나 사용자 힌트가 없으면 unknown일 수 있다. |
| P1 | Selector가 타입 교집합만 확인해 NTUSER.DAT에 AmcacheParser, 일반 registry hive에 MFTECmd 같은 잘못된 후보를 만들었다. | 타입과 `input_format`을 AND 조건으로 강제했다. `any`, `name:`, `ext:` 문법과 레거시 표기를 지원하고 target을 중복 제거했다. `--tools`도 도구 선택만 강제할 뿐 동일한 입력 안전 gate를 사용한다. 모든 기본 YAML과 golden set을 이 계약에 맞췄다. | 강제 도구와 호환되는 증거가 없으면 실행 계획은 비며 CLI가 명시적으로 실패한다. |
| P1 | Bandit·Semgrep·Gitleaks를 일치 파일마다 실행하면 같은 source tree를 반복 순회하고 finding이 중복될 수 있었다. | 세 도구에 `target_mode: scan_root`를 적용했다. 식별된 inventory가 code/text 타입으로만 구성된 디렉터리면 선택된 도구마다 scan root를 한 번만 실행한다. `--tools` 강제 경로에도 같은 집계를 적용하며, memory/disk 등 binary 증거가 섞이면 안전하게 일치 파일별 target으로 되돌아간다. | 단일 파일 scan root에는 집계하지 않으며, 도구 자체 ignore/config 정책은 별도로 관리해야 한다. |
| P1 | doctor·installer·adapter·executor가 서로 다른 PATH 탐색 정책을 사용해 “설치됨”과 “실행 가능” 판정이 어긋났다. | 공용 executable resolver가 PATH 우선, 사용자 `tools_bin` 후순위 정책을 공유한다. 도구 metadata 경로도 config의 단일 resolver로 통합하고 wheel에 기본 YAML을 포함한다. | 다수 포렌식 도구는 라이선스·플랫폼 이유로 수동 설치가 필요하다. |
| P1 | priority와 `parallelizable`이 실제 스케줄링에 충분히 반영되지 않고, tool별 prerequisite 검사가 반복될 수 있었다. | priority 내림차순 job scheduler, 도구별 preflight 1회, 같은 non-parallel 도구 직렬화와 다른 도구 간 병렬화를 구현했다. timeout 시 process tree 종료를 시도한다. | child process 종료는 OS별 best-effort이며 외부 도구 자체의 안정성은 보장하지 않는다. |
| P1 | 대용량 출력의 앞부분만 보거나, chunk 경계와 여러 exporter에서 중복 finding이 생길 수 있었다. | CSV row batch+overlap, NDJSON line streaming, text chunk+overlap, generated 우선 순서, canonical location과 fingerprint 중복 제거를 적용했다. 실패·`output_missing`에도 읽을 수 있는 부분 artifact는 분석한다. | 단일 거대 JSON은 여전히 전체 `json.load()` 대상이며 외부 도구의 비표준 형식은 parser 확장이 필요하다. |
| P1 | RAG가 일부 후보 점수만 있거나 관련도가 낮아도 결정론 순서를 바꿨고, query에 실제 파일명이 없었다. | 파일명+타입+scenario를 query에 포함한다. 모든 eligible 도구의 유효 점수가 있고 최소 similarity와 score margin을 통과할 때만 정렬하며, 실제 순서가 바뀐 경우에만 `rag_used=True`다. | 기본 embedding과 합성 benchmark가 한국어 사건 질의를 충분히 대표하는지는 검증되지 않았다. |
| P1 | LLM 결과가 자유 형식이거나 근거 없는 finding을 만들 수 있고, 모델 tag 확인이 느슨했다. | JSON schema와 재시도, exact model tag health check, 입력에 실제 존재하는 excerpt만 허용, LLM confidence 상한, deterministic finding 보존을 적용했다. | LLM 설명은 비결정적이며 최종 포렌식 판단을 대체하지 않는다. |
| P1 | 동일 초에 보고서를 쓰거나 여러 target 분석을 합칠 때 덮어쓰기·누락 가능성이 있었다. | timestamp+run ID 파일명, 도구별 다중 execution/analysis 병합, fingerprint 기반 finding 중복 제거, 실행 상태와 artifact manifest를 보고서에 포함한다. | 보고서는 입력 증거 자체의 hash/chain-of-custody manifest까지 생성하지 않는다. |

## 5. 탐지 범위와 지원 증거

### 5.1 Scanner 분류 범위

| 분류 | 주요 식별 단서 | 현재 연결 도구 | 주의점 |
|---|---|---|---|
| `memory_dump` | `.mem`, `.dmp`, `.vmem`, `.lime`; `memory`, `memdump`, `ram`, `physmem`, `winpmem` 이름 패턴의 `.raw/.bin` 등 | Volatility 3 | 일반 `disk.raw`는 메모리로 단정하지 않는다. |
| `evtx_log` | `ElfFile` magic, `.evtx/.evt`, Windows Event Log 부모 경로 | Chainsaw, EvtxECmd | 기본 metadata gate는 `.evtx`만 소비하므로 `.evt`는 분류돼도 unhandled일 수 있다. |
| `registry_hive` | `regf` magic, NTUSER.DAT·UsrClass.dat·SYSTEM·SOFTWARE·SAM·SECURITY·DEFAULT·Amcache.hve | AmcacheParser, RECmd, RegRipper | 각 도구가 허용하는 hive basename이 다르다. |
| `pcap` | classic PCAP μs/ns 양 endian, PCAPNG magic, `.pcap/.pcapng/.cap` | 없음 | 현재 scanner 탐지만 지원한다. tshark/tcpdump는 doctor 대상이지만 실행 metadata가 없다. |
| `disk_image` | EWF/VMDK magic, `.dd/.e01/.aff/.vhd/.vhdx/.vmdk` | 없음 | MFTECmd는 디스크 이미지 자체가 아니라 추출된 NTFS metadata를 입력으로 받는다. |
| `ntfs_metadata` | `$MFT`, `$J`, `$Boot`, `$SDS`, `$I30`, `.mft` | MFTECmd | 원시 이미지에서 이 파일들을 자동 추출하지 않는다. |
| `sqlite_database` | SQLite magic, `.sqlite/.sqlite3/.db` | 없음 | 브라우저 맥락이 없으면 일반 DB로 남는다. |
| `browser_artifact` | History·Cookies·Web Data·Places.sqlite·formhistory.sqlite 또는 Chrome/Edge/Firefox profile 경로 | 없음 | 현재 분류만 지원하며 브라우저 전용 parser는 등록돼 있지 않다. |
| `prefetch` | `MAM\x04`, version DWORD 뒤 offset 4의 `SCCA`, `.pf`, Windows Prefetch 경로 | PECmd | 압축/버전 변형 전체를 검증한 것은 아니다. |
| `text_log` | `.log`, syslog/auth.log/secure 계열, `/var/log` | Gitleaks | 현재 연결은 secret 탐지이며 일반 로그 포렌식 parser가 아니다. |
| `text_document` | `.txt` | Gitleaks | 평문 secret 탐지 범위다. |
| `source_code_python` | `.py`, `.pyi` | Bandit, Semgrep, Gitleaks | 파일 확장자 기반이다. |
| `source_code_javascript` | `.js/.jsx/.ts/.tsx/.mjs/.cjs` | Semgrep, Gitleaks | JavaScript/TypeScript 계열을 같은 타입으로 묶는다. |
| `source_code_generic` | Java, Go, Ruby, PHP, C/C++, Rust, C#, Kotlin, Swift 확장자 | Semgrep, Gitleaks | 모든 언어별 ruleset의 설치·정확도를 의미하지 않는다. |
| `unknown` | 위 단서가 없음 | 없음 | CLI에서는 목록 대신 `unidentified_files` 카운트로 남는다. |

### 5.2 현재 등록 도구

| 도구 | 입력 gate | 주 출력 | 역할 |
|---|---|---|---|
| AmcacheParser | `Amcache.hve` | CSV | Amcache 실행 흔적 |
| Bandit | `.py`, `.pyi` | JSON | Python 정적 보안 분석 |
| Chainsaw | `.evtx` | JSON | EVTX/Sigma 기반 hunting |
| EvtxECmd | `.evtx` | CSV | Windows Event Log 정규화 |
| Gitleaks | source/text 전반 | JSON | secret·credential 패턴 탐지 |
| MFTECmd | 추출 NTFS metadata 이름 또는 `.mft` | CSV | MFT/USN 등 NTFS metadata |
| PECmd | `.pf` | CSV | Windows Prefetch |
| RECmd | 허용된 registry hive 이름 | CSV | Registry batch 분석 |
| RegRipper | 허용된 registry hive 이름 | text | hive별 plugin/profile 분석 |
| Semgrep | metadata에 열거된 source 확장자 | JSON | 다중 언어 정적 분석 |
| Volatility 3 | 인식된 memory dump | CSV | `pslist`·`cmdline` 기본 및 scenario 기반 메모리 plugin 분석 |

이 표의 “등록”은 실행 명령과 metadata가 있다는 뜻이다. 바이너리·ruleset·plugin이 함께 설치됐거나 실제 사건 데이터에서 성공했다는 보장은 아니다.

Bandit·Semgrep·Gitleaks의 `target_mode`는 `scan_root`다. `Inventory.scan_root`가 디렉터리이고 식별된 증거 타입 전체가 source code 또는 text 계열일 때만, 선택된 각 도구가 그 루트를 한 번 실행한다. 이 규칙은 `--tools`에도 동일하다. memory dump·disk image 같은 binary 증거가 하나라도 함께 식별되면 광범위한 재귀 스캔을 피하기 위해 일치한 파일별 실행으로 폴백한다. Gitleaks JSON은 stdout으로 가정하지 않고 격리된 `{output_dir}/gitleaks.json`에 생성해 artifact로 수집한다.

### 5.3 Finding 생성 범위

- 규칙 엔진은 matcher registry에 명시적으로 등록된 indicator만 finding으로 만든다.
- 현재 metadata에 선언된 indicator ID는 46개이며, `supported_indicator_ids()` 기준 지원 ID는 38개다. registry 밖의 추가 지원 ID는 없다.
- EVTX/Sigma, registry persistence, Prefetch, Amcache, NTFS metadata, Volatility의 parent-child·실행 경로·network·`malfind`, Bandit/Semgrep/Gitleaks 구조화 결과 등에 대한 matcher가 존재한다.
- 현재 명시적 지원 공백은 아래 8개다.

| 도구 | 아직 matcher가 없는 indicator ID |
|---|---|
| AmcacheParser | `amcache_deleted_executable`, `amcache_sha1_known_bad` |
| EvtxECmd | `ntds_dump_attempt` |
| MFTECmd | `huge_unallocated_clusters`, `zero_byte_executable_recreated` |
| PECmd | `prefetch_deleted_executable` |
| RECmd | `shellbags_unusual_path` |
| RegRipper | `shimcache_recent_execution` |

- 실제 TI 조회 기반 known-bad hash/IP 확정, 실제 파일 삭제·존재 여부, 일부 교차 artifact 상관분석은 별도 데이터가 없으면 확정하지 않는다.
- 미지원 indicator는 warning과 0 finding이 정상 동작이다. 이를 “이상 없음”으로 해석해서는 안 된다.
- `Finding`은 `rule_id`, 근거 위치·excerpt, deterministic fingerprint, confidence를 가진다. LLM finding은 입력에 그대로 존재하는 excerpt가 없으면 폐기된다.

## 6. 실행, 산출물, RAG와 LLM 폴백

### 6.1 선택과 실행 승인

- 기본 Stage 1은 `evidence_type AND input_format` 결정론 필터다.
- Bandit·Semgrep·Gitleaks는 code/text-only 디렉터리 inventory일 때 선택된 도구별로 `scan_root` 하나를 target으로 사용한다. binary 타입이 섞인 inventory에서는 일치 파일별 target을 유지한다.
- `--quick`은 short runtime 도구만 남긴다.
- `--tools`는 운영자가 명시한 도구를 강제하며 일반 자동 선택 gate를 우회한다.
- `--dry-run`은 Plan까지만 만들고 외부 도구를 실행하지 않는다.
- TTY에서는 실행 전 승인을 묻고, 비대화형 실행은 명시적인 `--auto`가 필요하다.

### 6.2 실제 산출물 구조

기본 출력은 사건 경로가 아니라 사용자 상태 디렉터리 아래에 생성된다.

```text
~/.forensicagent/output/<case>_<path-hash>/
├─ raw/
│  ├─ 0001_<tool>_<evidence>_<job-id>/
│  │  ├─ stdout
│  │  ├─ stderr
│  │  └─ generated/
│  │     └─ 도구가 생성한 CSV/JSON/text 등
│  └─ ...
├─ report_<timestamp>_<run-id>.json
└─ report_<timestamp>_<run-id>.md
```

각 실행 결과는 `success`, `failed`, `timeout`, `skipped`, `output_missing` 중 하나다. stdout·stderr·generated 파일은 role, format, size, SHA-256과 함께 manifest에 들어간다. 명령은 argv 배열과 `shell=False`로 실행하지만, 외부 프로그램 자체는 현재 사용자 권한으로 동작하며 별도 sandbox는 없다.

### 6.3 Analyzer 크기별 처리

- Case A: 작은 산출물. 결정론 규칙과 선택적 LLM 보조에 원문을 사용할 수 있다.
- Case B: 중간 크기 산출물. LLM에는 다중 MB 원문 대신 deterministic rule이 잡은 근거 excerpt만 보낸다.
- Case C: 큰 산출물. CSV/NDJSON/text를 스트리밍하며 결정론 규칙을 적용하고 LLM은 호출하지 않는다.
- generated artifact를 stdout보다 먼저 분석하며, 겹치는 batch/chunk와 canonical fingerprint로 경계 누락·중복을 줄인다.

### 6.4 RAG 동작과 폴백

런타임 도구 선택 RAG는 `tools_metadata`를 별도 tool collection으로 인덱싱해 사용한다.

1. Stage 1을 통과한 도구 ID만 검색 대상으로 제한한다.
2. 모든 eligible 도구가 finite 범위의 점수를 가져야 한다.
3. `RAG_MIN_SIMILARITY`와 `RAG_MIN_SCORE_MARGIN`을 통과해야 한다.
4. 정렬 결과가 실제로 달라질 때만 `rag_used=True`로 기록한다.

Chroma, embedding model, index가 없거나 query가 실패하면 예외로 전체 실행을 중단하지 않고 결정론 순서를 유지한다. 유효한 일부 snippet은 LLM context로 사용할 수 있지만, 불완전한 점수 집합으로 순서를 바꾸지는 않는다.

후보가 하나뿐이면 순위가 바뀔 수 없으므로 임베딩 backend를 로드하지 않는다. 기존 기본 score margin 0.03은 합성 EVTX 케이스에서 parser를 threat hunter보다 앞세우는 회귀를 만들었고, 현재 기본값은 0.10으로 보수적으로 재보정했다. 2026-08-15의 14-case 영어 합성셋 재측정 결과 NDCG@3은 deterministic 0.9295에서 RAG 0.9422로 0.0127 증가했고, NDCG@5는 0.9485에서 0.9613으로 0.0128 증가했다. 보조 도구까지 relevant로 보는 기존 MRR은 양쪽 모두 1.0에 포화됐지만, 핵심 도구(grade=2)만 보는 `core_mrr`는 0.8929에서 0.9286으로 0.0357 증가했다. `core_r@3/@5`는 0.9524/1.0으로 변하지 않아, 이번 RAG 개선은 탐지 도구의 존재 여부보다 첫 실행 순서를 개선한 것이다. 이 값은 순서 품질만 나타내며 실제 탐지율 증거는 아니다. 이 PC의 cold process에서는 MiniLM 최초 로드가 약 25~30초였으므로 다중 후보에서의 첫 RAG 호출은 여전히 지연될 수 있다.

`seed_docs`의 도메인별 collection은 오프라인 corpus 자산이다. 현재 Selector와 Analyzer의 `retrieve_tools()` 경로는 tool metadata collection을 조회하므로, 저장소의 큰 seed corpus가 5단계 런타임에 자동으로 사용되는 것은 아니다.

### 6.5 LLM 동작과 폴백

- 기본 provider는 로컬 Ollama이고 기본 모델은 `qwen2.5:7b`이며, 모델 tag를 정확히 확인한다.
- Selector LLM은 Stage 1 후보의 priority/reason만 바꿀 수 있고 새 도구를 추가할 수 없다.
- Ollama 연결 실패 시 Selector는 결정론 후보 순서를 그대로 사용한다.
- JSON parse가 재시도 후 실패하면 `llm_fallback`을 기록하고 결정론 결과를 보존한다.
- Analyzer LLM 실패 시 rule finding은 그대로 남고 LLM finding만 비게 된다.
- `--no-llm`으로 전체 LLM 경로를 끌 수 있으며, `--no-rag`으로 semantic 검색을 끌 수 있다.

## 7. 아직 남는 한계와 위험

### 7.1 외부 도구와 실제 증거

- 포렌식 도구 대부분은 프로젝트에 포함되지 않는다. 일부는 pip/zip 설치가 가능하지만 EZTools, RegRipper, Gitleaks 등은 플랫폼·라이선스·배포 방식에 따라 수동 설치가 필요하다.
- metadata의 command template가 모든 버전과 OS에서 동일하게 동작한다고 검증되지 않았다.
- Chainsaw rules, Volatility symbol/plugin, RegRipper profile 같은 부속 자산이 없으면 executable만 있어도 분석이 실패하거나 축소된다.
- timeout 시 process tree 종료는 best-effort다. 외부 도구는 sandbox 없이 사용자 권한으로 실행되므로 신뢰된 바이너리만 사용해야 한다.
- 현재 자동 테스트는 합성 fixture와 mock subprocess 비중이 높다. 실제 대용량 EVTX, hive, Prefetch, MFT/USN, memory image를 묶은 공개 regression corpus가 필요하다.

### 7.2 탐지·규칙 커버리지

- PCAP, disk image, 일반 SQLite, browser artifact는 분류 가능하지만 현재 소비 도구가 없다.
- raw disk image 자동 판별·mount·artifact 추출 기능이 없다.
- metadata에 적힌 indicator 전체가 matcher로 구현된 것은 아니다. 현재 공백 8개는 위 표와 같으며 오탐 방지를 위해 warning만 남긴다.
- 알려진 악성 hash/IP, 서명 검증, 파일 존재·삭제 여부, 시간선 상관분석은 외부 데이터나 교차 artifact 없이는 확정하지 않는다.
- Scanner는 입력 증거의 cryptographic hash, filesystem timestamp, acquisition metadata를 저장하지 않는다. 출력 artifact에는 SHA-256이 있지만 입력 chain-of-custody를 대체하지 못한다.
- 기본 scan 깊이와 ignore 규칙, symlink 미추적 때문에 특정 배치 구조에서는 증거를 놓칠 수 있다.

### 7.3 RAG와 LLM

- 기본 sentence-transformer와 현재 golden set은 한국어 질의에 대한 별도 benchmark가 없다. 한국어 시나리오, 파일명, 약어가 섞인 평가셋을 따로 만들어야 한다.
- similarity threshold와 score margin은 안전장치이지 relevance 품질 보증이 아니다.
- 로컬 MiniLM의 process cold-start가 길다. 후보가 하나인 경우는 건너뛰지만 다중 후보의 첫 query는 CLI가 멈춘 것처럼 보일 수 있다.
- seed corpus의 출처·중복·라이선스·최신성 검증과 runtime 연결 정책이 정리돼야 한다.
- LLM 결과는 모델·버전·temperature·prompt에 따라 변한다. 근거 excerpt 검사는 hallucination을 줄이지만 의미적 오판까지 제거하지는 않는다.
- OpenAI embedding backend를 선택하면 설정과 구현에 따라 query가 외부 서비스로 전송될 수 있으므로 사건명·파일명 노출 정책을 별도로 검토해야 한다.

### 7.4 저장소 위생

- `forensicagent_output`, `bench/**/raw`, `data/raw`, `seed_docs`의 기존 산출물·corpus가 tracked 상태다. 코드 diff 검토가 어렵고 저장소 크기와 provenance 관리 부담이 커진다.
- 기본 scanner가 `forensicagent_output`은 제외하지만 `bench`, `data`, `seed_docs` 전체를 자동 제외하지는 않는다.
- 기존 tracked 결과를 삭제할지는 보존·재현 정책 결정이 필요한 별도 작업이다. 이 감사에서는 삭제하지 않았다.

## 8. 재현 및 검증 명령

아래 명령은 Windows PowerShell과 저장소 루트를 기준으로 한다. Python 버전은 환경에 맞게 바꿀 수 있다.

### 8.1 개발 환경과 정적 확인

```powershell
py -3.12 -m pip install -e ".[dev]"
py -3.12 -m compileall -q forensicagent tests
git diff --check
```

### 8.2 환경·도구 metadata 확인

```powershell
py -3.12 -m forensicagent doctor
py -3.12 -m forensicagent tools list
py -3.12 -m forensicagent tools info volatility3
```

`doctor`의 optional tool `miss`는 모든 분석이 불가능하다는 뜻이 아니다. 현재 증거에 필요한 도구가 설치됐는지를 별도로 확인해야 한다.

### 8.3 외부 실행 없는 결정론 계획 확인

```powershell
py -3.12 -m forensicagent `
  --path C:\cases\case01 `
  --dry-run `
  --no-llm `
  --no-rag
```

이 명령으로 Inventory, 선택 도구, target 수, unhandled evidence를 먼저 확인한다.

### 8.4 실제 도구 실행

```powershell
py -3.12 -m forensicagent `
  --path C:\cases\case01 `
  --auto `
  --no-llm `
  --no-rag `
  --output-dir C:\forensic_runs\case01
```

먼저 복제된 테스트 증거로 실행하고, `raw/<job>/stderr`, `generated/`, JSON 보고서의 `status`, `command_template_used`, `artifacts`, `warnings`를 확인해야 한다. 운영 증거에는 별도의 읽기 전용 보존·hash 절차를 적용한다.

### 8.5 RAG와 LLM 경로

```powershell
py -3.12 -m forensicagent rag index-tools
py -3.12 -m forensicagent rag status

# RAG만 허용하고 LLM은 끈 계획 확인
py -3.12 -m forensicagent --path C:\cases\case01 --dry-run --no-llm

# Ollama까지 준비됐을 때만 실행
ollama pull qwen2.5:7b
py -3.12 -m forensicagent --path C:\cases\case01 --dry-run
```

### 8.6 자동화 테스트와 benchmark

```powershell
# 현재 수집되는 전체 테스트를 그대로 실행하므로 개수를 문서에 고정하지 않는다.
py -3.12 -m pytest -q

# 테스트 목록과 현재 개수 확인
py -3.12 -m pytest --collect-only -q

# RAG 도구 순위 benchmark. embedding/Chroma 준비가 필요하다.
py -3.12 -m forensicagent bench

# 기존 index를 재사용
py -3.12 -m forensicagent bench --no-rebuild
```

benchmark 통과는 합성 selection 품질을 뜻할 뿐, 실제 공격 탐지 recall/precision이나 법적 증거 신뢰성을 증명하지 않는다.

현재 matcher 지원 수와 metadata 공백은 다음처럼 코드에서 다시 산출할 수 있다.

```powershell
@'
from forensicagent import config
from forensicagent.analyzer.rules import supported_indicator_ids
from forensicagent.tools.loader import load_all_tools

tools = load_all_tools(config.resolve_tools_dir())
declared = {
    indicator.id
    for metadata in tools.values()
    for indicator in metadata.suspicious_indicators
}
supported = set(supported_indicator_ids())
print("declared=", len(declared))
print("supported=", len(supported))
print("unsupported=", sorted(declared - supported))
'@ | py -3.12 -
```

## 9. 다음 우선 작업

1. 실제 공개 증거셋을 이용해 도구별 설치 버전, command, 생성 artifact, matcher 결과를 end-to-end 고정한다.
2. PCAP, disk image, SQLite/browser artifact용 metadata·adapter·parser를 추가한다.
3. 입력 증거 SHA-256, 획득 시각·원본 경로·case ID를 포함하는 읽기 전용 evidence manifest를 도입한다.
4. 현재 미지원 indicator를 외부 TI/교차 artifact 의존성별로 분류하고, 구현된 matcher만 기본 metadata에 노출한다.
5. 한국어 시나리오와 혼합 언어 파일명을 포함한 RAG golden set을 별도로 만들고 threshold를 재보정한다.
6. tracked 출력과 대형 corpus의 보존 정책을 정해 Git LFS·외부 artifact 저장소·manifest 방식 중 하나로 분리한다.

현재 상태의 적절한 표현은 **“실패 시 결정론 경로를 보존하는 자동 트리아지 파이프라인”**이다. 등록 도구와 명시적 규칙이 다루는 범위에서는 재현성과 관찰 가능성이 개선됐지만, 지원하지 않는 증거·indicator까지 탐지한다고 해석해서는 안 된다.
