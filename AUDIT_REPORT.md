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
│  ├─ rag/             tool metadata 인덱싱·Chroma 검색
│  ├─ llm/             Ollama 호출, JSON 재시도와 오류 변환
│  ├─ observability/   단계별 시간 측정
│  └─ config.py        경로·RAG·LLM·실행 설정의 단일 진입점
├─ tools_metadata/     현재 실행 가능한 도구 정의 YAML
├─ tests/              단위·통합·회귀 테스트
├─ bench/              합성 golden set과 deterministic/RAG/LLM 순위 평가
├─ eval/               공개 출처·라이선스·gold label E2E manifest
├─ scripts/            선택적 외부 자료 수집·가공 보조
└─ sample.txt          사용자가 직접 재수집할 외부 출처 URL 목록
```

`data/`, `seed_docs/`, `eval/goldenset/`, 생성 benchmark 디렉터리와
`forensicagent_output/`은 공개용 export에서 제외하고 ignored 로컬 산출물로
분리한다. 기존 private working tree에는 보존돼 있을 수 있으므로 저장소 루트 대신
사건별 전용 디렉터리를 `--path`로 지정하는 것이 안전하다.

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
| Scanner | 단일 파일 또는 디렉터리 | symlink·Windows junction/reparse를 따라가지 않고 깊이 제한 순회. magic → 확장자 → 파일명 → 부모 경로 순으로 분류하고, 1.5 GiB 미만 증거의 SHA-256·크기·mtime과 coverage 누락을 기록 | `Inventory` |
| Selector | Inventory + 도구 metadata | `evidence_type`과 `input_format`을 모두 만족하는 후보만 통과. 선택적으로 RAG와 LLM이 순위만 보강 | `Plan`, `RunSpec` |
| Executor | Plan + metadata + Inventory | artifact별 최고 우선순위 owner 하나를 확정하고, 입력·설정·실행 파일·규칙 provenance와 안전한 resume를 검증한 뒤 `shell=False` 실행 | `ExecutionBundle` |
| Analyzer | 실행 산출물 + indicator metadata | 생성 artifact 우선 분석, CSV/NDJSON/text 스트리밍, 명시적 matcher 적용, 선택적 LLM 보조 | `ToolAnalysis`, `Finding` |
| Reporter | 앞 단계 전체 결과 | coverage ledger, finding 타임라인, user/IP/process 피벗, analyst annotation, 상태·요약·단계 시간 직렬화 | terminal, `report_*.json`, `report_*.md` |

### Scanner의 중요한 경계

- 기본 CLI는 `include_unknown=False`이므로 미식별 파일을 `evidence_list`에 넣지 않지만 `unidentified_files`는 증가시킨다.
- 식별됐지만 소비할 등록 도구가 없는 파일은 `Plan.unhandled_evidence`에 남는다. 미식별 파일은 이 목록을 폭증시키지 않도록 제외된다.
- 기본 출력 디렉터리는 증거 트리 밖의 configured state 디렉터리에 생성되고,
  현재 실행의 출력 경로는 scan 대상에서 제외된다. 이 checkout은 로컬 `.env`로
  저장소 내부 ignored `.forensicagent/`를 사용한다.
- `.git`, `.hg`, `.svn`, dependency/cache/build 디렉터리는 어느 scan root에서든
  정책상 제외한다. 이 의도적 제외는 `depth_limit_hit`로 집계되지 않는다.
- `.agents`, `.codex`, `.forensicagent`, `.serena`, `forensicagent_output` 같은
  프로젝트 상태 이름은 scan root가 신뢰된 `PROJECT_ROOT` 자체일 때만 제외한다.
  외부 증거 트리에 같은 이름이 있어도 자동 제외하지 않는다.
- `depth_limit_hit`, `unreadable_paths`, `reparse_paths`는 terminal·JSON·Markdown에 전파된다. 값이 있으면 실행 성공과 별개로 scan coverage가 불완전하다.
- 크기가 **1.5 GiB 이상**인 파일은 자동 제외하고 hash하지 않는다. 경로·크기·상한·제외 이유는 inventory와 report ledger에 남는다.

## 4. 근본 원인과 이번 수정

여기서 P0는 핵심 결과 누락·오탐·증거 오염처럼 분석 신뢰도를 직접 훼손하는 문제, P1은 탐지 정확도·운영 안정성·재현성을 크게 낮추는 문제를 뜻한다.

| 우선순위 | 근본 원인과 영향 | 현재 수정 내용 | 남는 조건 |
|---|---|---|---|
| P0 | Executor가 `stdout`만 결과로 간주했다. EZTools처럼 `{output_dir}`에 CSV를 쓰는 도구는 성공으로 표시돼도 Analyzer가 실제 결과를 보지 못했다. | job별 `generated/` 격리, 재귀 artifact 수집, format·size·SHA-256 manifest, 생성 파일이 없을 때 `output_missing` 상태를 추가했다. Analyzer는 generated artifact를 우선 소비한다. | 실제 도구 버전별 출력 디렉터리·파일명은 실증 검증이 필요하다. |
| P0 | `ToolSelection` 하나에 command 하나만 있어 첫 template가 모든 target에 적용됐다. Volatility·RegRipper의 중요한 plugin과 hive별 실행이 빠졌다. | target별 `RunSpec`을 추가했다. Volatility는 Windows 증거에서 scenario 문구와 무관하게 `pslist`·`cmdline`·`netscan`·`malfind`·`pstree`를 실행한다. RegRipper는 hive별 plugin/profile을 결정한다. 선택 template도 실행 결과에 기록한다. | Linux/macOS 메모리 plugin은 아직 지원하지 않는다. |
| P0 | 구현되지 않은 suspicious indicator를 자연어 substring으로 추정해 finding을 생성할 수 있었다. 정상 문장도 오탐으로 승격될 위험이 있었다. | concrete matcher registry에 등록된 ID만 실행한다. 기본 metadata도 구현된 ID만 선언하며, custom·미지원 ID는 warning을 남기고 finding을 만들지 않는다. Bandit·Semgrep·Gitleaks는 구조화 row를 기준으로 처리한다. | 외부 TI·파일 존재 확인·교차 artifact가 필요한 주장은 해당 데이터와 matcher가 생기기 전까지 metadata에 노출하지 않는다. |
| P0 | 출력이 증거 디렉터리 안에 생성되면 다음 scan이 자체 출력물을 다시 증거로 읽고 사건 디렉터리를 변경했다. | 기본 출력은 `<FORENSICAGENT_HOME>/output/<case>_<hash>` 아래로 이동했다. 현재 output 경로를 scan에서 prune하고 생성 디렉터리도 기본 ignore한다. 프로젝트 로컬 `.env`를 쓰면 이 경로도 저장소 내부 ignored state에 한정된다. | 과거 출력은 현재 tree에서 제외했지만 기존 Git 이력에는 남아 있다. 사용자가 `--output-dir`을 사건 폴더 내부로 강제하면 운용상 주의가 필요하다. |
| P1 | `.raw`를 모두 메모리로, SQLite를 모두 브라우저로 보는 등 분류가 실제 포맷보다 과장됐고, 설정·script-only tree는 unknown이어서 Gitleaks가 선택되지 않았다. | `ntfs_metadata`, `sqlite_database`, `text_document`를 추가했다. 일반 `.raw` 자동 메모리 분류를 제거하고 명명 패턴이 있는 dump만 메모리로 본다. `.env`·YAML/JSON/TOML/INI, shell/PowerShell/batch, XML/Terraform, Dockerfile/Makefile/Jenkinsfile 등을 text evidence로 분류하며 SCCA offset 4, ns-PCAP 양 endian, Amcache·NTFS 이름도 보강했다. | raw disk image는 이름만으로 확정하지 않으므로 별도 탐지기나 사용자 힌트가 없으면 unknown일 수 있다. 구조화 설정·script의 의미 분석이 아니라 secret scan 라우팅이다. |
| P1 | Selector가 타입 교집합만 확인해 NTUSER.DAT에 AmcacheParser, 일반 registry hive에 MFTECmd 같은 잘못된 후보를 만들었다. | 타입과 `input_format`을 AND 조건으로 강제했다. `any`, `name:`, `ext:` 문법과 레거시 표기를 지원하고 target을 중복 제거했다. `--tools`도 도구 선택만 강제할 뿐 동일한 입력 안전 gate를 사용한다. 모든 기본 YAML과 golden set을 이 계약에 맞췄다. | 강제 도구와 호환되는 증거가 없으면 실행 계획은 비며 CLI가 명시적으로 실패한다. |
| P1 | source tree 전체를 외부 SAST/secret 도구에 넘기면 Scanner가 제외·깊이 제한한 unknown/binary 증거까지 재귀 처리할 수 있었다. | Bandit·Semgrep·Gitleaks는 Scanner inventory에서 host·타입·input format gate를 통과한 파일만 target으로 받는다. `--tools` 강제 경로도 동일하다. | 파일별 실행은 큰 source tree에서 느릴 수 있으므로 향후 Scanner inventory 기반 manifest/batch 입력을 검토할 수 있다. |
| P1 | doctor·installer·adapter·executor가 서로 다른 PATH 탐색 정책을 사용했고 installer가 최신 ZIP·unpinned pip 패키지를 무결성 검증 없이 설치했다. | 공용 executable resolver를 공유한다. 자동 pip 설치는 정확한 버전을 요구하고, Chainsaw와 Gitleaks는 고정 release와 SHA-256 검증, 다운로드·압축 해제 한도, 경로 탈출·특수 member 차단, staged 교체를 적용한다. 무탐지 회귀가 있는 Gitleaks 8.30.1과 오래된 PyPI Binwalk는 설치하지 않는다. | 고정 버전과 checksum은 새 release 채택 때 수동 갱신해야 하며, 다수 포렌식 도구는 라이선스·플랫폼 이유로 수동 설치가 필요하다. |
| P1 | priority와 `parallelizable`이 실제 스케줄링에 충분히 반영되지 않고, timeout 뒤 자식 프로세스가 남을 수 있었다. | priority 내림차순 scheduler, 도구별 preflight 1회, 같은 non-parallel 도구 직렬화를 적용했다. Windows는 kill-on-close Job Object, POSIX는 전용 process group을 만들고 timeout 시 전체 그룹을 종료한다. | 격리 API 실패는 warning으로 남긴다. 외부 도구 자체의 안정성이나 파일·네트워크 sandbox를 보장하지 않는다. |
| P1 | 대용량 출력의 앞부분만 보거나, chunk 경계와 여러 exporter에서 중복 finding이 생길 수 있었고 500건 한도 도달 여부가 보고서에 드러나지 않았다. | CSV row batch+overlap, bounded NDJSON, text chunk+overlap, generated 우선 순서, canonical location과 fingerprint 중복 제거를 적용했다. 100KiB 초과 JSON은 report에 inline하지 않고 4MiB 초과 단일 JSON은 원본 artifact·SHA와 `coverage_truncated` 경고를 남긴다. 실제 누락이 생긴 501건부터 severity 우선 500건과 `finding_limit_reached`를 전파한다. | coverage/finding-limit flag가 있으면 결과가 완전하지 않으므로 원본 artifact를 별도 검토해야 한다. |
| P1 | RAG가 일부 후보 점수만 있거나 관련도가 낮아도 결정론 순서를 바꿨고, query에 실제 파일명이 없었다. | 파일명+타입+scenario를 query에 포함한다. 모든 eligible 도구의 유효 점수가 있고 최소 similarity와 score margin을 통과할 때만 정렬하며, 실제 순서가 바뀐 경우에만 `rag_used=True`다. | 기본 embedding과 합성 benchmark가 한국어 사건 질의를 충분히 대표하는지는 검증되지 않았다. |
| P1 | LLM 결과가 자유 형식이거나 근거 없는 finding을 만들 수 있었고, 코드 보안 출력의 소스·secret이 LLM에 전달될 수 있었다. | JSON schema와 재시도, exact model tag health check, 입력에 실제 존재하는 excerpt만 허용, LLM confidence 상한, deterministic finding 보존을 적용했다. LLM-only finding은 severity `low` 이하이고 source/confidence로 구분한다. `code_security` 결과는 LLM에 보내지 않는다. | LLM 설명은 비결정적이며 최종 포렌식 판단을 대체하지 않는다. |
| P1 | 동일 초에 보고서를 쓰거나 여러 target 분석을 합칠 때 덮어쓰기·누락 가능성이 있었다. | timestamp+run ID 파일명, 도구별 다중 execution/analysis 병합, fingerprint 기반 finding 중복 제거, 실행 상태와 입력·출력 artifact manifest를 보고서에 포함한다. | 입력 hash manifest는 획득 장비·서명·WORM 보관까지 포함한 완전한 chain of custody를 대체하지 않는다. |
| P1 | EvtxECmd CSV의 헤더보다 긴 행은 `csv.DictReader`가 `None` 키를 만들고, 정렬 JSON 직렬화가 `None`/문자열 키 비교에서 중단됐다. | 충돌하지 않는 surplus-column 키를 지정하고 공용 row 직렬화가 혼합 키를 보존하도록 보강했다. | 비정상 행은 coverage 상한을 넘으면 원본을 보존하고 경고와 함께 건너뛴다. |
| P1 | 같은 증거에 여러 도구가 겹치거나 고우선순위 도구가 없을 때 하위 도구로 암묵적 fallback할 수 있었고, 완료 작업 재사용에 입력·설정 무결성 계약이 없었다. | artifact별 최고 우선순위 owner 하나만 실행하며 unavailable owner는 명시적으로 skip한다. 입력별 실행 전·후 SHA-256, job별 stat, executable/tool/rule/settings hash와 산출물 hash가 모두 일치한 성공만 resume한다. | 검사 사이에 변경 후 완전히 복구하는 악의적 ABA writer는 읽기 전용 snapshot 없이는 배제할 수 없다. |
| P1 | 빈 성공 디렉터리, 무제한 출력, Ctrl+C 후 자식 프로세스, 실패/timeout/누락 상태 혼합이 운영을 불안정하게 했다. | 실제 출력이 없는 성공 job dir은 제거하고 disk preflight·job/전체 출력 상한·프로세스 트리 취소를 적용했다. `timeout`, `cancelled`, `output_limit`, `output_missing`을 구분하며 실패 부분 산출물은 보존한다. | 외부 바이너리 자체에는 파일·네트워크 sandbox가 없다. |
| P1 | 보고서가 시각 순서·coverage 상태·분석가 판정을 지속적으로 보존하지 못했다. | finding 시각을 UTC와 원문으로 함께 정렬하고, 무시각/파싱 불가 finding은 분리한다. artifact ledger, user/IP/process 비인과적 correlation, fingerprint 기반 `confirmed`/`false_positive`/`pending` 노트를 JSON·Markdown에 보존한다. | 원본 이벤트 전체 timeline이나 자동 인과관계 재구성은 이번 범위가 아니다. |

## 5. 탐지 범위와 지원 증거

### 5.1 Scanner 분류 범위

| 분류 | 주요 식별 단서 | 현재 연결 도구 | 주의점 |
|---|---|---|---|
| `memory_dump` | `.mem`, `.dmp`, `.vmem`, `.lime`; `memory`, `memdump`, `ram`, `physmem`, `winpmem` 이름 패턴의 `.raw/.bin` 등 | Volatility 3 (Windows 증거만) | 일반 `disk.raw`는 메모리로 단정하지 않는다. `.lime` 등 Linux/macOS 힌트가 있는 증거는 현재 Windows plugin 실행 계획의 platform gate를 통과하지 않는다. |
| `evtx_log` | `ElfFile` magic 또는 `.evtx` 확장자 | Chainsaw, EvtxECmd | 실제 EVTX magic은 확장자와 무관하게 식별한다. 두 도구가 지원하지 않는 legacy `.evt`는 unknown으로 남긴다. |
| `registry_hive` | `regf` magic, NTUSER.DAT·UsrClass.dat·SYSTEM·SOFTWARE·SAM·SECURITY·DEFAULT·Amcache.hve | AmcacheParser, RECmd, RegRipper | 각 도구가 허용하는 hive basename이 다르다. |
| `pcap` | classic PCAP μs/ns 양 endian, PCAPNG magic, `.pcap/.pcapng/.cap` | TShark | 설치된 TShark 하나만 owner로 실행하며 없으면 fallback 없이 skip한다. |
| `disk_image` | EWF/VMDK magic, `.dd/.e01/.aff/.vhd/.vhdx/.vmdk` | Sleuth Kit `fls` | 설치된 `fls`로 파일 목록 triage만 수행하며 mount·파일 복구를 뜻하지 않는다. |
| `ntfs_metadata` | `$MFT`, `$J`, `$Boot`, `$SDS`, `$I30`, `.mft` | MFTECmd | 원시 이미지에서 이 파일들을 자동 추출하지 않는다. |
| `sqlite_database` | SQLite magic, `.sqlite/.sqlite3/.db` | 없음 | 브라우저 맥락이 없으면 일반 DB로 남는다. |
| `browser_artifact` | History·Cookies·Web Data·Places.sqlite·formhistory.sqlite 또는 Chrome/Edge/Firefox profile 경로 | 내장 Browser SQLite | stdlib SQLite read-only query로 history/download row를 bounded 추출한다. 알 수 없는 schema·누락 table은 coverage warning으로 남긴다. |
| `prefetch` | `MAM\x04`, version DWORD 뒤 offset 4의 `SCCA`, `.pf`, Windows Prefetch 경로 | PECmd | 압축/버전 변형 전체를 검증한 것은 아니다. |
| `text_log` | `.log`, syslog/auth.log/secure 계열, `/var/log` | Gitleaks | 현재 연결은 secret 탐지이며 일반 로그 포렌식 parser가 아니다. |
| `text_document` | `.txt`, `.env*`, YAML/JSON/TOML/INI/config, `.sh/.ps1/.bat/.cmd/.xml/.tf/.tfvars`, `.pem/.key`, `Dockerfile`·`Makefile`·`Jenkinsfile` | Gitleaks | 구조화 포맷이나 script 의미 분석이 아니라 text secret 탐지 라우팅이다. |
| `source_code_python` | `.py`, `.pyi` | Bandit, Semgrep, Gitleaks | 파일 확장자 기반이다. |
| `source_code_javascript` | `.js/.jsx/.ts/.tsx/.mjs/.cjs` | Semgrep, Gitleaks | JavaScript/TypeScript 계열을 같은 타입으로 묶는다. |
| `source_code_generic` | Java, Go, Ruby, PHP, C/C++, Rust, C#, Kotlin, Swift 확장자 | Semgrep, Gitleaks | 모든 언어별 ruleset의 설치·정확도를 의미하지 않는다. |
| `unknown` | 위 단서가 없음 | 없음 | CLI에서는 목록 대신 `unidentified_files` 카운트로 남는다. |

### 5.2 현재 등록 도구

| 도구 | 입력 gate | 주 출력 | 역할 |
|---|---|---|---|
| AmcacheParser (Windows) | `Amcache.hve` | CSV | Amcache 실행 흔적 |
| Bandit | `.py`, `.pyi` | CSV | Python 정적 보안 분석 |
| Browser SQLite (내장) | Chrome/Edge History, Firefox Places 계열 | JSON | bounded history/download 추출 |
| Chainsaw | `.evtx` | JSONL (large) | 채널별 주요 Event ID의 결정론적 Tau search |
| EvtxECmd (Windows) | `.evtx` | CSV | Windows Event Log 정규화 |
| `fls` | disk image | text | 이미지 파일 목록 triage |
| Gitleaks | source/text 전반 | CSV | secret·credential 패턴 탐지 |
| MFTECmd (Windows) | 추출 NTFS metadata 이름 또는 `.mft` | CSV | MFT/USN 등 NTFS metadata |
| PECmd (Windows) | `.pf` | CSV | Windows Prefetch |
| RECmd (Windows) | 허용된 registry hive 이름 | CSV | Registry batch 분석 |
| RegRipper | 허용된 registry hive 이름 | text | hive별 plugin/profile 분석 |
| Semgrep | metadata에 열거된 source 확장자 | JSON | 다중 언어 정적 분석 |
| TShark | PCAP/PCAPNG | JSON | 패킷·프로토콜 필드 triage |
| Volatility 3 | Windows로 식별되거나 OS가 미상인 memory dump | CSV | scenario 문구와 무관한 Windows 5-plugin detector coverage |

이 표의 “등록”은 실행 명령과 metadata가 있다는 뜻이다. 바이너리·ruleset·plugin이 함께 설치됐거나 실제 사건 데이터에서 성공했다는 보장은 아니다.

Bandit·Semgrep·Gitleaks도 실제 실행은 Scanner가 inventory에 넣고 host·evidence type·input format gate를 통과한 파일만 target으로 사용한다. 따라서 unknown 파일, 정책상 제외된 공통 VCS/dependency 디렉터리, max-depth 밖 파일을 외부 도구가 다시 재귀 처리하지 않는다. 프로젝트 상태 디렉터리 이름은 신뢰된 `PROJECT_ROOT` scan에만 적용되어 외부 증거의 `.agents`·`.codex` 등을 숨기지 않는다. custom metadata의 레거시 `target_mode: scan_root` 값도 이 안전 경계를 넓히지 않는다. Bandit/Gitleaks CSV와 Semgrep JSON은 격리된 job output에 생성하거나 수집해 Analyzer에 전달한다.

### 5.3 Finding 생성 범위

- 규칙 엔진은 matcher registry에 명시적으로 등록된 indicator만 finding으로 만든다.
- 현재 metadata에 선언된 고유 indicator ID는 34개이며 모두 matcher와 연결된다. `supported_indicator_ids()`는 custom metadata 호환용 ID까지 포함해 41개를 반환한다.
- EVTX Event ID 기반 규칙, registry persistence, Prefetch, Amcache, NTFS metadata, Volatility의 parent-child·실행 경로·network·`malfind`, Bandit/Semgrep/Gitleaks 구조화 결과 등에 대한 matcher가 존재한다.
- 실제 TI 조회, 파일 삭제·존재 확인, 일부 교차 artifact 상관분석 또는 기본 도구 출력에 없는 필드가 필요한 indicator는 구현된 것처럼 보이지 않도록 기본 metadata에서 제거했다. 향후 필요한 데이터와 matcher를 함께 구현할 때만 다시 선언해야 한다.
- custom metadata의 미지원 indicator는 warning과 0 finding이 정상 동작이다. 이를 “이상 없음”으로 해석해서는 안 된다.
- `Finding`은 `rule_id`, 근거 위치·excerpt, deterministic fingerprint, `source`, confidence를 가진다. LLM finding은 입력에 그대로 존재하는 excerpt가 없으면 폐기되고 severity가 `low` 이하로 제한된다. Bandit·Semgrep·Gitleaks의 `code_security` 출력은 LLM 경로에서 제외된다.

## 6. 실행, 산출물, RAG와 LLM 폴백

### 6.1 선택과 실행 승인

- 기본 Stage 1은 `host platform AND target evidence platform AND evidence_type AND input_format` 결정론 필터다.
- Bandit·Semgrep·Gitleaks도 Scanner inventory에서 gate를 통과한 일치 파일별 target만 유지한다.
- `--quick`은 short runtime 도구만 남긴다.
- `--tools`는 운영자가 지정한 도구의 RAG/LLM 순위를 건너뛰지만 host OS,
  evidence type, input format 안전 gate는 그대로 적용한다.
- `--dry-run`은 Plan까지만 만들고 외부 도구를 실행하지 않는다.
- TTY에서는 실행 전 승인을 묻고, 비대화형 실행은 명시적인 `--auto`가 필요하다.

### 6.2 실제 산출물 구조

기본 출력은 사건 경로가 아니라 `FORENSICAGENT_HOME` 아래에 생성된다. 일반
기본값은 사용자 상태 디렉터리지만, 이 프로젝트의 로컬 `.env`는 상태·도구·cache를
저장소의 ignored `.forensicagent/`와 `.cache/`에 한정한다.

```text
<FORENSICAGENT_HOME>/output/<case>_<path-hash>/
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

각 실행 결과는 `success`, `failed`, `timeout`, `cancelled`, `output_limit`, `skipped`, `output_missing` 중 하나다. stdout·stderr·generated 파일은 role, format, size, SHA-256과 함께 manifest에 들어간다. 성공 재사용은 입력 SHA-256/size/mtime, tool metadata·rule·analyzer code·실행 파일·command dependency·argv·resource 설정, 기존 산출물 hash가 모두 일치하고 최종 입력 검증이 `verified`일 때만 허용한다. 명령은 argv 배열과 `shell=False`로 실행하지만, 외부 프로그램 자체는 현재 사용자 권한으로 동작하며 별도 sandbox는 없다.

### 6.3 Analyzer 크기별 처리

- Case A: 작은 산출물. 결정론 규칙과 선택적 LLM 보조에 원문을 사용할 수 있다.
- Case B: 중간 크기 산출물. LLM에는 다중 MB 원문 대신 deterministic rule이 잡은 근거 excerpt만 보낸다.
- Case C: 큰 산출물. CSV/JSONL(NDJSON)/text를 스트리밍하며 결정론 규칙을 적용하고 LLM은 호출하지 않는다. Chainsaw는 JSONL과 `large` 계약으로 이 경로를 사용한다.
- generated artifact를 stdout보다 먼저 분석하며, 겹치는 batch/chunk와 canonical fingerprint로 경계 누락·중복을 줄인다.
- malformed/oversized row, 단일 거대 JSON 등 때문에 전체를 해석하지 못하면
  `coverage_warnings`와 `coverage_truncated`가 보고서까지 전파된다.
- `code_security` category는 소스·secret이 모델에 전달되지 않도록 LLM을 호출하지 않는다.
- analysis 상태가 `analyzed`이고 finding이 0개인 경우와 `not_analyzed`는 coverage
  ledger에서 구분한다. 후자를 “이상 없음”으로 해석하면 안 된다.

### 6.4 RAG 동작과 폴백

런타임 도구 선택 RAG는 `tools_metadata`를 별도 tool collection으로 인덱싱해 사용한다.

1. Stage 1을 통과한 도구 ID만 검색 대상으로 제한한다.
2. 모든 eligible 도구가 finite 범위의 점수를 가져야 한다.
3. `RAG_MIN_SIMILARITY`와 `RAG_MIN_SCORE_MARGIN`을 통과해야 한다.
4. 정렬 결과가 실제로 달라질 때만 `rag_used=True`로 기록한다.

Chroma, embedding model, index가 없거나 query가 실패하면 예외로 전체 실행을 중단하지 않고 결정론 순서를 유지한다. 유효한 일부 snippet은 LLM context로 사용할 수 있지만, 불완전한 점수 집합으로 순서를 바꾸지는 않는다.

후보가 하나뿐이면 순위가 바뀔 수 없으므로 임베딩 backend를 로드하지 않는다.
현재 기본 score margin은 0.10이다. 하니스는 누락된 gold 도구도 NDCG 이상 순위와
Recall 분모에 포함하고 metadata/golden set/index freshness와 재현 환경을 기록한다.

2026-08-19 Windows 11 AMD64 / CPython 3.12.4 환경에서 14개 합성 케이스와
11개 도구를 1회 재측정했다.

| metric | deterministic | RAG | delta |
|---|---:|---:|---:|
| NDCG@3 | 0.9295 | 0.9242 | -0.0053 |
| NDCG@5 | 0.9485 | 0.9442 | -0.0043 |
| Core MRR | 0.8929 | 0.8571 | -0.0357 |
| Recall@3 | 0.9714 | 0.9714 | 0.0000 |
| Recall@5 | 1.0000 | 1.0000 | 0.0000 |

RAG는 3/14 케이스를 재정렬했지만 aggregate 순위 품질을 개선하지 못했다. 첫
index rebuild는 48.26초(embedding 43,094ms, Chroma write 716ms), 케이스당
RAG 선택 평균은 220.7ms였다. 이는 이번 로컬 환경의 1회 결과다. Analyzer와
외부 도구를 실행하지 않는 **도구 선택 순위 평가**이므로 실제 finding
precision/recall이나 end-to-end 탐지율 증거가 아니다. 상세 재현 metadata와
케이스별 결과는 `bench/bench_report.md`와 `bench/bench_result.json`에 있다.

`seed_docs`는 사용자가 선택적으로 다시 수집하는 ignored 로컬 corpus다. 현재
Selector와 Analyzer의 `retrieve_tools()` 경로는 tool metadata collection을
조회하므로, 이 외부 corpus가 5단계 런타임에 자동으로 사용되는 것은 아니다.

### 6.5 LLM 동작과 폴백

- 기본 provider는 로컬 Ollama이고 기본 모델은 `qwen2.5:7b`이며, 모델 tag를 정확히 확인한다.
- Selector LLM은 Stage 1 후보의 priority/reason만 바꿀 수 있고 새 도구를 추가할 수 없다.
- Ollama 연결 실패 시 Selector는 결정론 후보 순서를 그대로 사용한다.
- JSON parse가 재시도 후 실패하면 `llm_fallback`을 기록하고 결정론 결과를 보존한다.
- Analyzer LLM 실패 시 rule finding은 그대로 남고 LLM finding만 비게 된다.
- Analyzer의 LLM-only finding은 grounded excerpt가 필요하며 severity는 `low` 이하,
  confidence는 0.6 이하로 제한되고 report에서 `source=llm`으로 구분된다.
- `code_security` 도구 결과는 LLM으로 보내지 않는다.
- `--no-llm`은 LLM만 끄며 RAG는 유지된다. `--no-rag`은 semantic 검색만
  끄며 LLM은 유지된다. 둘 다 끄려면 두 플래그를 함께 사용한다.
- `--scenario`는 RAG query와 Selector/Analyzer LLM context에만 들어가고
  결정론 도구 자격 gate나 matcher를 바꾸지 않는다.
- `/summary`의 결정론 화면과 선택적 LLM context는 집계·도구 상태만 사용한다.
  finding 본문, 원본 경로, 실행 명령, raw excerpt는 보내지 않으며 모델 출력은
  4,000자로 제한하고 terminal markup/control 문자를 literal로 처리한다.

## 7. 아직 남는 한계와 위험

### 7.1 외부 도구와 실제 증거

- 포렌식 도구 대부분은 프로젝트에 포함되지 않는다. Volatility·Bandit·Semgrep은 고정 Python package, Chainsaw와 Gitleaks는 고정 ZIP+SHA-256으로 설치할 수 있지만 EZTools와 RegRipper 등은 플랫폼·라이선스·배포 방식에 따라 수동 설치가 필요하다. AmcacheParser·EvtxECmd·MFTECmd·PECmd·RECmd는 Windows host 전용이다.
- Semgrep은 1.173.0과 pip 26.2.1을 project-local 격리 venv에 고정한다. clean
  reinstall 뒤 `semgrep --version`, `pip check`, `pip-audit`와 로컬 rule scan을
  통과했으며 알려진 의존성 취약점은 보고되지 않았다. 다만 기본
  `--config=auto` ruleset은 Registry 네트워크와 upstream 변경에 의존한다.
- metadata의 command template가 모든 버전과 OS에서 동일하게 동작한다고 검증되지 않았다.
- 현재 Chainsaw adapter는 bundled Sigma hunt가 아니라 채널별 Event ID search만 실행한다. Sigma 지원에는 검증된 rules/mapping 경로를 받는 별도 실행 계약이 필요하다.
- 현재 Volatility 실행 계획은 Windows plugin만 생성한다. Linux/macOS에서 바이너리를 실행할 수 있다는 host `platform` 표기를 Linux/macOS 메모리 증거 지원으로 해석하면 안 된다. Volatility symbol/plugin이나 RegRipper profile 같은 부속 자산이 없으면 executable만 있어도 분석이 실패하거나 축소된다.
- timeout 격리는 Windows Job Object와 POSIX process group을 사용하고 실패 시
  warning을 남긴다. 이것은 권한·파일·네트워크 sandbox가 아니므로 신뢰된
  바이너리만 실행해야 한다.
- 현재 자동 테스트는 합성 fixture와 mock subprocess 비중이 높다. 실제 대용량 EVTX, hive, Prefetch, MFT/USN, memory image를 묶은 공개 regression corpus가 필요하다.

### 7.2 탐지·규칙 커버리지

- PCAP은 TShark, disk image는 `fls`, browser SQLite는 내장 parser metadata가 있다. 해당 단일 owner가 설치되지 않았거나 schema를 지원하지 않으면 다른 도구로 fallback하지 않고 skip/coverage warning을 남긴다.
- raw disk image 자동 판별·mount·artifact 추출 기능이 없다.
- 기본 metadata의 indicator는 모두 matcher와 연결된다. 다만 이는 제거된 TI·파일 존재·교차 artifact 의존 탐지까지 지원한다는 뜻이 아니다. 레거시 `sigma_rule_hit` matcher는 registry에 남아 있지만 기본 Chainsaw metadata와 실행 경로는 이를 사용하지 않는다.
- 보고서에 `finding_limit_reached=true`가 있으면 severity 우선 500건만 보존된 상태이므로 0 finding이나 낮은 건수를 전체 결과로 해석하면 안 된다.
- 알려진 악성 hash/IP, 서명 검증, 파일 존재·삭제 여부, 시간선 상관분석은 외부 데이터나 교차 artifact 없이는 확정하지 않는다.
- Scanner는 포함 증거의 SHA-256·크기·mtime을 기록하고 Executor가 시작·종료 시 다시 확인한다. 이는 획득 장비·서명·WORM 보관을 포함한 완전한 chain of custody를 대체하지 않으며, 1.5 GiB 이상 자동 제외 파일은 hash하지 않는다.
- 기본 scan 깊이, unreadable path, symlink/junction/reparse 미추적 때문에 특정 배치 구조에서는 증거를 놓칠 수 있다. 이 경우 coverage 필드는 경고하지만 누락 데이터를 대신 복구하지는 않는다. 공통 VCS/dependency ignore는 별도의 정책 제외라 coverage 경고에 포함되지 않는다.

### 7.3 RAG와 LLM

- 선택 의존성 ChromaDB 1.5.9는 CVE-2026-45829(무패치 pre-auth code injection)의 영향 범위다. forensicagent는 in-process `PersistentClient`만 사용하고 HTTP 서버를 시작하지 않지만, 패치 전 `chroma run`이나 Chroma API를 신뢰되지 않은 네트워크에 노출해서는 안 된다. 위험을 받지 않으려면 core-only 설치와 `--no-rag`를 사용한다.
- 기본 sentence-transformer와 현재 golden set은 한국어 질의에 대한 별도 benchmark가 없다. 한국어 시나리오, 파일명, 약어가 섞인 평가셋을 따로 만들어야 한다.
- similarity threshold와 score margin은 안전장치이지 relevance 품질 보증이 아니다.
- 로컬 MiniLM의 process cold-start가 길다. 후보가 하나인 경우는 건너뛰지만 다중 후보의 첫 query는 CLI가 멈춘 것처럼 보일 수 있다.
- 외부 corpus를 로컬에서 재수집하거나 다시 배포하려면 출처·중복·라이선스·최신성
  검증과 runtime 연결 정책을 먼저 정해야 한다.
- LLM 결과는 모델·버전·temperature·prompt에 따라 변한다. 근거 excerpt 검사는 hallucination을 줄이지만 의미적 오판까지 제거하지는 않는다.
- OpenAI embedding backend를 선택하면 설정과 구현에 따라 query가 외부 서비스로 전송될 수 있으므로 사건명·파일명 노출 정책을 별도로 검토해야 한다.

### 7.4 저장소 위생

- 공개용 export에서는 `forensicagent_output`, 생성 benchmark 디렉터리, `data/`,
  `seed_docs/`, `eval/goldenset/`, `tools_metadata/_failures/`를 제외한다.
  기존 private working tree의 로컬 파일은 보존하며 `.gitignore`로 재유입을 막는다.
- Gitleaks 8.30.0으로 34개 commit 전체를 검사한 결과 89건이 보고됐다. 85건은
  과거 외부 `data`/`seed_docs` corpus의 tutorial token·JWT·private-key 패턴이고
  4건은 합성 analyzer 테스트 키다. 공개 export 대상의 자격증명 형태 후보는
  합성 회귀 fixture뿐이며 실제 자격증명은 발견되지 않았다. 사용자 확인상 실제
  고객·사건 기밀 데이터도 사용하지 않았다. 다만 이 확인은 과거 외부 본문의
  재배포 권리나 Git 이력에서의 접근 가능성을 해결하지 않는다.
- 현재 소스·테스트·설정은 detect-secrets 1.5.0 `--no-verify`로도 별도 검사했다.
  후보는 공개 malware/release SHA-256과 합성 secret 회귀 fixture로 수동 확인했으며
  실제 자격증명은 발견되지 않았다. suppressing baseline은 만들지 않았다.
- 신뢰된 `PROJECT_ROOT` scan에서는 프로젝트 상태·생성 디렉터리를 제외하지만
  `bench`, `data`, `seed_docs` 전체는 자동 제외하지 않는다. 외부 증거 root에는
  프로젝트 전용 이름 제외를 적용하지 않는다.
- ignored corpus·산출물이 로컬에 남아 있을 수 있으므로 저장소 루트를 증거로
  지정할 때는 여전히 주의해야 한다.

### 7.5 공개 전 차단 조건

- 공개용 export는 외부 corpus 본문과 생성 산출물을 포함하지 않지만, 기존 Git 이력에는
  과거 corpus 본문과 자격증명 형태 후보 85건이 그대로 접근 가능하다. 따라서 이
  저장소를 이력째 public으로 전환하지 말고, 정리된 현재 tree만 새 초기 커밋으로
  가져간 sanitized fresh repository를 공개해야 한다. 기존 이력은 private로
  보존하는 방식을 권장한다.
- `sample.txt`로 외부 corpus를 다시 수집하거나 본문을 배포하려면 각 출처의 최신
  라이선스·이용약관·robots 정책을 별도로 확인해야 한다.
- 선택 의존성 ChromaDB의 미패치 취약점, Semgrep 격리 환경 재검증, 라벨된 실제
  증거 E2E 정확도 부재도
  공개 문구에서 명시해야 한다.
- private vulnerability reporting, push protection, branch protection 같은 GitHub
  저장소 설정은 코드로 보장할 수 없으므로 관리자가 공개 직전에 확인해야 한다.

## 8. 재현 및 검증 명령

아래 명령은 Windows PowerShell과 저장소 루트를 기준으로 한다. 먼저 저장소 전용
`.venv`를 만들고, 이후에는 해당 interpreter만 사용한다. Linux에서는 Python
package 설치 전에 시스템 `libmagic`도 설치해야 한다(Debian/Ubuntu 예:
`sudo apt-get install libmagic1`).

### 8.1 개발 환경과 정적 확인

```powershell
py -3.12 -m venv .venv
.\.venv\Scripts\python.exe -m pip install -e ".[dev]"
.\.venv\Scripts\python.exe -m compileall -q forensicagent tests
.\.venv\Scripts\ruff.exe check .
git diff --check
```

프로젝트 한정 운용은 `.env.example`을 `.env`로 복사하고
`FORENSICAGENT_HOME=.forensicagent`를 유지한다. 그러면 자동 설치 ZIP·격리 tool
venv·Chroma 상태는 저장소 내부 ignored 경로에 머물고 사용자 PATH를 수정하지 않는다.

### 8.2 환경·도구 metadata 확인

```powershell
.\.venv\Scripts\python.exe -m forensicagent doctor
.\.venv\Scripts\python.exe -m forensicagent tools list
.\.venv\Scripts\python.exe -m forensicagent tools info volatility3
```

`doctor`의 optional tool `miss`는 모든 분석이 불가능하다는 뜻이 아니다. 현재 증거에 필요한 도구가 설치됐는지를 별도로 확인해야 한다.

### 8.3 외부 실행 없는 결정론 계획 확인

```powershell
.\.venv\Scripts\python.exe -m forensicagent `
  --path C:\cases\case01 `
  --dry-run `
  --no-llm `
  --no-rag
```

이 명령으로 Inventory, 선택 도구, target 수, unhandled evidence를 먼저 확인한다.

### 8.4 실제 도구 실행

```powershell
.\.venv\Scripts\python.exe -m forensicagent `
  --path C:\cases\case01 `
  --auto `
  --no-llm `
  --no-rag `
  --output-dir C:\forensic_runs\case01
```

먼저 복제된 테스트 증거로 실행하고, `raw/<job>/stderr`, `generated/`, JSON 보고서의 `status`, `command_template_used`, `artifacts`, `warnings`를 확인해야 한다. 운영 증거에는 별도의 읽기 전용 보존·hash 절차를 적용한다.

### 8.5 RAG와 LLM 경로

```powershell
# RAG만 검증할 때
.\.venv\Scripts\python.exe -m pip install -e ".[dev,rag]"
.\.venv\Scripts\python.exe -m forensicagent rag index-tools
.\.venv\Scripts\python.exe -m forensicagent rag status

# RAG만 허용하고 LLM은 끈 계획 확인
.\.venv\Scripts\python.exe -m forensicagent --path C:\cases\case01 --dry-run --no-llm

# Ollama까지 준비됐을 때만 실행
.\.venv\Scripts\python.exe -m pip install -e ".[dev,llm,rag]"
ollama pull qwen2.5:7b
.\.venv\Scripts\python.exe -m forensicagent --path C:\cases\case01 --dry-run
```

### 8.6 자동화 테스트와 benchmark

```powershell
# 현재 수집되는 전체 테스트를 그대로 실행하므로 개수를 문서에 고정하지 않는다.
.\.venv\Scripts\python.exe -m pytest -q --basetemp .pytest_cache/tmp

# 테스트 목록과 현재 개수 확인
.\.venv\Scripts\python.exe -m pytest --collect-only -q --basetemp .pytest_cache/tmp

# RAG 도구 순위 benchmark. embedding/Chroma 준비가 필요하다.
.\.venv\Scripts\python.exe -m pip install -e ".[dev,rag]"
.\.venv\Scripts\python.exe -m forensicagent bench

# 기존 index를 재사용
.\.venv\Scripts\python.exe -m forensicagent bench --no-rebuild

# 공개 corpus finding E2E. 다운로드는 하지 않으며 corpus/run은 Git에서 제외된다.
.\.venv\Scripts\python.exe -m forensicagent.e2e_detection eval\e2e_manifest.json
```

benchmark 통과는 합성 selection 품질을 뜻할 뿐, 실제 공격 탐지 recall/precision이나 법적 증거 신뢰성을 증명하지 않는다.
현재 E2E manifest는 검증된 corpus SHA-256이 고정되지 않아 `executed_cases=0`,
`metrics_available=false`, aggregate metric `null`이 정상이다. 이 값을 0점 성능이나
탐지 정확도 증거로 사용하면 안 된다.

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
'@ | .\.venv\Scripts\python.exe -
```

### 8.7 CI 범위

`.github/workflows/ci.yml`은 Windows/Python 3.10·3.14와 Ubuntu/Python 3.12에서
lint, 테스트, wheel build/install, source tree 밖 import/CLI smoke test를 수행한다.
Linux job은 `libmagic1`을 설치한다. 배포, release publish, cloud credential을
사용하는 단계는 없으므로 현재 자동화는 **CI only**이며 CD가 아니다.

## 9. 다음 우선 작업

1. 실제 공개 증거셋을 이용해 도구별 설치 버전, command, 생성 artifact, matcher 결과를 end-to-end 고정한다.
2. 1.5 GiB 이상 원본은 읽기 전용 snapshot·분할 복제본 등 별도 대형 증거 운용 절차를 마련하고, 필요하면 명시적 정책 설정을 추가한다.
3. 제거한 TI·파일 존재·교차 artifact 의존 indicator는 필요한 데이터 소스와 matcher를 함께 구현할 때만 기본 metadata에 다시 노출한다.
4. 한국어 시나리오와 혼합 언어 파일명을 포함한 RAG golden set을 별도로 만들고 threshold를 재보정한다.
5. 정리된 현재 tree로 fresh public repository를 만들고 기존 corpus 포함 이력은 private로 보존한다.

현재 상태의 적절한 표현은 **“실패 시 결정론 경로를 보존하는 자동 트리아지 파이프라인”**이다. 등록 도구와 명시적 규칙이 다루는 범위에서는 재현성과 관찰 가능성이 개선됐지만, 지원하지 않는 증거·indicator까지 탐지한다고 해석해서는 안 된다.

라이선스는 [LICENSE](LICENSE), 취약점 제보 절차는 [SECURITY.md](SECURITY.md),
외부 도구·데이터 고지는 [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md)를
참조한다. 공개용 export의 파일 표면은 정리됐지만 sanitized fresh history와
저장소 보안 설정을 준비하기 전에는 “오픈소스 공개 준비 완료”로 표현하지 않는다.
