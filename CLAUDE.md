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

## 현재 상태 (2026-05-19)

이전의 RAG 챗봇 보안 시스템에서 forensicagent 로 프로젝트를 전환한 직후.
재사용 가능한 자산만 남기고 정리 완료:

- `forensicagent/observability/metrics.py` — Stopwatch / StageTimings /
  ScoreStats / LengthStats / percentile (도메인 dataclass 는 각 모듈에서 자체 정의)
- `forensicagent/rag/{vector_store,embedder}.py` — skeleton (NotImplementedError),
  도구 YAML 인덱싱에 그대로 활용 가능
- `scripts/crawlers/` — 5 개 크롤러 (도구 메타데이터 작성 보조)

다음 단계는 명세의 Phase 1 (패키징/CLI/Ollama 래퍼/doctor) — 아직 미시작.
