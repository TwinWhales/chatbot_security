# scripts/

런타임 파이프라인이 아닌 **보조 도구** 들의 자리. `src/` 가 매 요청마다
import 되는 코드라면, 여기에 있는 스크립트들은 사람이 가끔 손으로 돌리는
일회성 / 배치성 작업들이다.

## 컨벤션

- 각 스크립트는 `python scripts/<name>.py [subcommand] [args...]` 형태.
- 출력은 항상 `seed_docs/` 또는 `data/` 안에. 임의의 작업 디렉토리에 떨구지 않는다.
- src/ 를 import 하더라도 (예: vector_store 직접 호출), 반대 방향은 금지 —
  런타임 코드는 scripts/ 를 import 해선 안 된다.

## 스크립트

### `crawl_tryhackme.py` — TryHackMe Learn 컬렉터

TryHackMe 의 path / module / room URL 을 받아서, 안의 task 본문을 마크다운
으로 끌어내 `seed_docs/tryhackme/` 트리에 떨군다. 이후 `python main.py
ingest seed_docs/tryhackme/` 로 일괄 벡터화.

#### 의존성

Playwright 가 필요하다 (TryHackMe 가 JS 렌더링 + 로그인 필요):

```bash
pip install playwright html2text
playwright install chromium
```

runtime 에 무거운 의존성을 강제하지 않기 위해 `requirements.txt` 에는
넣지 않는다. 크롤러 작업하는 사람만 따로 설치.

#### 사용 흐름

```bash
# 1회 — 브라우저로 수동 로그인, 세션 저장
python scripts/crawl_tryhackme.py login
# → data/.tryhackme_session.json 에 저장 (.gitignore 됨)

# 본 수집 — 여러 URL 한 번에
python scripts/crawl_tryhackme.py crawl \
    https://tryhackme.com/path/outline/soclevel1 \
    https://tryhackme.com/path/outline/devsecops \
    https://tryhackme.com/module/macos-forensics \
    https://tryhackme.com/module/windows-endpoint-investigation \
    https://tryhackme.com/module/incident-response-and-forensics \
    https://tryhackme.com/module/digital-forensics-and-incident-response \
    https://tryhackme.com/module/dfir-essentials \
    https://tryhackme.com/module/mobile-analysis

# 이후 인덱싱
python main.py ingest seed_docs/tryhackme/
```

#### 동작 요약

1. **URL 분류** (`_classify_url`) — path / module / room
2. **펼치기** (`resolve_targets`) — path 는 module 까지, module 은 room 까지 펼쳐
   평탄 리스트로. 같은 room 이 여러 부모에 등장하면 parents 만 합쳐 1개로 dedupe
3. **태깅** (`_detect_tags`) — slug / title 키워드 매칭으로 `forensics` 등 부여
4. **본문 추출** (`fetch_room_content`) — Playwright 로 인증된 컨텍스트 진입,
   task DOM 을 마크다운으로
5. **파일 작성** (`_write_room`) — TryHackMe 계층을 mirror 하되 room 은 primary
   위치 (`paths/{path}/{module}/{slug}.md` 또는 `modules/{module}/{slug}.md`) 에
   1회만 저장. 나머지 parent 컨텍스트는 frontmatter `parents` 필드로 기록
6. **메타 + manifest** — `_path.md` / `_module.md` / `_manifest.json` 까지

#### 결과물 예 (frontmatter)

```markdown
---
source: https://tryhackme.com/room/dfirintro
room: dfirintro
title: DFIR: An Introduction
difficulty: easy
tags: [forensics]
parents:
  paths: [soclevel1]
  modules: [dfir-essentials, incident-response-and-forensics]
collected: 2026-05-18
---

(task 본문 마크다운)
```

#### 주의

- TryHackMe ToS 자동 스크래핑 / 콘텐츠 재배포 정책을 확인하고 본인 학습용
  범위 내에서 사용. 유료/구독 콘텐츠는 특히 주의.
- 로그인 세션 파일 (`data/.tryhackme_session.json`) 은 절대 커밋하지 말 것
  (이미 `.gitignore` 에 등록).
- 페이지 DOM 셀렉터는 사이트가 개편되면 깨질 수 있다. 첫 실행 시 한 두 곳
  조정이 필요할 수 있다 — 대표적인 의심 포인트:
  - `fetch_path` / `fetch_module` 의 `a[href*="/module/"]` / `a[href*="/room/"]`
    셀렉터가 사이드바·추천 영역까지 잡을 수 있음 → 결과가 이상하면
    부모 컨테이너로 한정 (예: `main a[href*="/room/"]`)
  - `fetch_room_content` 의 `main` 선택자가 nav/footer 까지 포함하면
    `_strip_chrome` 휴리스틱을 더 강하게 다듬어야 함
  - `aria-expanded="false"` 버튼 클릭으로 task 를 펼치는 부분 — TryHackMe
    가 다른 mechanism 으로 바꿨으면 여기서 본문이 빌 수 있음
- 디버깅 팁: `cmd_login` 의 `headless=False` 를 임시로 `cmd_crawl` 의
  `_load_context` 에도 적용해 페이지를 눈으로 보며 selector 잡기.
