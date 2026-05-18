# seed_docs/tryhackme/

`scripts/crawl_tryhackme.py` 가 수집한 TryHackMe Learn 콘텐츠가 쌓이는 자리.
사람이 직접 손대지 않는 디렉토리다 (크롤러가 덮어쓴다).

## 트리 구조

TryHackMe 의 **Path → Module → Room** 계층을 mirror. 단, **room 파일은
primary 위치에 1회만 저장**하고 다른 parent 컨텍스트는 frontmatter 의
`parents` 필드로 추적한다 (중복 청크 방지).

```
seed_docs/tryhackme/
├── _manifest.json                  # 수집 전체의 단일 진실 (room 위치 + 부모 매핑)
├── paths/
│   ├── soclevel1/
│   │   ├── _path.md                # path 메타
│   │   ├── dfir-essentials/
│   │   │   ├── _module.md          # module 메타 (forensics 태그 포함)
│   │   │   ├── dfirintro.md        # room
│   │   │   └── ...
│   │   └── ...
│   └── devsecops/
│       └── ...
└── modules/
    ├── macos-forensics/            # path 어디에도 안 들어간 standalone module
    │   ├── _module.md
    │   └── ...
    └── ...
```

## room md 의 frontmatter

```markdown
---
source: https://tryhackme.com/room/{slug}
room: {slug}
title: {Room 제목}
difficulty: easy | medium | hard
tags: [forensics]                 # 비어있을 수 있음
parents:
  paths: [soclevel1]
  modules: [dfir-essentials, incident-response-and-forensics]
collected: 2026-05-18
---

(task 본문 마크다운)
```

## 태깅 룰

`scripts/crawl_tryhackme.py` 의 `_detect_tags` 가 결정. 현재는 `forensics`
태그만 운영하며, slug / title / parent slug 들에 아래 키워드가 있으면 부여:

```
forensic, dfir, incident-response, investigation,
endpoint, mobile-analysis, memory-analysis
```

새 토픽 (예: malware, network) 을 추가하려면 `_FORENSICS_KEYWORDS` 옆에
같은 패턴으로 키워드 셋 + 태그 이름만 추가하면 된다.

이 태그는 ingest 시 metadata 로 보존되어, 추후 검색 필터 / 분석에 사용한다.

## ingest 와의 관계

```bash
python main.py ingest seed_docs/tryhackme/
```

`main.py _cmd_ingest` 가 디렉토리 입력을 처리하면 (frame), 위 트리를 walk
하며 모든 `.md` 파일을 `ingestion_graph.run()` 으로 N 회 호출한다.
`_path.md` / `_module.md` 도 같이 ingest 되어 path/module 자체의 개요도
검색에 잡히게 된다 (작아서 청크 1~2 개씩).

## 재수집 시

- `_manifest.json` 을 보면 어떤 room 이 어디 저장됐는지 정확히 알 수 있다.
- 같은 room 을 다시 수집하면 같은 경로에 덮어쓰기 된다 (idempotent).
- 단, **벡터 DB 는 자동으로 안 지워진다** — 재인덱싱 전에는
  `VectorStore.reset()` 또는 같은 source_file 의 chunk 를 제거하는 정책이
  필요. 현재 미구현.

## 주의

- 손으로 편집하지 말 것. 크롤러가 재실행되면 덮어쓰임.
- 수정사항이 필요하면 `scripts/crawl_tryhackme.py` 의 추출/포맷팅 로직을
  바꿔서 재수집.
- TryHackMe ToS / 저작권 범위 내에서만 사용.
