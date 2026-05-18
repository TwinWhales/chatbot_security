"""TryHackMe Learn 컬렉터 (frame).

런타임 파이프라인이 아닌 **보조 수집 도구**다. 출력은 seed_docs/tryhackme/
트리이고, ingest 는 동일한 `python main.py ingest seed_docs/tryhackme/` 로
처리된다.

사용:
    # 1회 — 브라우저 띄워 수동 로그인 후 세션 저장
    python scripts/crawl_tryhackme.py login

    # 본 수집 (path / module / room URL 혼합 가능)
    python scripts/crawl_tryhackme.py crawl \\
        https://tryhackme.com/path/outline/soclevel1 \\
        https://tryhackme.com/module/macos-forensics

흐름:

    [login]
        Playwright (headless=False) → 사용자 수동 로그인
        context.storage_state(SESSION_PATH)

    [crawl <url>...]
        ctx = _load_context()                 # 저장된 세션 재사용
        rooms = resolve_targets(ctx, urls)    # path/module → room 펼치기 + dedupe
        for room in rooms:
            room.tags = _detect_tags(room)    # forensics? 등
            body     = fetch_room_content(ctx, room)
            _write_room(room, body)           # seed_docs/tryhackme/{tree}/{slug}.md
        _write_path_meta / _write_module_meta
        _write_manifest(rooms)

출력 트리 (TryHackMe 계층 mirror, room 은 primary 위치에 1회만 저장):

    seed_docs/tryhackme/
    ├── _manifest.json
    ├── paths/
    │   └── {path-slug}/
    │       ├── _path.md
    │       └── {module-slug}/
    │           ├── _module.md
    │           └── {room-slug}.md
    └── modules/
        └── {module-slug}/           # path 에 속하지 않은 standalone module
            ├── _module.md
            └── {room-slug}.md

room frontmatter 예:
    ---
    source: https://tryhackme.com/room/{slug}
    room: {slug}
    title: {Room 제목}
    difficulty: easy
    tags: [forensics]
    parents:
      paths: [soclevel1]
      modules: [dfir-essentials, incident-response-and-forensics]
    collected: 2026-05-18
    ---

직접 구현해보세요 (frame — 모든 함수가 NotImplementedError).
의존성: `pip install playwright && playwright install chromium`
"""

from __future__ import annotations

import argparse
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Literal


# === 경로 ===
PROJECT_ROOT = Path(__file__).resolve().parent.parent
SESSION_PATH = PROJECT_ROOT / "data" / ".tryhackme_session.json"
OUTPUT_ROOT = PROJECT_ROOT / "seed_docs" / "tryhackme"

# === forensics 태깅 룰 ===
# slug/title 안에 아래 키워드 중 하나라도 있으면 "forensics" 태그 부여.
# 새 토픽 (예: malware, network 등) 도 같은 패턴으로 추가 가능.
_FORENSICS_KEYWORDS = (
    "forensic",
    "dfir",
    "incident-response",
    "investigation",
    "endpoint",
    "mobile-analysis",
    "memory-analysis",
)


# === 자료형 ===

@dataclass
class ParentRef:
    kind: Literal["path", "module"]
    slug: str
    title: str
    url: str


@dataclass
class RoomRef:
    slug: str
    title: str
    url: str
    difficulty: str = ""
    parents: list[ParentRef] = field(default_factory=list)
    tags: list[str] = field(default_factory=list)


# === 인증 ===

def cmd_login(_: argparse.Namespace) -> int:
    """Playwright 브라우저를 띄워 수동 로그인 → storage_state.json 저장.

    TODO:
      - playwright.sync_api.sync_playwright 컨텍스트
      - chromium.launch(headless=False)
      - context = browser.new_context()
      - page.goto("https://tryhackme.com/login")
      - input("로그인 완료 후 Enter 를 누르세요: ")
      - SESSION_PATH.parent.mkdir(parents=True, exist_ok=True)
      - context.storage_state(path=str(SESSION_PATH))
      - 저장 위치 print
    """
    raise NotImplementedError("cmd_login")


def _load_context(playwright):
    """저장된 storage_state 로 인증된 context 반환.

    TODO:
      - SESSION_PATH 가 없으면 SystemExit("먼저 `login` 실행하세요")
      - browser = playwright.chromium.launch(headless=True)
      - return browser.new_context(storage_state=str(SESSION_PATH))
    """
    raise NotImplementedError("_load_context")


# === URL 해석 ===

def _classify_url(url: str) -> Literal["path", "module", "room", "unknown"]:
    """URL 패턴으로 분류.

    TODO:
      - "/path/outline/" → "path"
      - "/module/"       → "module"
      - "/room/"         → "room"
      - 그 외             → "unknown"
    """
    raise NotImplementedError("_classify_url")


def fetch_path(ctx, url: str) -> tuple[ParentRef, list[ParentRef]]:
    """Path 페이지에서 path 메타 + 안의 module 목록 추출.

    TODO:
      - page = ctx.new_page(); page.goto(url); 적당한 wait
      - path 제목 / slug → ParentRef(kind="path", ...)
      - module 카드 querySelectorAll → list[ParentRef(kind="module", ...)]
      - DOM selector 는 첫 호출 시 한 번 디버깅하면서 잡으면 됨
    """
    raise NotImplementedError("fetch_path")


def fetch_module(ctx, url: str) -> tuple[ParentRef, list[RoomRef]]:
    """Module 페이지에서 module 메타 + 안의 room 목록 추출.

    TODO:
      - page.goto(url)
      - module 제목 / slug → ParentRef(kind="module", ...)
      - room 카드 → list[RoomRef] (parents 는 호출자가 채움)
    """
    raise NotImplementedError("fetch_module")


def fetch_room_content(ctx, room: RoomRef) -> str:
    """Room 페이지에서 task 본문을 마크다운으로 추출.

    TODO:
      - page.goto(room.url)
      - task 섹션 (보통 .task / [data-task] 류) 순회
      - 각 task 의 HTML → markdown 변환 (html2text / markdownify 권장)
      - 코드블록 / 이미지 alt / 외부 링크 보존
      - 단일 string 반환 (frontmatter 는 _to_markdown 이 붙임)
    """
    raise NotImplementedError("fetch_room_content")


# === target 해석 + dedup ===

def resolve_targets(ctx, urls: list[str]) -> list[RoomRef]:
    """입력 URL 들을 펼쳐 RoomRef 평탄 리스트로. 중복 room 은 parents 합쳐 1개로.

    TODO:
      - 각 URL 을 _classify_url 로 분류
        - "path"   → fetch_path → 각 module URL 에 대해 fetch_module → rooms
                     room.parents 에 path + module 모두 추가
        - "module" → fetch_module → rooms. room.parents 에 module 만 추가
        - "room"   → 단일 RoomRef (parents 비어 있을 수 있음)
      - dedupe: room.slug 가 같으면 첫 등장만 남기고 parents 만 합치기
      - 입력 출현 순서 보존
    """
    raise NotImplementedError("resolve_targets")


# === 태깅 ===

def _detect_tags(room: RoomRef) -> list[str]:
    """forensics 등 토픽 태그 결정.

    TODO:
      - haystack = (room.slug + room.title + 모든 parent.slug + parent.title) 의 lowercase
      - _FORENSICS_KEYWORDS 중 하나라도 in haystack 이면 "forensics" 추가
      - (확장 지점) 다른 토픽도 같은 패턴으로 keyword 셋만 늘리면 됨
      - 매칭 없으면 빈 리스트
    """
    raise NotImplementedError("_detect_tags")


# === 마크다운 출력 ===

def _to_markdown(room: RoomRef, body: str) -> str:
    """YAML frontmatter + 본문을 단일 문자열로 결합.

    TODO 예시 형식:
        ---
        source: {room.url}
        room: {room.slug}
        title: {room.title}
        difficulty: {room.difficulty}
        tags: [forensics]            # 비어있으면 빈 리스트
        parents:
          paths: [...]
          modules: [...]
        collected: 2026-05-18
        ---

        {body}
    """
    raise NotImplementedError("_to_markdown")


def _primary_location(room: RoomRef) -> Path:
    """seed_docs/tryhackme/ 안에서 이 room 의 파일 경로 결정 (mirror 하되 1회만).

    규칙:
      1. parents 에 path 가 있으면:
         paths/{first-path-slug}/{first-module-slug-in-that-path}/{room.slug}.md
      2. path 가 없고 module 만 있으면:
         modules/{first-module-slug}/{room.slug}.md
      3. 둘 다 없으면:
         orphan/{room.slug}.md   # 안전망

    TODO: 위 규칙대로 PurePath 조립해 반환
    """
    raise NotImplementedError("_primary_location")


def _write_room(room: RoomRef, body: str) -> Path:
    """room 1건을 디스크에 작성.

    TODO:
      - dest = OUTPUT_ROOT / _primary_location(room)
      - dest.parent.mkdir(parents=True, exist_ok=True)
      - dest.write_text(_to_markdown(room, body), encoding="utf-8")
      - return dest
    """
    raise NotImplementedError("_write_room")


def _write_module_meta(module: ParentRef, output_dir: Path, *, forensics: bool) -> None:
    """{output_dir}/_module.md 에 module 메타 기록.

    TODO: 단일 md, frontmatter 만:
        ---
        kind: module
        slug: ...
        title: ...
        source: ...
        tags: [forensics] | []
        ---
    """
    raise NotImplementedError("_write_module_meta")


def _write_path_meta(path: ParentRef, output_dir: Path) -> None:
    """{output_dir}/_path.md 에 path 메타 기록.

    TODO: module 메타와 동일 패턴, kind="path".
    """
    raise NotImplementedError("_write_path_meta")


def _write_manifest(rooms: list[RoomRef]) -> Path:
    """seed_docs/tryhackme/_manifest.json 에 전체 매핑 기록.

    TODO 형식:
        {
          "collected_at": "<UTC ISO-8601>",
          "rooms": [
            {
              "slug": "...",
              "title": "...",
              "url": "...",
              "tags": ["forensics"],
              "parents": {"paths": [...], "modules": [...]},
              "stored_at": "<repo-relative path>"
            }
          ]
        }
    """
    raise NotImplementedError("_write_manifest")


# === CLI ===

def cmd_crawl(args: argparse.Namespace) -> int:
    """본 수집 명령.

    TODO:
      - playwright.sync_api.sync_playwright() 컨텍스트 안에서:
          ctx = _load_context(playwright)
          rooms = resolve_targets(ctx, args.urls)
          - 부모 메타 기록 (path / module 별로 1회씩)
          - 각 room 마다:
              room.tags = _detect_tags(room)
              body = fetch_room_content(ctx, room)
              _write_room(room, body)
              print 으로 진행 (n/N, slug, tags)
          _write_manifest(rooms)
      - return 0
    """
    raise NotImplementedError("cmd_crawl")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="crawl_tryhackme",
        description="Collect TryHackMe Learn content into seed_docs/tryhackme/",
    )
    sub = parser.add_subparsers(dest="cmd", required=True)

    p_login = sub.add_parser(
        "login",
        help="Open a browser, log in manually, save the session for later crawls",
    )
    p_login.set_defaults(func=cmd_login)

    p_crawl = sub.add_parser(
        "crawl",
        help="Crawl one or more TryHackMe path/module/room URLs into seed_docs/tryhackme/",
    )
    p_crawl.add_argument(
        "urls",
        nargs="+",
        help="One or more TryHackMe URLs. Mix of /path/outline/, /module/, /room/ accepted.",
    )
    p_crawl.set_defaults(func=cmd_crawl)

    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.path.insert(0, str(PROJECT_ROOT))
    raise SystemExit(main())
