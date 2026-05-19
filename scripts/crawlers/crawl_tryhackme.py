"""TryHackMe Learn 컬렉터.

런타임 파이프라인이 아닌 **보조 수집 도구**다. 출력은 seed_docs/tryhackme/
트리이고, ingest 는 동일한 `python main.py ingest seed_docs/tryhackme/` 로
처리된다.

사용:
    # 1회 - 브라우저 띄워 수동 로그인 후 세션 저장
    python scripts/crawl_tryhackme.py login

    # 본 수집 (path / module / room URL 혼합 가능)
    python scripts/crawl_tryhackme.py crawl \\
        https://tryhackme.com/path/outline/soclevel1 \\
        https://tryhackme.com/module/macos-forensics

흐름:
    [login]   Playwright (headless=False) → 사용자가 수동 로그인
              context.storage_state(SESSION_PATH)

    [crawl <url>...]
              ctx = _load_context()                # 저장된 세션 재사용
              rooms = resolve_targets(ctx, urls)   # path/module → room 펼치기 + dedupe
              부모 메타(_path.md / _module.md) 기록
              for room in rooms:
                  room.tags = _detect_tags(room)
                  body     = fetch_room_content(ctx, room)
                  _write_room(room, body)
              _write_manifest(rooms)

출력 트리 (room 은 primary 위치에 1회만 저장, 다른 parents 는 frontmatter 에):

    seed_docs/tryhackme/
    ├── _manifest.json
    ├── paths/{path-slug}/{module-slug}/{room-slug}.md
    └── modules/{module-slug}/{room-slug}.md   # standalone module 의 room

의존성:
    pip install playwright html2text
    playwright install chromium
"""

from __future__ import annotations

import argparse
import json
import sys
import time
from dataclasses import dataclass, field
from datetime import date, datetime, timezone
from pathlib import Path
from typing import Literal
from urllib.parse import urlparse


# === 경로 ===
PROJECT_ROOT = Path(__file__).resolve().parent.parent
SESSION_PATH = PROJECT_ROOT / "data" / ".tryhackme_session.json"
OUTPUT_ROOT = PROJECT_ROOT / "seed_docs" / "tryhackme"

# === forensics 태깅 룰 ===
# slug/title/parent slug 들에 아래 키워드 중 하나라도 있으면 "forensics" 부여.
# 새 토픽은 키워드 셋 + 태그 이름만 추가하면 같은 패턴으로 확장 가능.
_FORENSICS_KEYWORDS = (
    "forensic",
    "dfir",
    "incident-response",
    "incident response",
    "investigation",
    "endpoint",
    "mobile-analysis",
    "mobile analysis",
    "memory-analysis",
    "memory analysis",
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
    """Playwright 브라우저를 띄워 수동 로그인 후 storage_state 저장.

    감지 방식: URL 이 /login 또는 /signup 에서 벗어나는 순간 (= 로그인 성공
    후 대시보드 리다이렉트) 을 wait_for_url 로 자동 감지. 최대 5분 대기.
    백그라운드 / 포어그라운드 어느 쪽에서도 동일하게 동작한다.
    """
    from playwright.sync_api import sync_playwright

    SESSION_PATH.parent.mkdir(parents=True, exist_ok=True)
    print("브라우저를 띄웁니다. 열린 창에서 직접 로그인 해주세요.")
    print("로그인이 성공해 다른 페이지로 넘어가면 자동으로 세션이 저장됩니다.")
    print("최대 5분 대기.")
    sys.stdout.flush()

    with sync_playwright() as p:
        browser = p.chromium.launch(headless=False)
        context = browser.new_context()
        page = context.new_page()
        page.goto("https://tryhackme.com/login", wait_until="domcontentloaded")
        try:
            page.wait_for_url(
                lambda url: "/login" not in url and "/signup" not in url,
                timeout=300_000,
            )
            _wait_ready(page)
        except Exception as exc:
            print(f"로그인 감지 타임아웃 또는 실패: {exc}", file=sys.stderr)
            browser.close()
            return 2
        context.storage_state(path=str(SESSION_PATH))
        browser.close()

    print(f"세션 저장 완료: {SESSION_PATH}")
    return 0


def _load_context(playwright):
    """저장된 storage_state 로 인증된 (browser, context) 반환."""
    if not SESSION_PATH.exists():
        raise SystemExit(
            f"세션 파일이 없습니다: {SESSION_PATH}\n"
            f"먼저 `python scripts/crawl_tryhackme.py login` 을 실행하세요."
        )
    browser = playwright.chromium.launch(headless=True)
    context = browser.new_context(storage_state=str(SESSION_PATH))
    return browser, context


# === URL 분류 / 유틸 ===

def _classify_url(url: str) -> Literal["path", "module", "room", "unknown"]:
    if "/path/outline/" in url:
        return "path"
    if "/module/" in url:
        return "module"
    if "/room/" in url:
        return "room"
    return "unknown"


def _slug_from_url(url: str) -> str:
    parsed = urlparse(url)
    parts = [p for p in parsed.path.split("/") if p]
    return parts[-1] if parts else ""


def _absolute_url(href: str) -> str:
    if href.startswith("http"):
        return href
    if href.startswith("/"):
        return "https://tryhackme.com" + href
    return "https://tryhackme.com/" + href


def _wait_ready(page) -> None:
    """페이지 콘텐츠가 안정될 때까지 대기. 일부 실패는 무시 (timeout 등)."""
    try:
        page.wait_for_load_state("networkidle", timeout=15000)
    except Exception:
        pass
    time.sleep(0.4)


def _safe_text(page, selector: str) -> str:
    try:
        el = page.query_selector(selector)
        if el:
            return el.inner_text()
    except Exception:
        pass
    return ""


# === 페이지 fetch ===

def fetch_path(ctx, url: str) -> tuple[ParentRef, list[ParentRef]]:
    """Path 페이지에서 path 메타 + 안의 module ParentRef 목록."""
    page = ctx.new_page()
    try:
        page.goto(url, wait_until="domcontentloaded", timeout=30000)
        _wait_ready(page)

        path_slug = _slug_from_url(url)
        title = _safe_text(page, "h1").strip() or path_slug
        path_ref = ParentRef(kind="path", slug=path_slug, title=title, url=url)

        # path 페이지의 module 링크들 - /module/<slug>
        hrefs = page.eval_on_selector_all(
            'a[href*="/module/"]',
            "els => els.map(e => e.getAttribute('href'))",
        ) or []

        modules: list[ParentRef] = []
        seen: set[str] = set()
        for href in hrefs:
            if not href:
                continue
            full = _absolute_url(href.split("?")[0].split("#")[0])
            slug = _slug_from_url(full)
            if not slug or slug in seen:
                continue
            seen.add(slug)
            # title 은 module 페이지에서 다시 얻으므로 일단 slug 로
            modules.append(ParentRef(kind="module", slug=slug, title=slug, url=full))
        return path_ref, modules
    finally:
        page.close()


def fetch_module(ctx, url: str) -> tuple[ParentRef, list[RoomRef]]:
    """Module 페이지에서 module 메타 + 안의 RoomRef 목록."""
    page = ctx.new_page()
    try:
        page.goto(url, wait_until="domcontentloaded", timeout=30000)
        _wait_ready(page)

        module_slug = _slug_from_url(url)
        title = _safe_text(page, "h1").strip() or module_slug
        module_ref = ParentRef(kind="module", slug=module_slug, title=title, url=url)

        # room 링크 + 카드 텍스트 (title 후보)
        cards = page.eval_on_selector_all(
            'a[href*="/room/"]',
            """els => els.map(e => ({
                href: e.getAttribute('href'),
                text: ((e.innerText || e.textContent) || '').trim()
            }))""",
        ) or []

        rooms: list[RoomRef] = []
        seen: set[str] = set()
        for c in cards:
            href = c.get("href") or ""
            if not href:
                continue
            full = _absolute_url(href.split("?")[0].split("#")[0])
            slug = _slug_from_url(full)
            if not slug or slug in seen:
                continue
            seen.add(slug)
            text = (c.get("text") or "").splitlines()[0].strip() if c.get("text") else ""
            rooms.append(RoomRef(
                slug=slug,
                title=(text[:200] if text else slug),
                url=full,
            ))
        return module_ref, rooms
    finally:
        page.close()


def fetch_room_content(ctx, room: RoomRef) -> str:
    """Room 페이지에서 task 본문을 마크다운으로 추출."""
    import html2text

    page = ctx.new_page()
    try:
        page.goto(room.url, wait_until="domcontentloaded", timeout=30000)
        _wait_ready(page)

        # 더 좋은 제목 / 난이도 메타가 있으면 갱신
        h1 = _safe_text(page, "h1").strip()
        if h1:
            room.title = h1
        difficulty = _safe_text(page, '[class*="difficulty" i]').strip()
        if difficulty:
            room.difficulty = difficulty

        # 접혀있는 task accordion 펼치기 (있을 경우)
        try:
            buttons = page.locator('button[aria-expanded="false"]')
            count = min(buttons.count(), 50)
            for i in range(count):
                try:
                    buttons.nth(i).click(timeout=1500)
                    time.sleep(0.12)
                except Exception:
                    pass
            # 펼친 뒤 추가 안정화
            _wait_ready(page)
        except Exception:
            pass

        # 본문 영역 - main 우선, 없으면 body
        html = page.evaluate("""
            () => {
                const main = document.querySelector('main')
                          || document.querySelector('[role="main"]')
                          || document.body;
                return main ? main.innerHTML : '';
            }
        """) or ""

        converter = html2text.HTML2Text()
        converter.body_width = 0
        converter.ignore_links = False
        converter.ignore_images = False
        converter.bypass_tables = False
        body_md = converter.handle(html).strip()
        return _strip_chrome(body_md)
    finally:
        page.close()


def _strip_chrome(md: str) -> str:
    """본문 앞뒤의 단순 nav 잡음 정리. 보수적으로만 손댐."""
    lines = [ln.rstrip() for ln in md.splitlines()]
    # 연속된 빈 줄 3개 이상 → 2개로 축약
    out: list[str] = []
    blank = 0
    for ln in lines:
        if not ln.strip():
            blank += 1
            if blank <= 2:
                out.append(ln)
        else:
            blank = 0
            out.append(ln)
    return "\n".join(out).strip()


# === target 해석 + dedup ===

def resolve_targets(ctx, urls: list[str]) -> list[RoomRef]:
    """입력 URL 들을 펼쳐 RoomRef 평탄 리스트로. 같은 room 은 parents 만 합쳐 1개로."""
    by_slug: dict[str, RoomRef] = {}
    insertion_order: list[str] = []

    for url in urls:
        kind = _classify_url(url)
        try:
            if kind == "path":
                print(f"  [path] {url}")
                path_ref, modules = fetch_path(ctx, url)
                print(f"    → {len(modules)} module")
                for m_stub in modules:
                    try:
                        module_ref, rooms = fetch_module(ctx, m_stub.url)
                    except Exception as exc:
                        print(f"    [warn] module fetch 실패: {m_stub.url} - {exc}",
                              file=sys.stderr)
                        continue
                    for r in rooms:
                        _accumulate_room(by_slug, insertion_order, r, [path_ref, module_ref])
            elif kind == "module":
                print(f"  [module] {url}")
                module_ref, rooms = fetch_module(ctx, url)
                print(f"    → {len(rooms)} room")
                for r in rooms:
                    _accumulate_room(by_slug, insertion_order, r, [module_ref])
            elif kind == "room":
                slug = _slug_from_url(url)
                _accumulate_room(
                    by_slug, insertion_order,
                    RoomRef(slug=slug, title=slug, url=url), [],
                )
            else:
                print(f"  [warn] 인식 불가 URL: {url}", file=sys.stderr)
        except Exception as exc:
            print(f"  [warn] target 해석 실패: {url} - {exc}", file=sys.stderr)

    return [by_slug[s] for s in insertion_order]


def _accumulate_room(
    bucket: dict[str, RoomRef],
    order: list[str],
    r: RoomRef,
    parents: list[ParentRef],
) -> None:
    existing = bucket.get(r.slug)
    if existing is None:
        r.parents = list(parents)
        bucket[r.slug] = r
        order.append(r.slug)
        return
    # parents 합치기 (중복 제거 - kind+slug 기준)
    for p in parents:
        if not any(pp.kind == p.kind and pp.slug == p.slug for pp in existing.parents):
            existing.parents.append(p)
    # title 이 더 풍부하면 갱신
    if len(r.title) > len(existing.title):
        existing.title = r.title


# === 태깅 ===

def _detect_tags(room: RoomRef) -> list[str]:
    haystack_parts = [room.slug, room.title]
    for p in room.parents:
        haystack_parts.extend([p.slug, p.title])
    haystack = " ".join(haystack_parts).lower()

    tags: list[str] = []
    if any(kw in haystack for kw in _FORENSICS_KEYWORDS):
        tags.append("forensics")
    return tags


# === 마크다운 출력 ===

def _yaml_scalar(s: str) -> str:
    """YAML scalar - 특수문자 있으면 quote."""
    if s is None:
        return '""'
    s = str(s)
    if not s:
        return '""'
    risky = (":", "#", '"', "'", "\n", "[", "]", "{", "}", ",",
             "&", "*", "|", ">", "!", "%", "@", "`")
    if any(c in s for c in risky):
        return '"' + s.replace("\\", "\\\\").replace('"', '\\"') + '"'
    return s


def _yaml_list(items: list[str]) -> str:
    if not items:
        return "[]"
    return "[" + ", ".join(_yaml_scalar(x) for x in items) + "]"


def _to_markdown(room: RoomRef, body: str) -> str:
    path_slugs = [p.slug for p in room.parents if p.kind == "path"]
    module_slugs = [p.slug for p in room.parents if p.kind == "module"]
    today = date.today().isoformat()

    fm = [
        "---",
        f"source: {room.url}",
        f"room: {room.slug}",
        f"title: {_yaml_scalar(room.title)}",
        f"difficulty: {_yaml_scalar(room.difficulty)}",
        f"tags: {_yaml_list(room.tags)}",
        "parents:",
        f"  paths: {_yaml_list(path_slugs)}",
        f"  modules: {_yaml_list(module_slugs)}",
        f"collected: {today}",
        "---",
        "",
    ]
    return "\n".join(fm) + body.strip() + "\n"


def _primary_location(room: RoomRef) -> Path:
    paths = [p for p in room.parents if p.kind == "path"]
    modules = [p for p in room.parents if p.kind == "module"]

    if paths and modules:
        return Path("paths") / paths[0].slug / modules[0].slug / f"{room.slug}.md"
    if modules:
        return Path("modules") / modules[0].slug / f"{room.slug}.md"
    return Path("orphan") / f"{room.slug}.md"


def _write_room(room: RoomRef, body: str) -> Path:
    rel = _primary_location(room)
    dest = OUTPUT_ROOT / rel
    dest.parent.mkdir(parents=True, exist_ok=True)
    dest.write_text(_to_markdown(room, body), encoding="utf-8")
    return dest


def _write_module_meta(module: ParentRef, output_dir: Path, *, forensics: bool) -> None:
    output_dir.mkdir(parents=True, exist_ok=True)
    tags = ["forensics"] if forensics else []
    today = date.today().isoformat()
    content = (
        "---\n"
        "kind: module\n"
        f"slug: {module.slug}\n"
        f"title: {_yaml_scalar(module.title)}\n"
        f"source: {module.url}\n"
        f"tags: {_yaml_list(tags)}\n"
        f"collected: {today}\n"
        "---\n"
    )
    (output_dir / "_module.md").write_text(content, encoding="utf-8")


def _write_path_meta(path_ref: ParentRef, output_dir: Path) -> None:
    output_dir.mkdir(parents=True, exist_ok=True)
    today = date.today().isoformat()
    content = (
        "---\n"
        "kind: path\n"
        f"slug: {path_ref.slug}\n"
        f"title: {_yaml_scalar(path_ref.title)}\n"
        f"source: {path_ref.url}\n"
        f"collected: {today}\n"
        "---\n"
    )
    (output_dir / "_path.md").write_text(content, encoding="utf-8")


def _write_manifest(rooms: list[RoomRef]) -> Path:
    OUTPUT_ROOT.mkdir(parents=True, exist_ok=True)
    manifest = {
        "collected_at": datetime.now(timezone.utc).isoformat(),
        "rooms": [
            {
                "slug": r.slug,
                "title": r.title,
                "url": r.url,
                "difficulty": r.difficulty,
                "tags": r.tags,
                "parents": {
                    "paths": [p.slug for p in r.parents if p.kind == "path"],
                    "modules": [p.slug for p in r.parents if p.kind == "module"],
                },
                "stored_at": str(_primary_location(r)).replace("\\", "/"),
            }
            for r in rooms
        ],
    }
    out = OUTPUT_ROOT / "_manifest.json"
    out.write_text(json.dumps(manifest, ensure_ascii=False, indent=2), encoding="utf-8")
    return out


def _module_is_forensics(module: ParentRef) -> bool:
    # 임시 RoomRef 로 동일 룰 재사용
    return "forensics" in _detect_tags(
        RoomRef(slug=module.slug, title=module.title, url=module.url)
    )


# === CLI ===

def cmd_crawl(args: argparse.Namespace) -> int:
    from playwright.sync_api import sync_playwright

    OUTPUT_ROOT.mkdir(parents=True, exist_ok=True)

    with sync_playwright() as p:
        browser, ctx = _load_context(p)
        try:
            print(f"[1/3] target 해석 - {len(args.urls)} URL")
            rooms = resolve_targets(ctx, args.urls)
            print(f"   → unique room {len(rooms)} 개")

            if not rooms:
                print("수집할 room 이 없습니다. URL 또는 셀렉터를 확인하세요.")
                return 1

            # 부모 메타 (_path.md / _module.md) - primary 위치 기준 1회씩
            print(f"[2/3] 부모 메타 기록")
            written_paths: set[str] = set()
            written_modules: set[tuple[str, ...]] = set()
            for r in rooms:
                paths_in = [pp for pp in r.parents if pp.kind == "path"]
                modules_in = [pp for pp in r.parents if pp.kind == "module"]
                primary_path = paths_in[0] if paths_in else None
                primary_module = modules_in[0] if modules_in else None

                if primary_path and primary_module:
                    path_dir = OUTPUT_ROOT / "paths" / primary_path.slug
                    if primary_path.slug not in written_paths:
                        _write_path_meta(primary_path, path_dir)
                        written_paths.add(primary_path.slug)
                    module_dir = path_dir / primary_module.slug
                    key = ("paths", primary_path.slug, primary_module.slug)
                    if key not in written_modules:
                        _write_module_meta(
                            primary_module, module_dir,
                            forensics=_module_is_forensics(primary_module),
                        )
                        written_modules.add(key)
                elif primary_module:
                    module_dir = OUTPUT_ROOT / "modules" / primary_module.slug
                    key = ("modules", primary_module.slug)
                    if key not in written_modules:
                        _write_module_meta(
                            primary_module, module_dir,
                            forensics=_module_is_forensics(primary_module),
                        )
                        written_modules.add(key)

            # 본문 수집
            print(f"[3/3] room 본문 수집")
            success = 0
            for i, r in enumerate(rooms, start=1):
                r.tags = _detect_tags(r)
                try:
                    body = fetch_room_content(ctx, r)
                except Exception as exc:
                    print(f"  [{i}/{len(rooms)}] FAIL {r.slug} - {exc}",
                          file=sys.stderr)
                    continue
                dest = _write_room(r, body)
                tags_str = ",".join(r.tags) if r.tags else "-"
                print(f"  [{i}/{len(rooms)}] {r.slug} ({tags_str}) "
                      f"→ {dest.relative_to(PROJECT_ROOT)}")
                success += 1
                time.sleep(0.5)  # 가벼운 throttle

            manifest_path = _write_manifest(rooms)
            print(f"\nmanifest: {manifest_path.relative_to(PROJECT_ROOT)}")
            print(f"성공 {success}/{len(rooms)}")
        finally:
            ctx.close()
            browser.close()

    return 0


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
