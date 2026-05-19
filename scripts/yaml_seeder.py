"""EZTools 매뉴얼 → tools_metadata/_draft/*.yaml 자동 시드.

각 매뉴얼은 `seed_docs/eztools/<tool>.json` 의 `{url,title,content}`. Ollama
의 `json_chat` 에 ToolMetadata 스키마를 강제해서 YAML 초안을 생성한다.

핵심 디자인:
  * 결과물은 **검수 대기 영역** (`tools_metadata/_draft/`) 으로 떨어진다.
    사람이 검수한 후 손으로 `tools_metadata/` 로 옮긴다.
  * Pydantic 으로 검증 통과한 것만 저장. 실패하면 raw JSON 을 _failures/
    에 남겨 디버깅.
  * Ollama 가 없으면 깨끗하게 skip + 안내 메시지 (CI / 오프라인 친화).
  * 한 도구씩 직렬 처리 (Ollama 자체가 직렬화되므로 풀 늘려도 의미 없음).

사용:
    python scripts/yaml_seeder.py
    python scripts/yaml_seeder.py --only mftecmd,evtxecmd
    python scripts/yaml_seeder.py --overwrite
"""

from __future__ import annotations

import argparse
import json
import logging
import sys
import time
from pathlib import Path

import yaml
from pydantic import ValidationError

from forensicagent.llm import JsonRetryFailed, OllamaClient, OllamaUnavailable
from forensicagent.llm.ollama_client import ChatMessage
from forensicagent.tools.schema import ToolMetadata

logger = logging.getLogger("yaml_seeder")

SEED_DIR = Path("seed_docs/eztools")
DRAFT_DIR = Path("tools_metadata/_draft")
FAIL_DIR = Path("tools_metadata/_failures")


# These map EZTools manual filenames to roughly applicable evidence types.
# It's a hint to the LLM — if it sees the manual is about "amcacheparser",
# we want applicable_evidence_types to include registry_hive. The LLM may
# override based on actual manual content.
_EVIDENCE_HINTS: dict[str, list[str]] = {
    "amcacheparser":         ["registry_hive"],
    "appcompatcacheparser":  ["registry_hive"],
    "bstrings":              ["unknown"],
    "evtxecmd":              ["evtx_log"],
    "ezviewer":              ["unknown"],
    "hasher":                ["unknown"],
    "iisgeolocate":          ["text_log"],
    "jlecmd":                ["unknown"],
    "lecmd":                 ["unknown"],
    "mftecmd":               ["disk_image"],
    "pecmd":                 ["prefetch"],
    "recmd":                 ["registry_hive"],
    "recentfilecacheparser": ["registry_hive"],
    "rbcmd":                 ["unknown"],
    "rlaexplorer":           ["registry_hive"],
    "sdbexplorer":           ["registry_hive"],
    "shellbagsexplorer":     ["registry_hive"],
    "sqlecmd":               ["browser_artifact"],
    "srumecmd":              ["unknown"],
    "sumecmd":               ["unknown"],
    "timelineexplorer":      ["unknown"],
    "tle":                   ["unknown"],
    "vsccmd":                ["disk_image"],
    "wxtcmd":                ["text_log"],
}


_SYSTEM_PROMPT = """You convert a CLI forensic tool's manual into a strict
ToolMetadata JSON object. The tool runs as a Windows command-line forensic
parser; many of these are from Eric Zimmerman's EZTools suite.

Reply with ONLY a JSON object matching this schema (no prose, no fences):

{
  "tool_id": "<slug, all lowercase, matches the tool's binary name>",
  "display_name": "<human-friendly name>",
  "version_supported": "<semver range or empty>",
  "category": "<one of: log_analysis | registry_analysis | memory_analysis | disk_analysis | network_analysis | timeline | string_extraction | hash | browser_artifact | prefetch | other>",
  "subcategory": "<short kebab tag>",
  "applicable_evidence_types": ["<one or more of: memory_dump, evtx_log, registry_hive, pcap, disk_image, browser_artifact, prefetch, text_log, unknown>"],
  "platform": ["windows" | "linux" | "macos" | "any"],
  "input_format": ["<file extensions or filenames>"],
  "output_format": "json | csv | text | binary",
  "output_size_estimate": "small | medium | large",
  "parallelizable": true,
  "estimated_runtime": "short | medium | long",
  "install_check": { "command": "<exe --help-like>", "expected_pattern": "<substring>" },
  "command_templates": [
    { "name": "<short name>",
      "template": "<command line with {evidence_path} placeholder>",
      "when": "<one sentence: when to pick this template>" }
  ],
  "usage_description": "<2-4 sentences, what the tool does and how it fits in DFIR>",
  "suspicious_indicators": [
    { "id": "<slug>", "pattern": "<one-line natural-language pattern>",
      "severity_baseline": "info|low|medium|high|critical",
      "description": "<one sentence>" }
  ],
  "known_false_positives": ["<1-2 sentences each>"],
  "reference_urls": ["<urls>"]
}

Rules:
  * applicable_evidence_types must be non-empty. Use 'unknown' if truly ambiguous.
  * command_templates must have at least one entry. Use the {evidence_path} placeholder.
  * Prefer short, actionable suspicious_indicators (3-6 items) over long ones.
  * Severity bias: 'low' if unsure. 'high'/'critical' only for clear compromise indicators.
"""


def _user_msg(slug: str, title: str, content: str, hint: list[str]) -> str:
    return (
        f"Tool slug (binary name): {slug}\n"
        f"Manual title: {title}\n"
        f"Evidence-type hint (use as starting point, override if manual disagrees):"
        f" {hint}\n\n"
        f"Manual contents:\n---\n{content}\n---\n\n"
        f"Reply with the JSON object now."
    )


def _truncate(text: str, budget: int = 14_000) -> str:
    if len(text) <= budget:
        return text
    return text[: budget - 500] + "\n\n...[truncated]...\n\n" + text[-400:]


def seed_one(
    path: Path,
    client: OllamaClient,
    *,
    overwrite: bool,
) -> tuple[str, str]:
    """매뉴얼 1 개 → YAML. (slug, status) 반환.

    status ∈ {written, cached, llm_failed, schema_failed, ollama_down}
    """
    slug = path.stem.lower()
    out = DRAFT_DIR / f"{slug}.yaml"
    if out.exists() and not overwrite:
        return slug, "cached"

    doc = json.loads(path.read_text(encoding="utf-8"))
    content = _truncate(doc.get("content", ""))
    title = doc.get("title", slug)
    hint = _EVIDENCE_HINTS.get(slug, ["unknown"])

    try:
        parsed = client.json_chat(
            [
                ChatMessage(role="system", content=_SYSTEM_PROMPT),
                ChatMessage(role="user", content=_user_msg(slug, title, content, hint)),
            ],
            retry=1,
        )
    except OllamaUnavailable as e:
        return slug, "ollama_down"
    except JsonRetryFailed as e:
        FAIL_DIR.mkdir(parents=True, exist_ok=True)
        (FAIL_DIR / f"{slug}.raw.txt").write_text(e.last_raw, encoding="utf-8")
        return slug, "llm_failed"

    if not isinstance(parsed, dict):
        return slug, "llm_failed"

    # The LLM sometimes omits tool_id. Inject from slug.
    parsed.setdefault("tool_id", slug)

    try:
        meta = ToolMetadata(**parsed)
    except ValidationError as e:
        FAIL_DIR.mkdir(parents=True, exist_ok=True)
        (FAIL_DIR / f"{slug}.json").write_text(
            json.dumps(parsed, ensure_ascii=False, indent=2),
            encoding="utf-8",
        )
        (FAIL_DIR / f"{slug}.err.txt").write_text(str(e), encoding="utf-8")
        return slug, "schema_failed"

    DRAFT_DIR.mkdir(parents=True, exist_ok=True)
    out.write_text(
        yaml.safe_dump(
            meta.model_dump(),
            sort_keys=False,
            allow_unicode=True,
            width=120,
        ),
        encoding="utf-8",
    )
    return slug, "written"


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--only", default="",
                    help="Comma-separated tool slugs to process (default: all in seed_docs/eztools).")
    ap.add_argument("--overwrite", action="store_true")
    ap.add_argument("--verbose", "-v", action="store_true")
    args = ap.parse_args(argv)
    logging.basicConfig(
        level=logging.INFO if args.verbose else logging.WARNING,
        format="%(levelname)s %(name)s: %(message)s",
    )

    if not SEED_DIR.exists():
        print(f"[seed] no input dir: {SEED_DIR}. Run ingest_sample.py first.")
        return 2

    files = sorted(SEED_DIR.glob("*.json"))
    if args.only:
        wanted = {s.strip() for s in args.only.split(",")}
        files = [f for f in files if f.stem.lower() in wanted]
    if not files:
        print(f"[seed] no eztools manuals to process")
        return 0

    client = OllamaClient()
    # Quick availability check so we fail fast.
    ok, detail = client.is_available()
    if not ok:
        print(f"[seed] Ollama unavailable: {detail}")
        print("[seed] Skipping Stage 2 (YAML seeder). Run again when Ollama is up.")
        return 3

    print(f"[seed] processing {len(files)} EZTools manuals via {client.model}")
    counts = {"written": 0, "cached": 0, "llm_failed": 0,
              "schema_failed": 0, "ollama_down": 0}
    start = time.perf_counter()
    for i, p in enumerate(files, 1):
        t0 = time.perf_counter()
        slug, status = seed_one(p, client, overwrite=args.overwrite)
        counts[status] = counts.get(status, 0) + 1
        dt = time.perf_counter() - t0
        print(f"  [{i:2d}/{len(files)}] {slug:24s} → {status:14s} ({dt:.1f}s)")
        if status == "ollama_down":
            print("[seed] aborting: Ollama disappeared")
            break

    print(
        f"\n[seed] done in {time.perf_counter() - start:.1f}s — "
        f"written={counts['written']} cached={counts['cached']} "
        f"llm_failed={counts['llm_failed']} schema_failed={counts['schema_failed']}"
    )
    print(f"  drafts → {DRAFT_DIR}")
    if counts["llm_failed"] or counts["schema_failed"]:
        print(f"  failures → {FAIL_DIR}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
