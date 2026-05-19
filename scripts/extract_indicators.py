"""CyberDefenders 블로그 → suspicious_indicators 후보.

각 블로그는 사고 유형/탐지 기법을 자연어로 설명한다. Ollama 에게 JSON
schema 를 강제해서 도구 YAML 의 `suspicious_indicators` 에 추가할 만한
패턴을 추출한다. 사람이 검수 후 해당 도구의 YAML 에 병합.

출력: `seed_docs/_indicator_candidates/<slug>.yaml`
"""

from __future__ import annotations

import argparse
import json
import logging
import sys
import time
from pathlib import Path

import yaml

from forensicagent.llm import JsonRetryFailed, OllamaClient, OllamaUnavailable
from forensicagent.llm.ollama_client import ChatMessage

logger = logging.getLogger("indicators")

SEED_DIR = Path("seed_docs/cyberdefenders")
OUT_DIR = Path("seed_docs/_indicator_candidates")
FAIL_DIR = Path("seed_docs/_indicator_candidates/_failures")


_SYSTEM_PROMPT = """You read a SOC analyst blog post and extract reusable
detection rules as "suspicious_indicators" that a forensic tool's YAML
metadata can host.

For each detection idea in the post, output an indicator with:
  * id:   short kebab slug
  * pattern: ONE line describing what to look for in tool output
  * severity_baseline: info|low|medium|high|critical  (bias low when unsure)
  * description: 1 short sentence
  * tool_hint: which DFIR tool category would surface this - one of:
              evtx (events), volatility (memory), regripper (registry),
              tshark (pcap), yara (signatures), plaso (timeline),
              browser (browser artifacts), eztools (windows artifacts),
              other

Also include `applicable_evidence_types` from:
   memory_dump, evtx_log, registry_hive, pcap, disk_image,
   browser_artifact, prefetch, text_log, unknown

Reply with ONLY a JSON object:
{
  "topic": "<one phrase summarizing what the post is about>",
  "indicators": [ ... up to 8 items ... ]
}
Do not invent things not implied by the post. If the post has no detection
content, return {"topic": "...", "indicators": []}.
"""


def _truncate(text: str, budget: int = 10_000) -> str:
    if len(text) <= budget:
        return text
    return text[: budget - 400] + "\n\n...[truncated]...\n\n" + text[-300:]


def extract_one(
    path: Path,
    client: OllamaClient,
    *,
    overwrite: bool,
) -> tuple[str, str]:
    slug = path.stem
    out = OUT_DIR / f"{slug}.yaml"
    if out.exists() and not overwrite:
        return slug, "cached"

    doc = json.loads(path.read_text(encoding="utf-8"))
    body = _truncate(doc.get("content", ""))
    title = doc.get("title", slug)
    url = doc.get("url", "")

    try:
        parsed = client.json_chat(
            [
                ChatMessage(role="system", content=_SYSTEM_PROMPT),
                ChatMessage(
                    role="user",
                    content=f"Title: {title}\nURL: {url}\n\nBody:\n---\n{body}\n---\n\n"
                            "Return JSON now.",
                ),
            ],
            retry=1,
        )
    except OllamaUnavailable:
        return slug, "ollama_down"
    except JsonRetryFailed as e:
        FAIL_DIR.mkdir(parents=True, exist_ok=True)
        (FAIL_DIR / f"{slug}.raw.txt").write_text(e.last_raw, encoding="utf-8")
        return slug, "llm_failed"

    if not isinstance(parsed, dict):
        return slug, "llm_failed"
    parsed.setdefault("source_url", url)
    parsed.setdefault("source_title", title)

    OUT_DIR.mkdir(parents=True, exist_ok=True)
    out.write_text(
        yaml.safe_dump(parsed, sort_keys=False, allow_unicode=True, width=120),
        encoding="utf-8",
    )
    return slug, "written"


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--overwrite", action="store_true")
    ap.add_argument("--limit", type=int, default=0)
    ap.add_argument("--verbose", "-v", action="store_true")
    args = ap.parse_args(argv)
    logging.basicConfig(
        level=logging.INFO if args.verbose else logging.WARNING,
        format="%(levelname)s %(name)s: %(message)s",
    )

    if not SEED_DIR.exists():
        print(f"[ind] no input dir: {SEED_DIR}. Run ingest first.")
        return 2

    files = sorted(SEED_DIR.glob("*.json"))
    if args.limit > 0:
        files = files[: args.limit]
    if not files:
        print("[ind] nothing to do")
        return 0

    client = OllamaClient()
    ok, detail = client.is_available()
    if not ok:
        print(f"[ind] Ollama unavailable: {detail}")
        return 3

    print(f"[ind] extracting indicators from {len(files)} posts via {client.model}")
    counts: dict[str, int] = {}
    start = time.perf_counter()
    for i, p in enumerate(files, 1):
        t0 = time.perf_counter()
        slug, status = extract_one(p, client, overwrite=args.overwrite)
        counts[status] = counts.get(status, 0) + 1
        dt = time.perf_counter() - t0
        print(f"  [{i:3d}/{len(files)}] {slug[:40]:40s} → {status} ({dt:.1f}s)")
        if status == "ollama_down":
            break

    print(f"\n[ind] {time.perf_counter() - start:.1f}s total - {counts}")
    print(f"  candidates → {OUT_DIR}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
