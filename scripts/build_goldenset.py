"""DFIR Report 사건 분석 → Phase 6 골든 셋 후보.

DFIR Report 의 각 포스트는 한 침해 사건의 처음부터 끝까지를 상세 분석한다.
어떤 evidence 가 있었고, 어떤 도구로 무엇을 잡았는지가 본문에 있어 좋은
정답 데이터의 1차 후보가 된다.

추출 스키마 (LLM 에 강제):
  {
    "case_name": "...",
    "case_summary": "...",
    "evidence_types_present": ["evtx_log", "memory_dump", ...],
    "tools_used": [
      {"tool_id": "chainsaw" | "volatility3" | ..., "purpose": "..."}
    ],
    "ttps": ["T1059.001", ...],            # MITRE ATT&CK if mentioned
    "key_iocs": ["IP 1.2.3.4", "C:\\Users\\Public\\foo.exe", ...]
  }

출력: `eval/goldenset/<slug>.json`. Phase 6 평가 시 forensicagent 가 같은
case 디렉토리를 받았을 때 어떤 도구를 골라야 했는지의 정답으로 활용.
"""

from __future__ import annotations

import argparse
import json
import logging
import sys
import time
from pathlib import Path

from forensicagent.llm import JsonRetryFailed, OllamaClient, OllamaUnavailable
from forensicagent.llm.ollama_client import ChatMessage

logger = logging.getLogger("goldenset")

SEED_DIR = Path("seed_docs/dfirreport")
OUT_DIR = Path("eval/goldenset")
FAIL_DIR = Path("eval/goldenset/_failures")


_SYSTEM_PROMPT = """You read a DFIR Report intrusion writeup and extract a
structured "ground truth" record for forensic-triage evaluation.

Reply with ONLY a JSON object:
{
  "case_name": "<short case slug>",
  "case_summary": "<2-4 sentences>",
  "evidence_types_present": ["memory_dump"|"evtx_log"|"registry_hive"|"pcap"
                             |"disk_image"|"browser_artifact"|"prefetch"
                             |"text_log"|"unknown" ...],
  "tools_used": [
    { "tool_id": "<slug, e.g. chainsaw>", "purpose": "<one sentence>" }
  ],
  "ttps": ["<MITRE ATT&CK technique IDs as mentioned, e.g. T1059.001>"],
  "key_iocs": ["<short ioc strings>"]
}

Rules:
  * Use tool_id slugs that match common DFIR tools when possible: chainsaw,
    volatility3, regripper, yara, plaso, mftecmd, evtxecmd, recmd, tshark,
    sysmon, eric-zimmerman-tools, kape, sleuthkit, autopsy, ftk-imager.
  * If a category of evidence is only inferred (not explicitly mentioned),
    still include it — but mark inferred ones honestly via the "_inferred"
    field of "tools_used" / not at all in evidence_types_present if you are
    not >70% sure.
  * Keep arrays short and high-signal.
"""


def _truncate(text: str, budget: int = 14_000) -> str:
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
    out = OUT_DIR / f"{slug}.json"
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
        json.dumps(parsed, ensure_ascii=False, indent=2),
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
        print(f"[gold] no input dir: {SEED_DIR}. Run ingest first.")
        return 2

    files = sorted(SEED_DIR.glob("*.json"))
    if args.limit > 0:
        files = files[: args.limit]
    if not files:
        print("[gold] nothing to do")
        return 0

    client = OllamaClient()
    ok, detail = client.is_available()
    if not ok:
        print(f"[gold] Ollama unavailable: {detail}")
        return 3

    print(f"[gold] building golden set from {len(files)} reports via {client.model}")
    counts: dict[str, int] = {}
    start = time.perf_counter()
    for i, p in enumerate(files, 1):
        t0 = time.perf_counter()
        slug, status = extract_one(p, client, overwrite=args.overwrite)
        counts[status] = counts.get(status, 0) + 1
        dt = time.perf_counter() - t0
        print(f"  [{i:2d}/{len(files)}] {slug[:50]:50s} → {status} ({dt:.1f}s)")
        if status == "ollama_down":
            break

    print(f"\n[gold] {time.perf_counter() - start:.1f}s total — {counts}")
    print(f"  goldenset → {OUT_DIR}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
