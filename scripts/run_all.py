"""sample.txt 전 파이프라인 마스터 오케스트레이터.

자원별로 다른 워커:
  * Stage 1 (crawl)        : 4 도메인 ThreadPool 동시 (네트워크 I/O 바운드)
  * Stage 3 (RAG index)    : 별도 background thread — Ollama 와 자원 안 겹침
  * Stage 2 (EZTools YAML) : Ollama 직렬 큐
  * Stage 4a (Indicators)  : Ollama 직렬 큐
  * Stage 4b (Goldenset)   : Ollama 직렬 큐

즉 실제 동시 실행:
   [Stage 1 (4-way)] → done →
                     ├─ [Stage 3 RAG  ─── 별도 thread, 즉시 시작 ──────]
                     ├─ [Stage 2 ─┐
                     ├─ [Stage 4a ├─ 동일 Ollama 큐, 순차 처리]
                     └─ [Stage 4b ┘
   ↑ 종료는 Stage 3 가 RAG 가 끝날 때까지 wait

Ollama / sentence-transformers 가 깔려 있지 않으면 해당 단계만 skip 하고
나머지는 그대로 진행 (graceful degradation).

사용:
    python scripts/run_all.py sample.txt
    python scripts/run_all.py sample.txt --skip-rag --skip-llm
    python scripts/run_all.py sample.txt --crawl-workers 6
"""

from __future__ import annotations

import argparse
import logging
import subprocess
import sys
import threading
import time
from pathlib import Path

logger = logging.getLogger("run_all")

REPO_ROOT = Path(__file__).resolve().parent.parent


def _run_module(args: list[str]) -> int:
    """Spawn a child Python process so each stage has clean import state.

    Inject PYTHONPATH=repo_root so `import forensicagent` works from any
    script under scripts/ (which isn't itself a package).
    """
    import os
    env = os.environ.copy()
    existing = env.get("PYTHONPATH", "")
    env["PYTHONPATH"] = (
        f"{REPO_ROOT}{os.pathsep}{existing}" if existing else str(REPO_ROOT)
    )
    cmd = [sys.executable, *args]
    proc = subprocess.Popen(cmd, cwd=str(REPO_ROOT), env=env)
    return proc.wait()


def stage1_crawl(input_path: str, *, max_workers: int, limit: int) -> int:
    print("\n========== Stage 1: crawl ==========")
    args = ["scripts/ingest_sample.py", input_path,
            "--max-workers", str(max_workers)]
    if limit > 0:
        args += ["--limit", str(limit)]
    return _run_module(args)


def stage3_rag_thread(result_holder: dict, overwrite: bool) -> None:
    print("\n========== Stage 3: RAG indexing (background) ==========")
    rc = _run_module(
        ["-m", "forensicagent.rag.indexer",
         "--domains", "cyberdefenders,dfirreport,hacktricks,eztools",
         *(["--overwrite"] if overwrite else [])]
    )
    result_holder["stage3"] = rc


def stage2_yaml_seed(overwrite: bool) -> int:
    print("\n========== Stage 2: EZTools YAML seeding ==========")
    return _run_module(
        ["scripts/yaml_seeder.py", *(["--overwrite"] if overwrite else [])]
    )


def stage4a_indicators(overwrite: bool, limit: int) -> int:
    print("\n========== Stage 4a: indicator candidates ==========")
    args = ["scripts/extract_indicators.py"]
    if overwrite:
        args.append("--overwrite")
    if limit > 0:
        args += ["--limit", str(limit)]
    return _run_module(args)


def stage4b_goldenset(overwrite: bool, limit: int) -> int:
    print("\n========== Stage 4b: golden set ==========")
    args = ["scripts/build_goldenset.py"]
    if overwrite:
        args.append("--overwrite")
    if limit > 0:
        args += ["--limit", str(limit)]
    return _run_module(args)


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("input", nargs="?", default="sample.txt")
    ap.add_argument("--crawl-workers", type=int, default=4)
    ap.add_argument("--limit", type=int, default=0,
                    help="If >0, limit URLs per domain & LLM stage items.")
    ap.add_argument("--skip-rag", action="store_true",
                    help="Skip Stage 3 (RAG indexing).")
    ap.add_argument("--skip-llm", action="store_true",
                    help="Skip Stage 2 + 4a + 4b (Ollama-using stages).")
    ap.add_argument("--skip-crawl", action="store_true",
                    help="Skip Stage 1 (use existing seed_docs).")
    ap.add_argument("--overwrite", action="store_true",
                    help="Re-fetch / re-embed / re-extract everything.")
    args = ap.parse_args(argv)

    logging.basicConfig(level=logging.WARNING,
                        format="%(levelname)s %(name)s: %(message)s")

    start = time.perf_counter()
    statuses: dict[str, int] = {}

    # ---- Stage 1 ----
    if not args.skip_crawl:
        statuses["stage1"] = stage1_crawl(
            args.input, max_workers=args.crawl_workers, limit=args.limit
        )
    else:
        statuses["stage1"] = 0
        print("[run_all] Stage 1 skipped")

    # ---- Stage 3 (RAG, background) starts as soon as crawl is done ----
    rag_holder: dict = {}
    rag_thread: threading.Thread | None = None
    if not args.skip_rag:
        rag_thread = threading.Thread(
            target=stage3_rag_thread, args=(rag_holder, args.overwrite),
            daemon=False,
        )
        rag_thread.start()
    else:
        print("[run_all] Stage 3 skipped")

    # ---- Stage 2 (LLM) ----
    if not args.skip_llm:
        statuses["stage2"] = stage2_yaml_seed(args.overwrite)
        statuses["stage4a"] = stage4a_indicators(args.overwrite, args.limit)
        statuses["stage4b"] = stage4b_goldenset(args.overwrite, args.limit)
    else:
        print("[run_all] Stages 2/4a/4b skipped (--skip-llm)")

    # ---- wait on RAG ----
    if rag_thread is not None:
        print("\n[run_all] waiting for RAG indexer to finish...")
        rag_thread.join()
        statuses["stage3"] = rag_holder.get("stage3", -1)

    elapsed = time.perf_counter() - start
    print(f"\n=========== run_all done in {elapsed:.1f}s ===========")
    for s, rc in statuses.items():
        flag = "OK" if rc == 0 else f"rc={rc}"
        print(f"  {s}: {flag}")
    failed = [s for s, rc in statuses.items() if rc != 0]
    return 0 if not failed else 1


if __name__ == "__main__":
    sys.exit(main())
