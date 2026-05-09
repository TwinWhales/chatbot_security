"""RAG 시스템 CLI 엔트리포인트 (LangGraph 기반).

실행 흐름은 두 개의 LangGraph StateGraph 로 분리되어 있다:

- src/graphs/ingestion_graph.py  : Layer 1 (Data Ingestion)
- src/graphs/query_graph.py      : Layer 2 ~ 5 (Query / Knowledge / Response / Logging)

이 파일은 단순히 그래프를 invoke 하고 결과를 콘솔/JSON 으로 출력한다.

서브커맨드:
    ingest <path>        — Layer 1 그래프 실행
    ask <question>       — Layer 2 ~ 5 그래프 실행
    stats                — 벡터 스토어 / 로그 요약
    metrics              — 전체 성능 / 품질 리포트
"""

from __future__ import annotations

import argparse
import json
import sys
from dataclasses import asdict
from pathlib import Path

# 어떤 위치에서 실행되어도 src 패키지가 import 되도록 보정.
sys.path.insert(0, str(Path(__file__).resolve().parent))

from config import settings  # noqa: E402
from src.graphs import ingestion_graph, query_graph  # noqa: E402
from src.knowledge.knowledge_base import KnowledgeBase  # noqa: E402
from src.knowledge.retriever import Retriever  # noqa: E402
from src.knowledge.vector_store import VectorStore  # noqa: E402
from src.logging import analytics  # noqa: E402
from src.logging.log_store import LogStore  # noqa: E402


def _cmd_ingest(args: argparse.Namespace) -> int:
    store = VectorStore()
    final = ingestion_graph.run(args.path, store=store)
    metrics = final["metrics"]
    out = {
        "source_file": metrics.source_file,
        "file_type": metrics.file_type,
        "pages_extracted": metrics.pages_after_clean,
        "chunks_written": metrics.chunks_written,
        "used_ocr": final.get("used_ocr", False),
        "metrics": metrics.to_dict(),
    }
    print(json.dumps(out, ensure_ascii=False, indent=2))
    return 0


def _cmd_ask(args: argparse.Namespace) -> int:
    store = VectorStore()
    retriever = Retriever(kb=KnowledgeBase(store=store))
    log_store = LogStore()

    final = query_graph.run(
        args.question,
        rewrite=args.rewrite,
        store=store,
        retriever=retriever,
        log_store=log_store,
    )
    response = final["response"]
    log_id = final["log_id"]
    retrieval = final["retrieval"]

    if args.json:
        out = {
            "log_id": log_id,
            "answer": response.answer,
            "retrieval_source": response.retrieval_source,
            "top_score": retrieval.top_score,
            "citations": [asdict(c) for c in response.citations],
            "model": response.model,
            "provider": response.provider,
            "response_time_ms": response.response_time_ms,
            "metrics": response.metrics.to_dict(),
        }
        print(json.dumps(out, ensure_ascii=False, indent=2))
    else:
        print(f"=== Answer (source: {response.retrieval_source}) ===")
        print(response.answer)
        print()
        print(f"top_score={retrieval.top_score:.3f}  threshold={settings.SIMILARITY_THRESHOLD}")
        if response.citations:
            print("Sources:")
            for c in response.citations:
                print(f"  - [{c.kind}] {c.label}  ({c.locator})")
        stage = response.metrics.stage_ms
        if stage:
            parts = ", ".join(f"{k}={v}ms" for k, v in stage.items())
            print(f"Stages: {parts}")
        print(f"\n(log_id={log_id}, model={response.model}, total={response.response_time_ms} ms)")
    return 0


def _cmd_stats(_: argparse.Namespace) -> int:
    store = VectorStore()
    log_store = LogStore()
    routes = analytics.route_counts(log_store)
    print(json.dumps(
        {
            "vector_store": {
                "collection": settings.CHROMA_COLLECTION,
                "chunks": store.count(),
            },
            "logs": {
                "total": routes.total,
                "rag": routes.rag,
                "web": routes.web,
                "avg_latency_ms": analytics.average_latency_ms(log_store),
            },
        },
        ensure_ascii=False,
        indent=2,
    ))
    return 0


def _cmd_metrics(_: argparse.Namespace) -> int:
    log_store = LogStore()
    store = VectorStore()
    report = analytics.full_report(log_store)
    report["vector_store"] = {
        "collection": settings.CHROMA_COLLECTION,
        "chunks": store.count(),
        "embedding_model": settings.EMBEDDING_MODEL,
        "embedding_dimension": settings.EMBEDDING_DIMENSION,
    }
    report["config"] = {
        "similarity_threshold": settings.SIMILARITY_THRESHOLD,
        "top_k": settings.TOP_K,
        "chunk_size": settings.CHUNK_SIZE,
        "chunk_overlap": settings.CHUNK_OVERLAP,
        "llm_model": settings.LLM_MODEL,
        "llm_provider": settings.LLM_PROVIDER,
    }
    print(json.dumps(report, ensure_ascii=False, indent=2))
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="rag", description="RAG system CLI (LangGraph-based)")
    sub = parser.add_subparsers(dest="cmd", required=True)

    p_ing = sub.add_parser("ingest", help="Run the ingestion StateGraph on a file")
    p_ing.add_argument("path", help="Path to a file to ingest")
    p_ing.set_defaults(func=_cmd_ingest)

    p_ask = sub.add_parser("ask", help="Run the query StateGraph on a question")
    p_ask.add_argument("question", help="The user question")
    p_ask.add_argument("--rewrite", action="store_true", help="Use LLM to rewrite query")
    p_ask.add_argument("--json", action="store_true", help="Emit JSON instead of human format")
    p_ask.set_defaults(func=_cmd_ask)

    p_st = sub.add_parser("stats", help="Show pipeline stats")
    p_st.set_defaults(func=_cmd_stats)

    p_m = sub.add_parser("metrics", help="Show full performance/quality report")
    p_m.set_defaults(func=_cmd_metrics)

    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
