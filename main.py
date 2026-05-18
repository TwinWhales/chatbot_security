"""RAG 시스템 CLI 엔트리포인트 (LangGraph 기반).

argparse 골격은 frame 으로 유지하고, 각 _cmd_* 함수의 본문을 직접 채워보세요.
서브커맨드는 두 그래프를 invoke 하는 thin layer 입니다.

서브커맨드:
    ingest <path>        — Layer 1 그래프 실행
    ask <question>       — Layer 2 ~ 5 그래프 실행
    stats                — 벡터 스토어 / 로그 요약
    metrics              — 전체 성능 / 품질 리포트
"""

from __future__ import annotations

import argparse
import sys
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
    """ingestion_graph.run() 을 호출하고 metrics 를 JSON 으로 출력.

    args.path 가 파일이면 1회, 디렉토리면 안의 지원 확장자(.pdf/.txt/.md/
    .docx) 를 모두 순회하며 N 회 호출한다. `seed_docs/` 를 통째로 인덱싱
    하는 시나리오를 지원한다.

    TODO:
      - VectorStore 인스턴스 생성 (한 번만 — 모든 파일이 같은 컬렉션에 들어감)
      - p = Path(args.path)
        - p.is_file() 면: ingestion_graph.run(p, store=store) 한 번
        - p.is_dir() 면: 지원 확장자 파일만 골라 정렬 후 순회
            * 각 파일마다 ingestion_graph.run(file, store=store)
            * 실패한 파일은 에러 메시지만 출력하고 다음 파일로 계속
      - 결과 출력:
        - 파일 1개: final state 의 metrics 를 json.dumps
        - 디렉토리: 파일별 {source, metrics, chunk_ids} 의 list 로 묶어 json.dumps
      - return 0  (전체 실패 시에만 1)
    """
    raise NotImplementedError("_cmd_ingest")


def _cmd_ask(args: argparse.Namespace) -> int:
    """query_graph.run() 을 호출하고 답변/citation/timings 를 출력.

    TODO:
      - VectorStore + Retriever + LogStore 의존성 구성
      - query_graph.run(args.question, rewrite=args.rewrite, store=..., retriever=..., log_store=...)
      - final state 의 response 를 args.json 여부에 따라 사람용/JSON 형식으로 출력
      - 사람용은 답변 + top_score + citations + 노드별 timing + log_id 표시
      - return 0
    """
    raise NotImplementedError("_cmd_ask")


def _cmd_stats(_: argparse.Namespace) -> int:
    """벡터 스토어 청크 수 + 로그 route 카운트 + 평균 latency 출력.

    TODO:
      - analytics.route_counts(log_store) / average_latency_ms(log_store)
      - VectorStore.count() 도 포함
      - json.dumps 로 출력
    """
    raise NotImplementedError("_cmd_stats")


def _cmd_metrics(_: argparse.Namespace) -> int:
    """analytics.full_report 결과에 vector_store 정보와 config 스냅샷을 덧붙여 출력.

    TODO:
      - report = analytics.full_report(log_store)
      - report["vector_store"] / report["config"] 채우기
      - json.dumps 로 출력
    """
    raise NotImplementedError("_cmd_metrics")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="rag", description="RAG system CLI (LangGraph-based)")
    sub = parser.add_subparsers(dest="cmd", required=True)

    p_ing = sub.add_parser("ingest", help="Run the ingestion StateGraph on a file or directory")
    p_ing.add_argument(
        "path",
        help="Path to a file or directory. If a directory, all supported files "
             "(.pdf/.txt/.md/.docx) inside are ingested in sequence — useful "
             "for seeding the knowledge base from seed_docs/.",
    )
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
