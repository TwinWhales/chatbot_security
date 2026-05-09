"""LangGraph 기반 RAG 파이프라인 스모크 테스트.

검증 항목:
  - ingestion_graph.run() 이 IngestMetrics 와 chunk_ids 를 채워 반환한다
  - query_graph.run() 이 RAG 경로(threshold 충족)에서 정상 답변을 만든다
  - 같은 그래프가 임계 미달 시 web 경로로 분기된다 (conditional edge 동작)
  - 로그 스토어에 metrics JSON 까지 round-trip 된다
  - analytics.full_report 가 stage 별 latency / route 비율을 집계한다
"""

from __future__ import annotations

import hashlib
import shutil
import sys
import tempfile
from pathlib import Path


def _stub_embed(text: str, dim: int = 32) -> list[float]:
    h = hashlib.sha256(text.encode("utf-8")).digest()
    raw = [(h[i % len(h)] - 128) / 128.0 for i in range(dim)]
    norm = sum(x * x for x in raw) ** 0.5 or 1.0
    return [x / norm for x in raw]


def main() -> int:
    try:
        sys.stdout.reconfigure(encoding="utf-8")  # type: ignore[attr-defined]
    except Exception:
        pass

    repo_root = Path(__file__).resolve().parent
    sys.path.insert(0, str(repo_root))

    tmp = Path(tempfile.mkdtemp(prefix="rag_smoke_"))
    import os

    os.environ["CHROMA_PERSIST_DIR"] = str(tmp / "chroma")
    os.environ["LOG_DB_URL"] = f"sqlite:///{tmp / 'logs.db'}"
    os.environ["EMBEDDING_DIMENSION"] = "32"
    for k in ("ANTHROPIC_API_KEY", "OPENAI_API_KEY", "TAVILY_API_KEY"):
        os.environ.pop(k, None)

    from src.graphs import ingestion_graph, query_graph
    from src.ingestion import embedder
    from src.knowledge.knowledge_base import KnowledgeBase
    from src.knowledge.retriever import Retriever
    from src.knowledge.vector_store import VectorStore
    from src.logging import analytics
    from src.logging.log_store import LogStore

    embedder._get_backend.cache_clear()  # type: ignore[attr-defined]

    class _StubBackend:
        def embed(self, texts):
            return [_stub_embed(t) for t in texts]

    embedder._get_backend = lambda: _StubBackend()  # type: ignore[assignment]

    try:
        # ---------- 1) Ingestion graph ----------
        sample_path = tmp / "sample.txt"
        sample_path.write_text(
            "FY2024 Q3 revenue was 12.3 billion KRW, up 18% YoY.\n"
            "Growth was driven by enterprise contracts and APAC expansion.\n"
            "Operating margin improved to 14.2 percent for the quarter.\n",
            encoding="utf-8",
        )
        store = VectorStore()
        ing_state = ingestion_graph.run(sample_path, store=store)
        m_ing = ing_state["metrics"]

        assert m_ing.chunks_written >= 1, "ingest: 최소 1개 chunk 가 저장되어야 한다"
        assert m_ing.file_size_bytes > 0
        assert m_ing.embedding_dimension == 32
        # 그래프가 모든 노드를 거쳤는지 stage_ms 키로 확인
        for st in ("file_load", "text_read", "clean", "chunk", "embed", "tag", "store_write"):
            assert st in m_ing.stage_ms, f"ingest stage {st} missing"
        assert m_ing.total_ms > 0
        print(f"[ok] ingestion graph: stages={list(m_ing.stage_ms.keys())} total={m_ing.total_ms}ms")

        # ---------- 2) Query graph — RAG 경로 ----------
        log_store = LogStore()
        retriever_loose = Retriever(kb=KnowledgeBase(store=store), threshold=-1.0)

        q_state = query_graph.run(
            "What was FY2024 Q3 revenue?",
            store=store,
            retriever=retriever_loose,
            log_store=log_store,
        )
        resp = q_state["response"]
        m_q = resp.metrics

        assert resp.retrieval_source == "rag", f"RAG 경로여야 함, got {resp.retrieval_source}"
        for st in ("preprocess", "query_embed", "retrieve", "llm_generate"):
            assert st in m_q.stage_ms, f"query stage {st} missing"
        assert m_q.similarity.count >= 1
        assert m_q.threshold_met is True
        assert q_state["log_id"]
        print(f"[ok] query graph (RAG): stages={list(m_q.stage_ms.keys())} top={m_q.similarity.top:.3f}")

        # ---------- 3) Query graph — Web fallback 경로 ----------
        retriever_strict = Retriever(kb=KnowledgeBase(store=store), threshold=2.0)
        q_state2 = query_graph.run(
            "Random unrelated question",
            store=store,
            retriever=retriever_strict,
            log_store=log_store,
        )
        resp2 = q_state2["response"]
        m_q2 = resp2.metrics

        assert resp2.retrieval_source == "web", "임계 미달 시 web 경로로 분기되어야 함"
        for st in ("web_search", "web_filter", "llm_generate"):
            assert st in m_q2.stage_ms, f"web stage {st} missing"
        assert m_q2.web_results_raw == 0   # Tavily key 없음
        assert m_q2.web_results_kept == 0
        print(f"[ok] query graph (Web fallback): stages={list(m_q2.stage_ms.keys())}")

        # ---------- 4) 로그 round-trip ----------
        rt = log_store.get(q_state["log_id"])
        assert rt is not None
        assert rt["metrics"] is not None
        assert "stage_ms" in rt["metrics"]
        assert "similarity" in rt["metrics"]
        print(f"[ok] log round-trip: keys={sorted(rt['metrics'])[:5]}")

        # ---------- 5) Analytics 리포트 ----------
        report = analytics.full_report(log_store)
        assert report["totals"]["queries"] == 2
        assert report["totals"]["rag"] == 1
        assert report["totals"]["web"] == 1
        assert "llm_generate" in report["latency_per_stage_ms"]
        assert report["latency_overall_ms"]["count"] == 2
        print(f"[ok] analytics: stages_aggregated={list(report['latency_per_stage_ms'])}")

        print("\nALL LANGGRAPH SMOKE TESTS PASSED")
        return 0
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


if __name__ == "__main__":
    raise SystemExit(main())
