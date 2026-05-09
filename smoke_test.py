"""LangGraph 기반 RAG 파이프라인 스모크 테스트 (frame).

frame branch 에서는 노드 본문이 모두 NotImplementedError 이므로 실행하면
첫 번째 노드부터 폭발한다. 이 파일은 **구현이 끝났을 때 무엇을 검증할지**의
스펙으로 남겨둔다 — 함수 본문을 채워가며 단계별로 통과시켜 보세요.

기대 동작 (모두 구현되었을 때):
  1. ingestion_graph.run() 이 IngestMetrics 와 chunk_ids 를 채워 반환
  2. query_graph.run() 이 RAG 경로(threshold 충족) 에서 정상 답변 생성
  3. 같은 그래프가 임계 미달 시 web 경로로 분기 (conditional edge 동작)
  4. 로그 스토어가 metrics JSON 까지 round-trip
  5. analytics.full_report 가 stage 별 latency / route 비율 집계
"""

from __future__ import annotations


def main() -> int:
    """TODO: 구현이 진행되면서 단계적으로 다음 검증을 추가해보세요.

    힌트:
      - 임시 디렉토리에서 chroma persist + sqlite log DB 사용
      - ANTHROPIC_API_KEY / OPENAI_API_KEY / TAVILY_API_KEY 는 unset 으로 두고
        stub 답변 / 빈 웹결과로 그래프가 끝까지 흐르는지 확인
      - sentence-transformers 로딩이 무겁다면 hashlib 기반의 deterministic stub
        embedder 로 src.ingestion.embedder._get_backend 를 monkey-patch
      - Retriever 의 threshold 를 -1.0 / 2.0 으로 강제해 두 분기 모두 트리거
    """
    raise NotImplementedError(
        "smoke_test 는 구현이 완료된 후 채워보세요 — 구조 힌트는 docstring 참고"
    )


if __name__ == "__main__":
    raise SystemExit(main())
