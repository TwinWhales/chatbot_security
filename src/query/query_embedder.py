"""Embed the user query.

명세 2.3 의 핵심 — **반드시 ingestion 과 동일한 임베딩 모델**을 써야 한다.
이를 코드 구조로 강제하기 위해 ingestion.embedder 를 직접 호출하는 얇은
래퍼로 둔다.

직접 구현해보세요.
"""

from __future__ import annotations

from src.ingestion import embedder


def embed_query(text: str) -> list[float]:
    """질문을 단일 벡터로 임베딩한다.

    TODO:
      - return embedder.embed_text(text)
      (한 줄. ingestion 과의 일치성을 코드로 보장하는 게 이 모듈의 핵심.)
    """
    raise NotImplementedError("embed_query — embedder.embed_text 위임 구현하기")
