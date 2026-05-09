"""Embedding interface used by both ingestion and query layers.

명세 1.8 + 2.3 의 핵심 — **ingestion 과 query 가 동일한 임베딩 모델을
공유**해야 유사도 비교가 의미 있다. 그 일치를 코드 구조로 강제하기 위해
이 모듈을 양쪽에서 모두 import 한다.

직접 구현해보세요.
"""

from __future__ import annotations

from functools import lru_cache
from typing import Iterable

from config import settings


class _SentenceTransformerBackend:
    """sentence-transformers 기반 로컬 임베딩 백엔드.

    TODO:
      - __init__(self, model_name): SentenceTransformer 로드
      - embed(self, texts) -> list[list[float]]: model.encode 후 .tolist()
    """

    def __init__(self, model_name: str) -> None:
        raise NotImplementedError("_SentenceTransformerBackend.__init__")

    def embed(self, texts: list[str]) -> list[list[float]]:
        raise NotImplementedError("_SentenceTransformerBackend.embed")


class _OpenAIBackend:
    """OpenAI API 기반 임베딩 백엔드.

    TODO:
      - __init__: settings.OPENAI_API_KEY 검증, OpenAI client 생성
      - embed(texts): client.embeddings.create(model, input=texts) 결과를 list[list[float]] 로
    """

    def __init__(self, model_name: str) -> None:
        raise NotImplementedError("_OpenAIBackend.__init__")

    def embed(self, texts: list[str]) -> list[list[float]]:
        raise NotImplementedError("_OpenAIBackend.embed")


@lru_cache(maxsize=1)
def _get_backend():
    """settings.EMBEDDING_MODEL 에 따라 적절한 백엔드를 반환한다.

    TODO:
      - 모델명이 "openai:" 로 시작하면 _OpenAIBackend, 아니면 _SentenceTransformerBackend
      - lru_cache(1) 로 프로세스 단위 싱글턴
    """
    raise NotImplementedError("_get_backend — provider 라우팅 구현하기")


def embed_texts(texts: Iterable[str]) -> list[list[float]]:
    """배치 임베딩.

    TODO:
      - 빈 입력은 [] 반환
      - 그 외엔 _get_backend().embed(list(texts))
    """
    raise NotImplementedError("embed_texts — 배치 호출 구현하기")


def embed_text(text: str) -> list[float]:
    """단일 텍스트 임베딩 — embed_texts 위에 thin wrapper.

    TODO:
      - return embed_texts([text])[0]
    """
    raise NotImplementedError("embed_text — 단일 호출 구현하기")
