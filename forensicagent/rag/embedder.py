"""Embedding interface for forensicagent's tool-metadata RAG.

도구 YAML 인덱싱 시점과 (드물게 발생하는) 자연어 도구 추천 질의 시점이
**같은 임베딩 모델**을 써야 의미 검색이 동작한다. 그 일치를 코드 구조로
강제하기 위해 인덱서와 셀렉터가 모두 이 모듈을 import 한다.

직접 구현해보세요.
"""

from __future__ import annotations

from functools import lru_cache
from typing import Iterable

from forensicagent import config as settings


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
