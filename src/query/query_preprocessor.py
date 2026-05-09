"""Normalize and (optionally) rewrite a user query before embedding.

명세 2.1 / 2.2 — 직접 구현해보세요.
"""

from __future__ import annotations

from dataclasses import dataclass

from config import settings


@dataclass
class PreprocessedQuery:
    original: str
    processed: str
    rewritten: bool


def _normalize(text: str) -> str:
    """유니코드/공백 정규화.

    TODO:
      - unicodedata.normalize("NFKC", text)
      - 연속 공백 → 단일 스페이스, 양끝 strip
    """
    raise NotImplementedError("_normalize — 정규화 구현하기")


def _rewrite_with_llm(query: str) -> str | None:
    """LLM 으로 검색 친화적 형태로 재구성. 키 없으면 None.

    TODO (best-effort):
      - settings.ANTHROPIC_API_KEY 없으면 None
      - anthropic SDK 없으면 None
      - client.messages.create 로 "Rewrite the following question into a single
        self-contained search query" 요청
      - 실패 시 None (예외를 흘려보내지 말 것 — 파이프라인을 막으면 안 됨)
    """
    raise NotImplementedError("_rewrite_with_llm — LLM rewriting 구현하기")


def preprocess(query: str, *, rewrite: bool = False) -> PreprocessedQuery:
    """정규화 후 (선택적으로) LLM rewriting 적용.

    TODO:
      1. _normalize → 빈 문자열이면 ValueError
      2. rewrite=True 이고 _rewrite_with_llm 결과가 있으면 그걸 processed 로
      3. 아니면 정규화된 텍스트가 processed
      4. PreprocessedQuery 반환
    """
    raise NotImplementedError("preprocess — 전처리 파이프라인 구현하기")
