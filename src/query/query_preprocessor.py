"""Normalize and (optionally) rewrite a user query before embedding."""

from __future__ import annotations

import re
import unicodedata
from dataclasses import dataclass

from config import settings


_WS = re.compile(r"\s+")


@dataclass
class PreprocessedQuery:
    original: str
    processed: str
    rewritten: bool


def _normalize(text: str) -> str:
    text = unicodedata.normalize("NFKC", text)
    text = _WS.sub(" ", text).strip()
    return text


def _rewrite_with_llm(query: str) -> str | None:
    """Best-effort LLM-based rewriting; returns None when unavailable.

    Falls through silently if no API key — preprocessing should never break
    the request path just because rewriting is unconfigured.
    """
    if not settings.ANTHROPIC_API_KEY:
        return None
    try:
        import anthropic  # type: ignore
    except ImportError:
        return None

    try:
        client = anthropic.Anthropic(api_key=settings.ANTHROPIC_API_KEY)
        msg = client.messages.create(
            model=settings.LLM_MODEL,
            max_tokens=200,
            messages=[
                {
                    "role": "user",
                    "content": (
                        "Rewrite the following question into a single self-contained "
                        "search query optimized for semantic retrieval. "
                        "Return only the rewritten query, no preamble.\n\n"
                        f"Question: {query}"
                    ),
                }
            ],
        )
        parts = [b.text for b in msg.content if getattr(b, "type", "") == "text"]
        rewritten = "".join(parts).strip()
        return rewritten or None
    except Exception:
        return None


def preprocess(query: str, *, rewrite: bool = False) -> PreprocessedQuery:
    normalized = _normalize(query)
    if not normalized:
        raise ValueError("Empty query after normalization")

    if rewrite:
        candidate = _rewrite_with_llm(normalized)
        if candidate:
            return PreprocessedQuery(
                original=query, processed=candidate, rewritten=True
            )

    return PreprocessedQuery(original=query, processed=normalized, rewritten=False)
