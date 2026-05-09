"""Embed the user query.

This is a thin wrapper around the ingestion-side embedder so both sides
share the exact same model — the spec calls this out as load-bearing for
similarity to be meaningful.
"""

from __future__ import annotations

from src.ingestion import embedder


def embed_query(text: str) -> list[float]:
    return embedder.embed_text(text)
