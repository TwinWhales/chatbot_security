"""Path A: build the RAG prompt and call the LLM.

The function returns just the answer text; source citation is the caller's
job (response_builder), so the LLM doesn't need to know about chunk IDs.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Sequence

from config import settings
from src.knowledge.vector_store import RetrievedChunk


@dataclass
class GeneratedAnswer:
    text: str
    model: str
    provider: str


def _format_context(chunks: Sequence[RetrievedChunk]) -> str:
    blocks: list[str] = []
    for i, c in enumerate(chunks, start=1):
        src = c.metadata.get("source_file", "unknown")
        page = c.metadata.get("page_number", "?")
        blocks.append(
            f"[Context {i}] (source: {src}, p.{page})\n{c.content}"
        )
    return "\n\n".join(blocks)


def build_prompt(query: str, chunks: Sequence[RetrievedChunk]) -> str:
    context = _format_context(chunks) if chunks else "(no context)"
    return (
        "다음은 관련 문서에서 검색된 내용입니다:\n\n"
        f"{context}\n\n"
        "위 내용을 바탕으로 다음 질문에 답변하세요. "
        "답변에 사용한 출처를 반드시 표기하세요.\n\n"
        f"질문: {query}"
    )


def _call_anthropic(prompt: str) -> str:
    import anthropic  # type: ignore

    client = anthropic.Anthropic(api_key=settings.ANTHROPIC_API_KEY)
    msg = client.messages.create(
        model=settings.LLM_MODEL,
        max_tokens=settings.LLM_MAX_TOKENS,
        messages=[{"role": "user", "content": prompt}],
    )
    parts = [b.text for b in msg.content if getattr(b, "type", "") == "text"]
    return "".join(parts).strip()


def _call_openai(prompt: str) -> str:
    from openai import OpenAI  # type: ignore

    client = OpenAI(api_key=settings.OPENAI_API_KEY)
    resp = client.chat.completions.create(
        model=settings.LLM_MODEL,
        max_tokens=settings.LLM_MAX_TOKENS,
        messages=[{"role": "user", "content": prompt}],
    )
    return (resp.choices[0].message.content or "").strip()


def _call_stub(prompt: str, chunks: Sequence[RetrievedChunk]) -> str:
    """Offline fallback so the pipeline still completes without API keys."""
    if not chunks:
        return "[stub] No retrieved context and no LLM configured."
    preview = chunks[0].content[:300].replace("\n", " ")
    return (
        "[stub answer - no LLM API key configured]\n"
        f"Top context: {preview}..."
    )


def generate(query: str, chunks: Sequence[RetrievedChunk]) -> GeneratedAnswer:
    prompt = build_prompt(query, chunks)
    provider = settings.LLM_PROVIDER.lower()

    if provider == "anthropic" and settings.ANTHROPIC_API_KEY:
        return GeneratedAnswer(
            text=_call_anthropic(prompt), model=settings.LLM_MODEL, provider="anthropic"
        )
    if provider == "openai" and settings.OPENAI_API_KEY:
        return GeneratedAnswer(
            text=_call_openai(prompt), model=settings.LLM_MODEL, provider="openai"
        )

    return GeneratedAnswer(
        text=_call_stub(prompt, chunks), model="stub", provider="stub"
    )
