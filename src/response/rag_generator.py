"""Path A: build the RAG prompt and call the LLM.

명세 4.1 / 4.3 — 직접 구현해보세요.
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
    """검색된 청크들을 LLM 컨텍스트 문자열로 포맷.

    TODO:
      - 청크마다 "[Context i] (source: <source_file>, p.<page>)\\n<content>" 블록
      - 블록 사이는 \\n\\n 로 구분
    """
    raise NotImplementedError("_format_context")


def build_prompt(query: str, chunks: Sequence[RetrievedChunk]) -> str:
    """명세 4.1 의 한국어 템플릿으로 프롬프트 구성.

    TODO: 다음 형식의 단일 문자열을 반환
        다음은 관련 문서에서 검색된 내용입니다:

        {_format_context(chunks)}

        위 내용을 바탕으로 다음 질문에 답변하세요.
        답변에 사용한 출처를 반드시 표기하세요.

        질문: {query}
    """
    raise NotImplementedError("build_prompt")


def _call_anthropic(prompt: str) -> str:
    """Anthropic SDK 로 LLM 호출.

    TODO:
      - anthropic.Anthropic(api_key=settings.ANTHROPIC_API_KEY)
      - client.messages.create(model, max_tokens, messages=[{"role":"user","content":prompt}])
      - 응답 content 의 text 블록만 join 해 반환
    """
    raise NotImplementedError("_call_anthropic")


def _call_openai(prompt: str) -> str:
    """OpenAI Chat Completion 호출.

    TODO:
      - OpenAI(api_key=settings.OPENAI_API_KEY)
      - client.chat.completions.create(model, max_tokens, messages=[...])
      - choices[0].message.content 반환
    """
    raise NotImplementedError("_call_openai")


def _call_stub(prompt: str, chunks: Sequence[RetrievedChunk]) -> str:
    """API 키가 없을 때의 폴백 — 파이프라인이 끊기지 않도록 가짜 답변.

    TODO:
      - 청크가 없으면 "[stub] No retrieved context and no LLM configured."
      - 있으면 첫 청크 미리보기를 포함한 stub 메시지
    """
    raise NotImplementedError("_call_stub")


def generate(query: str, chunks: Sequence[RetrievedChunk]) -> GeneratedAnswer:
    """provider 라우팅 후 답변 생성.

    TODO:
      - prompt = build_prompt(query, chunks)
      - settings.LLM_PROVIDER 와 키 유무에 따라 _call_anthropic / _call_openai / _call_stub
      - GeneratedAnswer(text, model=settings.LLM_MODEL or "stub", provider=...)
    """
    raise NotImplementedError("generate")
