"""Thin Ollama client with structured-output discipline.

로컬 LLM 의 두 가지 신뢰성 이슈를 흡수한다:
  1. JSON 출력이 깨지면 한 번 더 시도, 실패 시 명확한 예외 → 룰 fallback
  2. 모델/데몬이 없으면 OllamaUnavailable — Selector/Analyzer 가 잡아
     graceful degradation 으로 분기

Lazy import: ollama 패키지는 CLI 부팅과 무관하므로 chat 호출 시점에만 import.
"""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass
from typing import Any, Iterable

from forensicagent import config as settings

logger = logging.getLogger(__name__)


class OllamaUnavailable(RuntimeError):
    """ollama 데몬 또는 지정 모델이 사용 불가."""


class JsonRetryFailed(ValueError):
    """JSON 으로 응답하라고 강제했는데 두 번 모두 파싱 실패."""

    def __init__(self, message: str, last_raw: str) -> None:
        super().__init__(message)
        self.last_raw = last_raw


@dataclass
class ChatMessage:
    role: str   # "system" | "user" | "assistant"
    content: str

    def to_dict(self) -> dict[str, str]:
        return {"role": self.role, "content": self.content}


class OllamaClient:
    """forensicagent 의 모든 LLM 호출이 통과하는 단일 진입점."""

    def __init__(
        self,
        base_url: str | None = None,
        model: str | None = None,
        temperature: float | None = None,
    ) -> None:
        self.base_url = base_url or settings.LLM_BASE_URL
        self.model = model or settings.LLM_MODEL
        self.temperature = (
            temperature if temperature is not None else settings.LLM_TEMPERATURE
        )

    # ---------- low level ----------

    def _client(self):
        # Lazy import — ollama 패키지가 없거나 데몬이 죽었을 때
        # forensicagent 자체는 부팅되어야 한다 (doctor 가 그걸 알려줘야 함).
        try:
            import ollama  # type: ignore
        except ImportError as e:
            raise OllamaUnavailable(
                "ollama python package not installed (pip install ollama)"
            ) from e
        return ollama.Client(host=self.base_url)

    def is_available(self) -> tuple[bool, str]:
        """doctor 가 쓰기 좋은 형태로 가용성 점검.

        반환: (ok, detail_message)
        """
        try:
            client = self._client()
        except OllamaUnavailable as e:
            return False, str(e)

        try:
            models = client.list()
        except Exception as e:  # noqa: BLE001
            return False, f"cannot reach ollama at {self.base_url}: {e}"

        names = [m.get("name", "") for m in models.get("models", [])]
        if self.model not in names and not any(
            n.startswith(self.model.split(":")[0] + ":") for n in names
        ):
            return False, (
                f"ollama is reachable but model '{self.model}' not pulled. "
                f"Available: {', '.join(names) or '(none)'}"
            )
        return True, f"ollama ok, model {self.model} ready ({len(names)} pulled)"

    # ---------- text chat ----------

    def chat(
        self,
        messages: Iterable[ChatMessage | dict[str, str]],
        *,
        temperature: float | None = None,
    ) -> str:
        """plain text chat. 빈 응답이면 빈 문자열 반환."""
        try:
            client = self._client()
        except OllamaUnavailable:
            raise

        msgs = [m.to_dict() if isinstance(m, ChatMessage) else m for m in messages]
        try:
            resp = client.chat(
                model=self.model,
                messages=msgs,
                options={
                    "temperature": (
                        temperature if temperature is not None else self.temperature
                    ),
                },
            )
        except Exception as e:  # noqa: BLE001
            raise OllamaUnavailable(f"ollama chat failed: {e}") from e
        return (resp.get("message") or {}).get("content", "") or ""

    # ---------- structured JSON chat ----------

    def json_chat(
        self,
        messages: Iterable[ChatMessage | dict[str, str]],
        *,
        temperature: float | None = None,
        retry: int = 1,
    ) -> dict[str, Any] | list[Any]:
        """JSON 강제 응답. 파싱 실패 시 retry 번 재시도 후 JsonRetryFailed.

        format="json" 옵션과 함께, 시스템 메시지를 마지막에 한 줄 더 박아
        모델이 산문 답변을 섞지 않도록 강제한다.
        """
        try:
            client = self._client()
        except OllamaUnavailable:
            raise

        base_msgs = [
            m.to_dict() if isinstance(m, ChatMessage) else dict(m) for m in messages
        ]
        attempts = retry + 1
        last_raw = ""
        last_err = ""

        for attempt in range(attempts):
            msgs = list(base_msgs)
            if attempt > 0:
                # 보강: 이전 응답이 깨졌으니 JSON 만 달라고 명시.
                msgs.append(
                    {
                        "role": "user",
                        "content": (
                            "Your previous reply could not be parsed as JSON. "
                            "Reply ONLY with a single valid JSON value — no prose, "
                            "no markdown fences, no commentary."
                        ),
                    }
                )
            try:
                resp = client.chat(
                    model=self.model,
                    messages=msgs,
                    format="json",
                    options={
                        "temperature": (
                            temperature
                            if temperature is not None
                            else self.temperature
                        ),
                    },
                )
            except Exception as e:  # noqa: BLE001
                raise OllamaUnavailable(f"ollama json_chat failed: {e}") from e

            last_raw = (resp.get("message") or {}).get("content", "") or ""
            try:
                return json.loads(last_raw)
            except json.JSONDecodeError as e:
                last_err = str(e)
                logger.warning(
                    "json_chat parse attempt %d/%d failed: %s",
                    attempt + 1,
                    attempts,
                    last_err,
                )

        raise JsonRetryFailed(
            f"JSON parse failed after {attempts} attempt(s): {last_err}",
            last_raw=last_raw,
        )
