"""Drop low-quality / irrelevant web search results before injection.

명세 4.2-2 — 직접 구현해보세요.
"""

from __future__ import annotations

from src.response.web_search_agent import WebResult


# 사실 정보의 인용처로 부적절한 도메인 (예시).
_BLOCKED_DOMAINS = {
    "pinterest.com",
    "quora.com",
}


def filter_results(results: list[WebResult], min_snippet_chars: int = 40) -> list[WebResult]:
    """결과를 정제: 빈 URL/스니펫, 짧은 스니펫, 차단 도메인, 중복 URL 제거.

    TODO:
      1. URL/snippet 비어 있으면 skip
      2. snippet.strip() 길이 < min_snippet_chars 면 skip
      3. urlparse(url).hostname 이 _BLOCKED_DOMAINS 또는 그 서브도메인이면 skip
      4. 이미 본 URL 이면 skip (set 으로 추적)
      5. 통과한 결과만 list 로 반환
    """
    raise NotImplementedError("filter_results")
