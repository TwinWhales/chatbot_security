"""Web search fallback agent (Tavily / SerpAPI).

명세 4.2-1 — 직접 구현해보세요. 키 없으면 빈 리스트 반환.
"""

from __future__ import annotations

from dataclasses import dataclass

from config import settings


@dataclass
class WebResult:
    title: str
    url: str
    snippet: str
    score: float = 0.0


def _search_tavily(query: str, top_k: int) -> list[WebResult]:
    """Tavily API 호출.

    TODO:
      - settings.TAVILY_API_KEY 없으면 []
      - tavily.TavilyClient(api_key=...).search(query, max_results=top_k, search_depth="basic")
      - 결과의 results 리스트를 WebResult 로 매핑
        (title, url, content/snippet, score)
    """
    raise NotImplementedError("_search_tavily")


def _search_serpapi(query: str, top_k: int) -> list[WebResult]:
    """SerpAPI 호출.

    TODO:
      - settings.SERPAPI_API_KEY 없으면 []
      - requests.get("https://serpapi.com/search", params={...})
      - organic_results 의 상위 top_k 를 WebResult 로 매핑
    """
    raise NotImplementedError("_search_serpapi")


def search(query: str, top_k: int | None = None) -> list[WebResult]:
    """provider 라우팅.

    TODO:
      - top_k 기본값: settings.WEB_SEARCH_TOP_K
      - settings.WEB_SEARCH_PROVIDER 에 따라 _search_tavily / _search_serpapi
      - 그 외 provider 면 []
    """
    raise NotImplementedError("search")
