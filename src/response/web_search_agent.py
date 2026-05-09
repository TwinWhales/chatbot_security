"""Web search fallback agent (Tavily / SerpAPI)."""

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
    if not settings.TAVILY_API_KEY:
        return []
    try:
        from tavily import TavilyClient  # type: ignore
    except ImportError:
        return []

    client = TavilyClient(api_key=settings.TAVILY_API_KEY)
    raw = client.search(query=query, max_results=top_k, search_depth="basic")
    out: list[WebResult] = []
    for item in raw.get("results", []):
        out.append(
            WebResult(
                title=item.get("title", ""),
                url=item.get("url", ""),
                snippet=item.get("content", "") or item.get("snippet", ""),
                score=float(item.get("score", 0.0) or 0.0),
            )
        )
    return out


def _search_serpapi(query: str, top_k: int) -> list[WebResult]:
    if not settings.SERPAPI_API_KEY:
        return []
    try:
        import requests  # serpapi has its own SDK but requests is universally available
    except ImportError:
        return []

    resp = requests.get(
        "https://serpapi.com/search",
        params={
            "q": query,
            "api_key": settings.SERPAPI_API_KEY,
            "num": top_k,
        },
        timeout=15,
    )
    resp.raise_for_status()
    data = resp.json()
    out: list[WebResult] = []
    for item in (data.get("organic_results") or [])[:top_k]:
        out.append(
            WebResult(
                title=item.get("title", ""),
                url=item.get("link", ""),
                snippet=item.get("snippet", ""),
            )
        )
    return out


def search(query: str, top_k: int | None = None) -> list[WebResult]:
    k = top_k or settings.WEB_SEARCH_TOP_K
    provider = settings.WEB_SEARCH_PROVIDER.lower()

    if provider == "tavily":
        return _search_tavily(query, k)
    if provider == "serpapi":
        return _search_serpapi(query, k)
    return []
