"""Drop low-quality / irrelevant web search results before injection."""

from __future__ import annotations

from urllib.parse import urlparse

from src.response.web_search_agent import WebResult


# Domains we never want to cite as factual sources.
_BLOCKED_DOMAINS = {
    "pinterest.com",
    "quora.com",
}


def _domain(url: str) -> str:
    try:
        return (urlparse(url).hostname or "").lower()
    except Exception:
        return ""


def filter_results(results: list[WebResult], min_snippet_chars: int = 40) -> list[WebResult]:
    seen_urls: set[str] = set()
    out: list[WebResult] = []
    for r in results:
        if not r.url or not r.snippet:
            continue
        if len(r.snippet.strip()) < min_snippet_chars:
            continue
        host = _domain(r.url)
        if any(host == d or host.endswith("." + d) for d in _BLOCKED_DOMAINS):
            continue
        if r.url in seen_urls:
            continue
        seen_urls.add(r.url)
        out.append(r)
    return out
