"""Same-origin BFS crawler. Fetches via the scope-gated HttpClient, parses
HTML with BeautifulSoup, and collects links, forms and <script src> URLs."""
from __future__ import annotations

from collections import deque
from urllib.parse import urldefrag, urljoin, urlparse

import httpx
from bs4 import BeautifulSoup

from ..http import HttpClient, Session
from ..scope import ScopeError, in_scope

_SKIP_SCHEMES = ("mailto:", "tel:", "javascript:", "data:", "sms:", "#")
_FIELD_TAGS = ("input", "select", "textarea", "button")


def _origin(url: str) -> tuple[str, str, int | None]:
    p = urlparse(url)
    return (p.scheme, (p.hostname or "").lower(), p.port or {"http": 80, "https": 443}.get(p.scheme))


def _normalize(base: str, href: str) -> str | None:
    """Resolve href against base; drop fragments and non-http(s) schemes."""
    href = (href or "").strip()
    if not href or href.lower().startswith(_SKIP_SCHEMES):
        return None
    url = urldefrag(urljoin(base, href))[0]
    return url if urlparse(url).scheme in ("http", "https") else None


def _parse(page_url: str, html: str) -> tuple[list[str], list[dict], list[str]]:
    soup = BeautifulSoup(html, "html.parser")
    base = page_url
    base_tag = soup.find("base", href=True)
    if base_tag:
        base = urljoin(page_url, base_tag["href"])

    links = [u for a in soup.find_all("a", href=True) if (u := _normalize(base, a["href"]))]
    scripts = [u for s in soup.find_all("script", src=True) if (u := _normalize(base, s["src"]))]

    forms = []
    for f in soup.find_all("form"):
        action = _normalize(base, f.get("action", "")) if f.get("action", "").strip() else page_url
        if action is None:  # e.g. action="javascript:..."
            continue
        names = []
        for el in f.find_all(_FIELD_TAGS):
            n = el.get("name")
            if n and n not in names:
                names.append(n)
        forms.append({
            "page": page_url,
            "action": action,
            "method": (f.get("method") or "GET").upper(),
            "inputs": names,
        })
    return links, forms, scripts


async def crawl(
    client: HttpClient,
    seed: str,
    *,
    max_depth: int = 2,
    max_pages: int = 100,
    session: Session | None = None,
    bodies: dict[str, str] | None = None,
) -> dict:
    """Crawl same-origin pages from `seed`.

    If `bodies` is given, each crawled page's HTML is stored in it by URL.

    Returns {pages_crawled, forms, script_urls, discovered_urls}.
    discovered_urls = every same-origin, in-scope URL seen (crawled or not).
    The seed itself is scope-checked by the client and raises ScopeError.
    """
    seed = urldefrag(seed)[0]
    origin = _origin(seed)

    queue: deque[tuple[str, int]] = deque([(seed, 0)])
    seen = {seed}
    discovered: list[str] = [seed]
    pages: list[str] = []
    forms: list[dict] = []
    scripts: list[str] = []

    while queue and len(pages) < max_pages:
        url, depth = queue.popleft()
        try:
            resp = await client.get(url, session=session, follow_redirects=False)
        except ScopeError:
            if url == seed:
                raise
            continue
        except httpx.HTTPError:
            continue

        # Follow redirects manually so every hop stays same-origin + scoped.
        if resp.is_redirect and resp.headers.get("location"):
            target = _normalize(url, resp.headers["location"])
            if target and _origin(target) == origin and in_scope(target) and target not in seen:
                seen.add(target)
                discovered.append(target)
                queue.appendleft((target, depth))
            continue

        if resp.status_code >= 400 or "html" not in resp.headers.get("content-type", "").lower():
            continue

        pages.append(url)
        if bodies is not None:
            bodies[url] = resp.text
        links, page_forms, page_scripts = _parse(url, resp.text)
        forms.extend(page_forms)
        for s in page_scripts:
            if s not in scripts:
                scripts.append(s)

        for link in links:
            if _origin(link) != origin or not in_scope(link) or link in seen:
                continue
            seen.add(link)
            discovered.append(link)
            if depth < max_depth:
                queue.append((link, depth + 1))

    return {
        "pages_crawled": pages,
        "forms": forms,
        "script_urls": scripts,
        "discovered_urls": discovered,
    }
