"""Playwright-first Browser Crawler (Phase 2.1b).

Uses headless Chromium as the PRIMARY crawl method instead of httpx.
Intercepts network requests (XHR/fetch) to discover API endpoints.
Extracts links, forms, and scripts from the rendered DOM.

Falls back to the static Crawler if Playwright is unavailable.
"""
from __future__ import annotations

import asyncio
import logging
import re
from collections import deque
from dataclasses import dataclass, field
from urllib.parse import urljoin, urlparse, parse_qs, urlencode

from ..http import HttpClient, Session
from ..scope import in_scope

logger = logging.getLogger(__name__)

_SKIP_EXTENSIONS = frozenset({
    ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".bmp", ".webp",
    ".css", ".map", ".woff", ".woff2", ".ttf", ".eot", ".otf",
    ".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx",
    ".zip", ".tar", ".gz", ".rar", ".7z",
    ".mp3", ".mp4", ".avi", ".mov", ".webm", ".ogg",
})

_API_CONTENT_TYPES = ("application/json", "application/xml", "text/xml")

_USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/125.0.0.0 Safari/537.36"
)


@dataclass
class InterceptedRequest:
    url: str
    method: str
    resource_type: str
    post_data: str | None = None


class BrowserCrawler:
    """Playwright-based BFS crawler that renders JS and intercepts network calls."""

    def __init__(
        self,
        client: HttpClient,
        session: Session | None = None,
        *,
        base_url: str = "",
        max_depth: int = 3,
        max_pages: int = 100,
    ):
        self.client = client
        self.session = session
        self.base_url = base_url.rstrip("/") if base_url else ""
        self.max_depth = max_depth
        self.max_pages = max_pages
        self._base_host = urlparse(self.base_url).hostname or ""
        self._intercepted: list[InterceptedRequest] = []

    async def crawl(self) -> dict:
        """BFS crawl using headless Chromium. Returns pipeline-compatible dict."""
        from playwright.async_api import async_playwright

        pages_crawled: list[str] = []
        forms: list[dict] = []
        script_urls: list[str] = []
        errors: list[str] = []
        bodies: dict[str, str] = {}

        visited: set[str] = set()
        queue: deque[tuple[str, int]] = deque()
        start = self.base_url or ""
        if not start:
            return {"pages_crawled": [], "forms": [], "script_urls": [], "errors": ["No start URL"]}

        queue.append((start, 0))

        async with async_playwright() as pw:
            browser = await pw.chromium.launch(headless=True)
            context = await browser.new_context(
                user_agent=_USER_AGENT,
                extra_http_headers={
                    "Accept-Language": "en-US,en;q=0.9",
                },
            )

            if self.session:
                cookies = []
                all_cookies = dict(self.session.cookies or {})
                if self.session.jsessionid:
                    all_cookies["JSESSIONID"] = self.session.jsessionid
                parsed = urlparse(self.base_url)
                domain = parsed.hostname or ""
                for name, value in all_cookies.items():
                    cookies.append({
                        "name": name,
                        "value": value,
                        "domain": domain,
                        "path": "/",
                    })
                if cookies:
                    await context.add_cookies(cookies)

            try:
                while queue and len(pages_crawled) < self.max_pages:
                    url, depth = queue.popleft()
                    canonical = self._canonical(url)
                    if canonical in visited:
                        continue
                    visited.add(canonical)

                    if not self._should_visit(url):
                        continue

                    page = await context.new_page()
                    page_intercepted: list[InterceptedRequest] = []

                    def on_request(req):
                        rt = req.resource_type
                        if rt in ("xhr", "fetch", "document"):
                            page_intercepted.append(InterceptedRequest(
                                url=req.url,
                                method=req.method,
                                resource_type=rt,
                                post_data=req.post_data,
                            ))

                    page.on("request", on_request)

                    try:
                        resp = await page.goto(url, wait_until="domcontentloaded", timeout=30000)
                        await asyncio.sleep(2)

                        if resp and resp.status >= 400:
                            errors.append(f"{url}: HTTP {resp.status}")
                            await page.close()
                            continue

                        html = await page.content()
                        bodies[url] = html
                        pages_crawled.append(url)

                        links = await self._extract_links(page, url)
                        page_forms = await self._extract_forms(page, url)
                        page_scripts = await self._extract_scripts(page, url)

                        forms.extend(page_forms)
                        for s in page_scripts:
                            if s not in script_urls:
                                script_urls.append(s)

                        self._intercepted.extend(page_intercepted)

                        if depth < self.max_depth:
                            for link in links:
                                lc = self._canonical(link)
                                if lc not in visited and self._should_visit(link):
                                    queue.append((link, depth + 1))

                    except Exception as exc:
                        errors.append(f"{url}: {exc}")
                    finally:
                        await page.close()

            finally:
                await browser.close()

        api_endpoints = self._extract_api_endpoints()

        return {
            "pages_crawled": pages_crawled,
            "forms": forms,
            "script_urls": script_urls,
            "errors": errors,
            "bodies": bodies,
            "intercepted_apis": api_endpoints,
        }

    async def _extract_links(self, page, base_url: str) -> list[str]:
        links: list[str] = []
        try:
            hrefs = await page.eval_on_selector_all(
                "a[href]", "els => els.map(e => e.href)"
            )
            for href in hrefs:
                resolved = self._resolve(href, base_url)
                if resolved and not self._is_skip_ext(resolved):
                    links.append(resolved)
        except Exception:
            pass
        return list(dict.fromkeys(links))

    async def _extract_forms(self, page, base_url: str) -> list[dict]:
        forms: list[dict] = []
        try:
            raw_forms = await page.evaluate("""() => {
                return Array.from(document.querySelectorAll('form')).map(form => {
                    const fields = Array.from(
                        form.querySelectorAll('input[name], textarea[name], select[name]')
                    ).map(el => ({
                        name: el.name,
                        type: (el.type || 'text').toLowerCase(),
                    })).filter(f => !['submit','button','image','reset'].includes(f.type));
                    return {
                        action: form.action || '',
                        method: (form.method || 'GET').toUpperCase(),
                        fields: fields,
                    };
                });
            }""")
            for f in raw_forms:
                action = f.get("action", "")
                if not action:
                    action = base_url
                elif not action.startswith("http"):
                    action = urljoin(base_url, action)
                fields = f.get("fields", [])
                if fields or action:
                    forms.append({
                        "action": action,
                        "method": f.get("method", "GET"),
                        "fields": fields,
                        "source_page": base_url,
                    })
        except Exception:
            pass
        return forms

    async def _extract_scripts(self, page, base_url: str) -> list[str]:
        scripts: list[str] = []
        try:
            srcs = await page.eval_on_selector_all(
                "script[src]", "els => els.map(e => e.src)"
            )
            for src in srcs:
                resolved = self._resolve(src, base_url)
                if resolved:
                    scripts.append(resolved)
        except Exception:
            pass
        return scripts

    def _extract_api_endpoints(self) -> list[dict]:
        seen: set[str] = set()
        endpoints: list[dict] = []
        for req in self._intercepted:
            if req.resource_type in ("xhr", "fetch"):
                key = f"{req.method}:{req.url}"
                if key not in seen:
                    seen.add(key)
                    endpoints.append({
                        "url": req.url,
                        "method": req.method,
                        "has_body": bool(req.post_data),
                    })
        return endpoints

    def _should_visit(self, url: str) -> bool:
        if self._is_skip_ext(url):
            return False
        if not in_scope(url):
            return False
        parsed = urlparse(url)
        if (parsed.hostname or "").lower() != self._base_host.lower():
            return False
        return True

    def _resolve(self, href: str, base: str) -> str | None:
        if not href:
            return None
        for scheme in ("javascript:", "mailto:", "tel:", "data:", "blob:"):
            if href.lower().startswith(scheme):
                return None
        try:
            resolved = urljoin(base, href)
            parsed = urlparse(resolved)
            return parsed._replace(fragment="").geturl()
        except Exception:
            return None

    @staticmethod
    def _is_skip_ext(url: str) -> bool:
        path = urlparse(url).path.lower()
        return any(path.endswith(ext) for ext in _SKIP_EXTENSIONS)

    @staticmethod
    def _canonical(url: str) -> str:
        parsed = urlparse(url)
        host = (parsed.hostname or "").lower()
        port = f":{parsed.port}" if parsed.port and parsed.port not in (80, 443) else ""
        path = parsed.path or "/"
        if path != "/" and path.endswith("/"):
            path = path.rstrip("/")
        query = ""
        if parsed.query:
            params = parse_qs(parsed.query, keep_blank_values=True)
            query = "?" + urlencode(sorted(params.items()), doseq=True)
        return f"{parsed.scheme}://{host}{port}{path}{query}"
