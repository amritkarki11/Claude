"""HTML Crawler (Phase 2.1).

Breadth-first spider that discovers pages, forms, and link-based endpoints
within scope. Respects scope guard, depth limits, and rate limiting
(all handled by the underlying HttpClient).

Usage:
    crawler = Crawler(client, session, base_url="https://app.example.com")
    result = await crawler.crawl()
    for page in result.pages:
        print(page.url, page.forms, page.links)
"""
from __future__ import annotations

import hashlib
import logging
import re
import uuid
from collections import deque
from dataclasses import dataclass, field
from difflib import SequenceMatcher
from typing import Any
from urllib.parse import urljoin, urlparse, parse_qs, urlencode

from ..http import HttpClient, Session
from ..scope import in_scope

logger = logging.getLogger(__name__)

# ── HTML parsing patterns ──────────────────────────────────────

_HREF = re.compile(
    r"""<a\s[^>]*href\s*=\s*["']([^"']+)["']""",
    re.IGNORECASE,
)

_FORM = re.compile(
    r"""<form(?:\s[^>]*)?>(.+?)</form>""",
    re.IGNORECASE | re.DOTALL,
)

_FORM_ACTION = re.compile(
    r"""action\s*=\s*["']([^"']*)["']""",
    re.IGNORECASE,
)

_FORM_METHOD = re.compile(
    r"""method\s*=\s*["']?(GET|POST|PUT|DELETE|PATCH)["']?""",
    re.IGNORECASE,
)

_INPUT = re.compile(
    r"""<(?:input|textarea|select)\s[^>]*name\s*=\s*["']([^"']+)["']""",
    re.IGNORECASE,
)

_INPUT_TYPE = re.compile(
    r"""type\s*=\s*["']([^"']+)["']""",
    re.IGNORECASE,
)

_META_REDIRECT = re.compile(
    r"""<meta\s[^>]*content\s*=\s*["'][^"']*url=([^"';]+)""",
    re.IGNORECASE,
)

_LINK_HREF = re.compile(
    r"""<link\s[^>]*href\s*=\s*["']([^"']+)["']""",
    re.IGNORECASE,
)

# Interesting resource patterns (API endpoints in data attributes, etc.)
_DATA_URL = re.compile(
    r"""data-(?:url|href|src|action|endpoint|api)\s*=\s*["']([^"']+)["']""",
    re.IGNORECASE,
)

# ── Soft-404 detection ────────────────────────────────────────

# Body-level indicators that a 200 response is actually a "not found" page
_SOFT_404_BODY_PATTERNS = [
    re.compile(r"\b404\b.*\b(not\s+found|error)\b", re.IGNORECASE),
    re.compile(r"\b(page|resource|url|file|endpoint)\s+(was\s+)?(not\s+found|does\s*n[o']?t\s+exist|could\s+not\s+be\s+found|cannot\s+be\s+found|is\s+no\s+longer\s+available)", re.IGNORECASE),
    re.compile(r"\b(not\s+found|doesn't\s+exist|does\s+not\s+exist)\b", re.IGNORECASE),
    re.compile(r"<title>[^<]*(404|not\s+found)[^<]*</title>", re.IGNORECASE),
    re.compile(r"<h[1-3][^>]*>[^<]*(404|not\s+found|page\s+missing)[^<]*</h[1-3]>", re.IGNORECASE),
    re.compile(r"\bthe\s+requested\s+(url|page|resource)\s+(was\s+)?not\s+found\b", re.IGNORECASE),
    re.compile(r"\bno\s+such\s+(page|resource|endpoint|route)\b", re.IGNORECASE),
    re.compile(r"\broute\s+not\s+(found|defined)\b", re.IGNORECASE),
    re.compile(r"\b(invalid|unknown)\s+(url|endpoint|path|route)\b", re.IGNORECASE),
]

# Title-level indicators (checked against <title> content)
_SOFT_404_TITLE_KEYWORDS = [
    "404", "not found", "page not found", "error",
    "page missing", "page does not exist",
]

# Response body length threshold: real 404 custom pages are usually small
_SOFT_404_MAX_BODY_CHECK = 5000  # only check first N chars for patterns


@dataclass
class Soft404Fingerprint:
    """Baseline 404 fingerprint captured by requesting a known-bad path.

    Used to compare discovered pages against the server's actual 404 response.
    This catches custom 404 pages that don't match keyword patterns — the server
    may return a React/Angular SPA shell, a branded error page, or a redirect
    to a generic landing page, all with HTTP 200.
    """
    status_code: int = 0
    body_hash: str = ""        # MD5of stripped body
    body_length: int = 0
    title: str = ""
    content_type: str = ""
    # Stripped body text for similarity comparison (first 5000 chars)
    body_text: str = ""

    def similarity(self, html: str, status_code: int) -> float:
        """Return 0.0–1.0 similarity score against a page."""
        if not self.body_text:
            return 0.0
        # If status codes differ significantly, less likely to be soft-404
        if status_code >= 400:
            return 0.0  # Already a real error
        snippet = _strip_dynamic(html[:15000])
        return SequenceMatcher(None, self.body_text, snippet).ratio()


def _strip_dynamic(html: str) -> str:
    """Strip HTML tags and dynamic content to get pure text for comparison.

    By comparing text-only content instead of raw HTML, we avoid false
    positives on sites where every page shares a heavy template (header,
    nav, footer, CSS) — the template HTML dominates the first few KB and
    makes all pages look 96%+ similar even when their actual content differs.
    """
    # Remove script/style blocks entirely
    text = re.sub(r'<(script|style)[^>]*>.*?</\1>', '', html, flags=re.I | re.DOTALL)
    # Remove all HTML tags
    text = re.sub(r'<[^>]+>', ' ', text)
    # Remove nonce/csrf tokens, timestamps, session IDs
    text = re.sub(r'(nonce|csrf|token|timestamp|sid)="[^"]*"', '', text, flags=re.I)
    text = re.sub(r'\b\d{10,13}\b', '', text)  # Unix timestamps
    # Collapse whitespace
    text = re.sub(r'\s+', ' ', text).strip()
    return text


def _is_soft_404(html: str, status_code: int, title: str = "",
                 fingerprint: Soft404Fingerprint | None = None) -> bool:
    """Detect soft 404 — server returns 200 but page says 'not found'.

    Checks (in order):
      0. Skip if page has <form> tags (real interactive pages, never 404)
      1. Baseline fingerprint comparison (if available) — most reliable
      2. Title contains 404/not-found keywords
      3. Body contains soft-404 regex patterns
      4. Only triggers on short pages (large content pages with a stray
         '404' reference are unlikely to be error pages)
    """
    # Skip if not a 200-range response (real errors are already handled)
    if status_code < 200 or status_code >= 300:
        return False

    # Check 0: Pages with real <form> tags are interactive pages, not 404s.
    # This prevents filtering out login pages, search pages, contact forms, etc.
    if _FORM.search(html):
        return False

    # Check 0b: Pages with unique titles different from the 404 page are real.
    # Most real pages have meaningful titles ("Login", "Account Summary")
    # while 404 pages have generic ones ("Page Not Found", site name).
    if fingerprint and title:
        fp_title = fingerprint.title.strip().lower()
        page_title = title.strip().lower()
        if fp_title and page_title and page_title != fp_title:
            return False

    # Check 0c: Pages with <table>, <article>, or significant content structure
    # are real content pages, not 404s.
    if re.search(r'<(table|article|section)\b[^>]*>.*?</(table|article|section)>',
                 html[:10000], re.DOTALL | re.IGNORECASE):
        return False

    # Check 1: Baseline fingerprint comparison (highest reliability)
    if fingerprint and fingerprint.body_text:
        sim = fingerprint.similarity(html, status_code)
        # Require very high similarity (>0.96) AND similar body length
        # (within 30%) to avoid false positives on sites using the same
        # template/layout for both real pages and error pages.
        if sim > 0.96:
            fp_len = fingerprint.body_length
            cur_len = len(html)
            if fp_len > 0:
                ratio = cur_len / fp_len if cur_len < fp_len else fp_len / cur_len
                if ratio > 0.7:
                    return True
            else:
                return True

    # Check 2: Title keywords
    title_lower = title.lower()
    if any(kw in title_lower for kw in _SOFT_404_TITLE_KEYWORDS):
        if len(html) < 50_000:
            return True

    # Check 3: Body patterns on the first N characters
    snippet = html[:_SOFT_404_MAX_BODY_CHECK].strip()
    if not snippet:
        return False

    # Only flag short-to-medium pages as soft 404
    if len(html) > 20_000:
        return False

    matches = sum(1 for pat in _SOFT_404_BODY_PATTERNS if pat.search(snippet))
    return matches >= 2


# ── Noise filters ──────────────────────────────────────────────

_SKIP_EXTENSIONS = frozenset({
    ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".bmp", ".webp",
    ".css", ".js", ".map",
    ".woff", ".woff2", ".ttf", ".eot", ".otf",
    ".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx",
    ".zip", ".tar", ".gz", ".rar", ".7z",
    ".mp3", ".mp4", ".avi", ".mov", ".webm", ".ogg",
    ".xml", ".rss", ".atom",
})

_SKIP_SCHEMES = frozenset({
    "javascript", "mailto", "tel", "data", "blob", "ftp",
})


# ── Data classes ───────────────────────────────────────────────


@dataclass
class FormField:
    """A form input/select/textarea discovered during crawling."""
    name: str
    input_type: str = "text"
    required: bool = False


@dataclass
class DiscoveredForm:
    """A form found on a crawled page."""
    action: str                    # resolved absolute URL
    method: str = "GET"
    fields: list[FormField] = field(default_factory=list)
    source_page: str = ""

    @property
    def param_names(self) -> list[str]:
        return [f.name for f in self.fields]


@dataclass
class CrawledPage:
    """A single page visited by the crawler."""
    url: str
    status_code: int = 0
    content_type: str = ""
    title: str = ""
    links: list[str] = field(default_factory=list)      # outgoing links
    forms: list[DiscoveredForm] = field(default_factory=list)
    data_urls: list[str] = field(default_factory=list)   # data-url/data-api attrs
    depth: int = 0
    error: str = ""
    is_soft_404: bool = False    # server returned 200 but body says "not found"


@dataclass
class CrawlResult:
    """Complete result of a crawl session."""
    base_url: str
    pages: list[CrawledPage] = field(default_factory=list)
    urls_visited: int = 0
    urls_skipped: int = 0       # out of scope or filtered
    forms_found: int = 0
    errors: list[str] = field(default_factory=list)

    @property
    def all_links(self) -> list[str]:
        """All unique links discovered across all pages."""
        seen: set[str] = set()
        out: list[str] = []
        for page in self.pages:
            for link in page.links:
                if link not in seen:
                    seen.add(link)
                    out.append(link)
        return out

    @property
    def all_forms(self) -> list[DiscoveredForm]:
        """All forms discovered across all pages."""
        return [f for page in self.pages for f in page.forms]

    @property
    def all_data_urls(self) -> list[str]:
        """All unique data-url/data-api attributes discovered."""
        seen: set[str] = set()
        out: list[str] = []
        for page in self.pages:
            for u in page.data_urls:
                if u not in seen:
                    seen.add(u)
                    out.append(u)
        return out

    @property
    def soft_404_count(self) -> int:
        """Number of pages that were soft 404s."""
        return sum(1 for p in self.pages if p.is_soft_404)

    @property
    def valid_pages(self) -> list[CrawledPage]:
        """Pages that are real (not soft-404, not error)."""
        return [p for p in self.pages if not p.is_soft_404 and not p.error]

    def summary(self) -> dict:
        return {
            "base_url": self.base_url,
            "pages_visited": self.urls_visited,
            "urls_skipped": self.urls_skipped,
            "unique_links": len(self.all_links),
            "forms_found": self.forms_found,
            "data_urls": len(self.all_data_urls),
            "soft_404s": self.soft_404_count,
            "valid_pages": len(self.valid_pages),
            "errors": len(self.errors),
        }


# ── Crawler ────────────────────────────────────────────────────


class Crawler:
    """Breadth-first scope-aware HTML spider.

    Discovers:
      - Links (<a href>)
      - Forms (<form> with inputs)
      - Data attributes (data-url, data-api, etc.)
      - Meta redirects

    Respects:
      - Scope guard (only follows in-scope links)
      - Depth limit
      - Max pages limit
      - Extension filter (skips static assets)
    """

    def __init__(
        self,
        client: HttpClient,
        session: Session | None = None,
        *,
        base_url: str = "",
        max_depth: int = 3,
        max_pages: int = 100,
        same_origin_only: bool = True,
    ):
        self.client = client
        self.session = session
        # Keep trailing slash for root URLs, strip for paths
        if base_url.endswith("/") and urlparse(base_url).path == "/":
            self.base_url = base_url
        else:
            self.base_url = base_url.rstrip("/")
        self.max_depth = max_depth
        self.max_pages = max_pages
        self.same_origin_only = same_origin_only

        self._base_parsed = urlparse(self.base_url) if self.base_url else None
        self._404_fingerprint: Soft404Fingerprint | None = None

    # ── Public API ─────────────────────────────────────────────

    async def _capture_404_fingerprint(self, base: str) -> None:
        """Request a known-bad path to capture the server's 404 response.

        This fingerprint is compared against every discovered page to catch
        custom 404 pages that return HTTP 200 but show the same content as
        a real 404 (e.g. SPA catch-all routes, branded error pages).
        """
        random_path = f"/{uuid.uuid4().hex[:16]}-does-not-exist-{uuid.uuid4().hex[:8]}"
        parsed = urlparse(base)
        test_url = f"{parsed.scheme}://{parsed.netloc}{random_path}"
        try:
            resp = await self.client.get(test_url, session=self.session)
            body = resp.text
            self._404_fingerprint = Soft404Fingerprint(
                status_code=resp.status_code,
                body_hash=hashlib.md5(body.strip().encode()).hexdigest(),
                body_length=len(body),
                title=self._extract_title(body),
                content_type=resp.headers.get("content-type", ""),
                body_text=_strip_dynamic(body[:15000]),
            )
            logger.info("404 fingerprint captured: status=%d len=%d title=%r",
                        resp.status_code, len(body), self._404_fingerprint.title)
        except Exception as exc:
            logger.debug("Failed to capture 404 fingerprint: %s", exc)
            self._404_fingerprint = None

    async def crawl(self, start_url: str | None = None) -> CrawlResult:
        """Spider from start_url (defaults to base_url), BFS up to limits."""
        start = start_url or self.base_url
        if not start:
            return CrawlResult(base_url="", errors=["No start URL"])

        # Capture 404 fingerprint before crawling
        await self._capture_404_fingerprint(start)

        result = CrawlResult(base_url=start)
        visited: set[str] = set()
        queue: deque[tuple[str, int]] = deque()  # (url, depth)
        queue.append((self._normalize_url(start), 0))

        while queue and result.urls_visited < self.max_pages:
            url, depth = queue.popleft()

            # Skip if already visited
            canonical = self._canonical(url)
            if canonical in visited:
                continue
            visited.add(canonical)

            # Skip if out of scope
            if not self._should_visit(url):
                result.urls_skipped += 1
                continue

            # Fetch page
            page = await self._fetch_page(url, depth)
            result.pages.append(page)
            result.urls_visited += 1
            result.forms_found += len(page.forms)

            if page.error:
                result.errors.append(f"{url}: {page.error}")
                continue

            # Enqueue discovered links if within depth
            if depth < self.max_depth:
                for link in page.links:
                    link_canonical = self._canonical(link)
                    if link_canonical not in visited and self._should_visit(link):
                        queue.append((link, depth + 1))

                # Also follow data-url attributes
                for data_url in page.data_urls:
                    data_canonical = self._canonical(data_url)
                    if data_canonical not in visited and self._should_visit(data_url):
                        queue.append((data_url, depth + 1))

        return result

    def parse_page(self, html: str, page_url: str) -> CrawledPage:
        """Parse a single HTML page for links, forms, and data attributes.

        Can be used standalone (without HTTP) for testing.
        """
        page = CrawledPage(url=page_url)
        page.title = self._extract_title(html)

        # Extract links
        for m in _HREF.finditer(html):
            href = m.group(1).strip()
            resolved = self._resolve_url(href, page_url)
            if resolved and not self._is_skip_url(resolved):
                page.links.append(resolved)

        # Meta redirects
        for m in _META_REDIRECT.finditer(html):
            redirect_url = m.group(1).strip()
            resolved = self._resolve_url(redirect_url, page_url)
            if resolved:
                page.links.append(resolved)

        # Extract forms
        for m in _FORM.finditer(html):
            form_html = m.group(0)
            form = self._parse_form(form_html, page_url)
            if form:
                page.forms.append(form)

        # Data attributes with URLs
        for m in _DATA_URL.finditer(html):
            data_val = m.group(1).strip()
            resolved = self._resolve_url(data_val, page_url)
            if resolved:
                page.data_urls.append(resolved)

        # Deduplicate links
        seen: set[str] = set()
        unique_links: list[str] = []
        for link in page.links:
            if link not in seen:
                seen.add(link)
                unique_links.append(link)
        page.links = unique_links

        return page

    # ── Page fetching ──────────────────────────────────────────

    async def _fetch_page(self, url: str, depth: int) -> CrawledPage:
        """Fetch a URL and parse the HTML response.

        Includes soft-404 detection: if the server returns 200 but the
        response body indicates a 'not found' page, the page is flagged
        and its links/forms/data_urls are cleared so we don't spider
        into ghost endpoints.

        The start URL (depth 0) is NEVER treated as soft-404 because it's
        the user-provided target and is always valid. This prevents false
        positives on sites that return similar templates for 404 pages.
        """
        try:
            resp = await self.client.get(url, session=self.session)
        except Exception as exc:
            return CrawledPage(url=url, depth=depth, error=str(exc))

        content_type = resp.headers.get("content-type", "")
        page = CrawledPage(
            url=url,
            status_code=resp.status_code,
            content_type=content_type,
            depth=depth,
        )

        # Hard 404/5xx — mark as error, don't parse
        if resp.status_code >= 400:
            page.error = f"HTTP {resp.status_code}"
            return page

        # Only parse HTML responses
        if "text/html" not in content_type and "application/xhtml" not in content_type:
            return page

        html = resp.text
        parsed = self.parse_page(html, url)
        page.title = parsed.title

        # ── Soft-404 detection ────────────────────────────────
        # Skip for depth 0 (user-provided start URL is always valid).
        # Use stricter thresholds: fingerprint similarity must be > 0.92
        # AND body length must be within 30% of the 404 page to reduce
        # false positives on sites using the same template for everything.
        if depth > 0 and _is_soft_404(html, resp.status_code, page.title,
                                       self._404_fingerprint):
            page.is_soft_404 = True
            page.error = "soft-404 (200 status but body indicates not found)"
            logger.info("Soft-404 detected: %s (title=%r)", url, page.title)
            # Don't extract links/forms from fake pages
            return page

        page.links = parsed.links
        page.forms = parsed.forms
        page.data_urls = parsed.data_urls
        return page

    # ── Form parsing ───────────────────────────────────────────

    def _parse_form(self, form_html: str, page_url: str) -> DiscoveredForm | None:
        """Parse a <form> tag and its inputs."""
        # Action
        action_match = _FORM_ACTION.search(form_html)
        action = action_match.group(1).strip() if action_match else ""
        resolved_action = self._resolve_url(action, page_url) or page_url

        # Method
        method_match = _FORM_METHOD.search(form_html)
        method = method_match.group(1).upper() if method_match else "GET"

        # Fields
        fields: list[FormField] = []
        seen_names: set[str] = set()
        for inp_match in _INPUT.finditer(form_html):
            name = inp_match.group(1)
            if name in seen_names:
                continue
            seen_names.add(name)

            # Get type — extract the full tag that contains this name= attr
            # Find the < that opens this tag by scanning backward
            tag_start = form_html.rfind("<", 0, inp_match.start() + 1)
            tag_end = form_html.find(">", inp_match.end())
            if tag_start >= 0 and tag_end >= 0:
                tag_html = form_html[tag_start:tag_end + 1]
            else:
                tag_html = ""
            type_match = _INPUT_TYPE.search(tag_html)
            input_type = type_match.group(1).lower() if type_match else "text"

            # Skip submit/button/hidden-csrf type fields for param discovery
            if input_type in ("submit", "button", "image", "reset"):
                continue

            required = "required" in tag_html.lower()
            fields.append(FormField(
                name=name,
                input_type=input_type,
                required=required,
            ))

        if not fields and not action:
            return None

        return DiscoveredForm(
            action=resolved_action,
            method=method,
            fields=fields,
            source_page=page_url,
        )

    # ── URL helpers ────────────────────────────────────────────

    def _resolve_url(self, href: str, page_url: str) -> str | None:
        """Resolve a potentially relative URL against a page URL."""
        if not href:
            return None
        # Skip non-http schemes
        for scheme in _SKIP_SCHEMES:
            if href.lower().startswith(f"{scheme}:"):
                return None
        try:
            resolved = urljoin(page_url, href)
            # Strip fragment
            parsed = urlparse(resolved)
            return parsed._replace(fragment="").geturl()
        except Exception:
            return None

    def _normalize_url(self, url: str) -> str:
        """Normalize a URL for consistency."""
        parsed = urlparse(url)
        # Sort query params for canonical comparison
        if parsed.query:
            params = parse_qs(parsed.query, keep_blank_values=True)
            sorted_query = urlencode(sorted(params.items()), doseq=True)
            return parsed._replace(query=sorted_query, fragment="").geturl()
        return parsed._replace(fragment="").geturl()

    def _canonical(self, url: str) -> str:
        """Canonical form for dedup: lowercase host, sorted params, no fragment."""
        parsed = urlparse(url)
        host = (parsed.hostname or "").lower()
        port = f":{parsed.port}" if parsed.port and parsed.port not in (80, 443) else ""
        path = parsed.path or "/"
        # Strip trailing slash for dedup (except root)
        if path != "/" and path.endswith("/"):
            path = path.rstrip("/")
        query = ""
        if parsed.query:
            params = parse_qs(parsed.query, keep_blank_values=True)
            query = "?" + urlencode(sorted(params.items()), doseq=True)
        return f"{parsed.scheme}://{host}{port}{path}{query}"

    def _should_visit(self, url: str) -> bool:
        """Check if a URL should be visited (scope + origin + extension)."""
        if self._is_skip_url(url):
            return False
        # Scope check
        if not in_scope(url):
            return False
        # Same-origin check
        if self.same_origin_only and self._base_parsed:
            parsed = urlparse(url)
            if (parsed.hostname or "").lower() != (self._base_parsed.hostname or "").lower():
                return False
        return True

    @staticmethod
    def _is_skip_url(url: str) -> bool:
        """Should this URL be skipped entirely (static assets, etc)?"""
        parsed = urlparse(url)
        path = parsed.path.lower()
        for ext in _SKIP_EXTENSIONS:
            if path.endswith(ext):
                return True
        return False

    @staticmethod
    def _extract_title(html: str) -> str:
        """Extract <title> content from HTML."""
        m = re.search(r"<title[^>]*>([^<]+)</title>", html, re.IGNORECASE)
        return m.group(1).strip() if m else ""
