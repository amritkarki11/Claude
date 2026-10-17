"""JS/SPA Endpoint Extractor (Phase 2.2).

Fetches JavaScript bundles from a target and extracts API endpoint paths
using regex-based pattern matching. Handles minified code, string literals,
template strings, and common patterns from frameworks like Angular, React,
Vue, jQuery, and vanilla fetch/axios.

Usage:
    extractor = JsExtractor(client, session)
    result = await extractor.extract("https://app.example.com")
    for ep in result.endpoints:
        print(ep.path, ep.method, ep.params)
"""
from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urljoin, urlparse

from ..http import HttpClient, Session

logger = logging.getLogger(__name__)

# ── Patterns for finding JS source URLs in HTML ────────────────

_SCRIPT_SRC = re.compile(
    r"""<script[^>]+src\s*=\s*["']([^"']+\.js[^"']*)["']""",
    re.IGNORECASE,
)

# ── Patterns for extracting endpoints from JS source ───────────

# API path literals: "/api/...", "/data/...", "/v1/...", "/rest/..."
# Captures paths with 2+ segments to avoid noise like "/a"
_API_PATH = re.compile(
    r"""(?:["'`])"""                       # opening quote
    r"""(/(?:api|data|rest|v[0-9]+|graphql|auth|admin|user|users|account"""
    r"""|order|orders|product|products|item|items|cart|checkout|payment"""
    r"""|search|config|setting|settings|dashboard|report|reports"""
    r"""|upload|download|export|import|webhook|notification|notifications"""
    r"""|invoice|invoices|inventory|catalog|category|categories"""
    r"""|shipment|shipments|vendor|vendors|warehouse|facility"""
    r"""|return|returns|channel|channels|manifest|manifests"""
    r"""|login|logout|register|signup|token|refresh|verify|otp"""
    r"""|health|status|ping|version|info|metadata)"""
    r"""(?:/[a-zA-Z0-9_\-{}:.*$]+)*)"""    # path continuation
    r"""(?:["'`])""",                       # closing quote
    re.VERBOSE,
)

# Generic path: any "/word/word..." path with 2+ segments
# More aggressive — catches things _API_PATH misses but noisier
_GENERIC_PATH = re.compile(
    r"""(?:["'`])"""
    r"""(/[a-zA-Z][a-zA-Z0-9_\-]*/[a-zA-Z0-9_\-/{}.:]*)"""
    r"""(?:["'`])""",
)

# URL patterns: full URLs with http(s)
_FULL_URL = re.compile(
    r"""(?:["'`])(https?://[a-zA-Z0-9._\-]+(?::[0-9]+)?/[a-zA-Z0-9_\-/.?&={}:*%$#+]*)(?:["'`])"""
)

# fetch/axios/XHR calls
_FETCH_CALL = re.compile(
    r"""(?:fetch|axios(?:\.(?:get|post|put|delete|patch))?|\.ajax|\$\.(?:get|post|ajax)|\.open)\s*\(\s*["'`]([^"'`]+)["'`]""",
    re.IGNORECASE,
)

# HTTP method detection near a URL
_METHOD_HINT = re.compile(
    r"""(?:method|type)\s*[:=]\s*["']?(GET|POST|PUT|DELETE|PATCH|OPTIONS|HEAD)["']?""",
    re.IGNORECASE,
)

# Angular $http / HttpClient patterns
_ANGULAR_HTTP = re.compile(
    r"""\$http\s*\.\s*(get|post|put|delete|patch)\s*\(\s*["'`]([^"'`]+)["'`]""",
    re.IGNORECASE,
)

# String concatenation: baseUrl + "/endpoint"
_CONCAT_PATH = re.compile(
    r"""\+\s*["'`](/[a-zA-Z][a-zA-Z0-9_\-/{}:.]*?)["'`]"""
)

# Template literal: `${baseUrl}/endpoint/path`
_TEMPLATE_PATH = re.compile(
    r"""`[^`]*\$\{[^}]+\}(/[a-zA-Z][a-zA-Z0-9_\-/{}:.]*)`"""
)

# Query param keys: ?key= or &key= patterns near API paths
_QUERY_PARAM = re.compile(
    r"""[?&]([a-zA-Z_][a-zA-Z0-9_]*)\s*=""",
)

# JSON body keys near API calls (common param names)
_BODY_KEY = re.compile(
    r"""["']([a-zA-Z_][a-zA-Z0-9_]*)["']\s*:""",
)

# ── Noise filters ──────────────────────────────────────────────

# Paths that are definitely not API endpoints
_NOISE_PREFIXES = frozenset({
    "/static", "/assets", "/img", "/images", "/css", "/js",
    "/fonts", "/font", "/media", "/public", "/build", "/dist",
    "/node_modules", "/vendor", "/bower_components",
    "/favicon", "/.well-known", "/robots.txt", "/sitemap",
    "/wp-content", "/wp-includes", "/wp-admin",
})

_NOISE_EXTENSIONS = frozenset({
    ".js", ".css", ".png", ".jpg", ".jpeg", ".gif", ".svg",
    ".ico", ".woff", ".woff2", ".ttf", ".eot", ".map",
    ".html", ".htm", ".xml", ".txt", ".pdf",
    ".mp3", ".mp4", ".webm", ".ogg",
})

_NOISE_EXACT = frozenset({
    "/", "/index", "/home", "/undefined", "/null", "/true", "/false",
    "/NaN", "/Object", "/Array", "/String", "/Number",
})


# ── Data classes ───────────────────────────────────────────────


@dataclass
class ExtractedEndpoint:
    """A single endpoint extracted from JavaScript source."""
    path: str
    method: str = "GET"
    params: list[str] = field(default_factory=list)
    source_file: str = ""
    confidence: str = "medium"   # high / medium / low
    context: str = ""            # snippet of surrounding JS code


@dataclass
class JsExtractionResult:
    """Result of JS extraction from a target."""
    target: str
    js_files_found: int = 0
    js_files_fetched: int = 0
    js_bytes_total: int = 0
    endpoints: list[ExtractedEndpoint] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)

    @property
    def endpoint_count(self) -> int:
        return len(self.endpoints)

    def unique_paths(self) -> list[str]:
        """Deduplicated paths in discovery order."""
        seen: set[str] = set()
        out: list[str] = []
        for ep in self.endpoints:
            if ep.path not in seen:
                seen.add(ep.path)
                out.append(ep.path)
        return out


# ── Extractor ──────────────────────────────────────────────────


class JsExtractor:
    """Fetches JS from a target and extracts API endpoints.

    Two modes:
      1. HTML mode: fetch a page, find <script src="..."> tags, fetch each
      2. Direct mode: extract from JS source text already in hand

    The extractor is intentionally aggressive — it over-extracts rather
    than missing endpoints. Downstream scanners decide which to probe.
    """

    def __init__(
        self,
        client: HttpClient | None = None,
        session: Session | None = None,
        *,
        max_js_size: int = 10 * 1024 * 1024,  # 10 MB
        max_js_files: int = 50,
    ):
        self.client = client
        self.session = session
        self.max_js_size = max_js_size
        self.max_js_files = max_js_files

    # ── Public API ─────────────────────────────────────────────

    async def extract(self, target_url: str) -> JsExtractionResult:
        """Fetch the target page, discover JS files, extract endpoints."""
        result = JsExtractionResult(target=target_url)

        if self.client is None:
            result.errors.append("No HTTP client configured")
            return result

        # Step 1: Fetch the page HTML
        try:
            resp = await self.client.get(target_url, session=self.session)
            html = resp.text
        except Exception as exc:
            result.errors.append(f"Failed to fetch {target_url}: {exc}")
            return result

        # Step 2: Find JS file URLs
        js_urls = self._find_js_urls(html, target_url)
        result.js_files_found = len(js_urls)

        # Also extract from inline scripts in the HTML
        inline_endpoints = self._extract_inline_scripts(html, target_url)
        result.endpoints.extend(inline_endpoints)

        # Step 3: Fetch and extract from each JS file
        for js_url in js_urls[:self.max_js_files]:
            try:
                js_resp = await self.client.get(js_url, session=self.session)
                js_text = js_resp.text
                result.js_files_fetched += 1
                result.js_bytes_total += len(js_resp.content)

                if len(js_resp.content) > self.max_js_size:
                    result.errors.append(
                        f"JS file too large ({len(js_resp.content)} bytes): {js_url}"
                    )
                    continue

                endpoints = self.extract_from_source(js_text, source_file=js_url)
                result.endpoints.extend(endpoints)

            except Exception as exc:
                result.errors.append(f"Failed to fetch {js_url}: {exc}")

        # Deduplicate while preserving order and picking highest confidence
        result.endpoints = self._deduplicate(result.endpoints)
        return result

    def extract_from_source(
        self,
        js_source: str,
        *,
        source_file: str = "",
        base_url: str = "",
    ) -> list[ExtractedEndpoint]:
        """Extract endpoints from raw JS source code.

        This is the core extraction logic — it can be used standalone
        without an HTTP client (e.g. for local files, benchmarking).
        """
        endpoints: list[ExtractedEndpoint] = []

        # 1. API path literals (high confidence)
        for m in _API_PATH.finditer(js_source):
            path = m.group(1)
            if self._is_noise(path):
                continue
            method = self._guess_method_near(js_source, m.start(), m.end())
            params = self._extract_params_near(js_source, m.start(), m.end())
            endpoints.append(ExtractedEndpoint(
                path=self._normalize_path(path),
                method=method,
                params=params,
                source_file=source_file,
                confidence="high",
                context=js_source[max(0, m.start() - 30):m.end() + 30],
            ))

        # 2. fetch/axios/XHR calls (high confidence)
        for m in _FETCH_CALL.finditer(js_source):
            url_or_path = m.group(1)
            path = self._url_to_path(url_or_path, base_url)
            if not path or self._is_noise(path):
                continue
            method = self._guess_method_from_call(js_source, m.start())
            params = self._extract_params_near(js_source, m.start(), m.end() + 200)
            endpoints.append(ExtractedEndpoint(
                path=self._normalize_path(path),
                method=method,
                params=params,
                source_file=source_file,
                confidence="high",
                context=js_source[max(0, m.start() - 20):m.end() + 50],
            ))

        # 3. Angular $http patterns (high confidence)
        for m in _ANGULAR_HTTP.finditer(js_source):
            method = m.group(1).upper()
            url_or_path = m.group(2)
            path = self._url_to_path(url_or_path, base_url)
            if not path or self._is_noise(path):
                continue
            endpoints.append(ExtractedEndpoint(
                path=self._normalize_path(path),
                method=method,
                params=[],
                source_file=source_file,
                confidence="high",
                context=js_source[max(0, m.start() - 10):m.end() + 30],
            ))

        # 4. Full URLs (medium confidence — may be external)
        for m in _FULL_URL.finditer(js_source):
            full_url = m.group(1)
            path = self._url_to_path(full_url, base_url)
            if not path or self._is_noise(path):
                continue
            method = self._guess_method_near(js_source, m.start(), m.end())
            endpoints.append(ExtractedEndpoint(
                path=self._normalize_path(path),
                method=method,
                params=[],
                source_file=source_file,
                confidence="medium",
                context=js_source[max(0, m.start() - 20):m.end() + 30],
            ))

        # 5. Generic paths (medium confidence)
        for m in _GENERIC_PATH.finditer(js_source):
            path = m.group(1)
            if self._is_noise(path):
                continue
            # Skip if already found by more specific patterns
            norm = self._normalize_path(path)
            if any(ep.path == norm for ep in endpoints):
                continue
            method = self._guess_method_near(js_source, m.start(), m.end())
            endpoints.append(ExtractedEndpoint(
                path=norm,
                method=method,
                params=[],
                source_file=source_file,
                confidence="medium",
                context=js_source[max(0, m.start() - 20):m.end() + 30],
            ))

        # 6. String concatenation paths (low confidence)
        for m in _CONCAT_PATH.finditer(js_source):
            path = m.group(1)
            if self._is_noise(path):
                continue
            norm = self._normalize_path(path)
            if any(ep.path == norm for ep in endpoints):
                continue
            endpoints.append(ExtractedEndpoint(
                path=norm,
                method="GET",
                params=[],
                source_file=source_file,
                confidence="low",
                context=js_source[max(0, m.start() - 40):m.end() + 20],
            ))

        # 7. Template literal paths (low confidence)
        for m in _TEMPLATE_PATH.finditer(js_source):
            path = m.group(1)
            if self._is_noise(path):
                continue
            norm = self._normalize_path(path)
            if any(ep.path == norm for ep in endpoints):
                continue
            endpoints.append(ExtractedEndpoint(
                path=norm,
                method="GET",
                params=[],
                source_file=source_file,
                confidence="low",
                context=js_source[max(0, m.start() - 30):m.end() + 20],
            ))

        return endpoints

    # ── HTML parsing helpers ───────────────────────────────────

    def _find_js_urls(self, html: str, base_url: str) -> list[str]:
        """Extract JS file URLs from HTML <script> tags."""
        urls: list[str] = []
        seen: set[str] = set()
        for m in _SCRIPT_SRC.finditer(html):
            src = m.group(1).strip()
            # Skip data: URIs and inline handlers
            if src.startswith(("data:", "javascript:", "blob:")):
                continue
            full = urljoin(base_url, src)
            if full not in seen:
                seen.add(full)
                urls.append(full)
        return urls

    def _extract_inline_scripts(
        self, html: str, source_file: str
    ) -> list[ExtractedEndpoint]:
        """Extract endpoints from inline <script> blocks in HTML."""
        endpoints: list[ExtractedEndpoint] = []
        # Match <script>...</script> blocks (non-greedy)
        for m in re.finditer(
            r"<script[^>]*>(.+?)</script>", html, re.DOTALL | re.IGNORECASE
        ):
            block = m.group(1).strip()
            if len(block) < 10:
                continue
            eps = self.extract_from_source(
                block, source_file=f"{source_file}#inline"
            )
            endpoints.extend(eps)
        return endpoints

    # ── Path helpers ───────────────────────────────────────────

    @staticmethod
    def _normalize_path(path: str) -> str:
        """Normalize a path: strip trailing slashes, collapse //, lowercase."""
        path = re.sub(r"/+", "/", path)   # collapse double slashes
        path = path.rstrip("/")
        if not path:
            path = "/"
        return path

    @staticmethod
    def _url_to_path(url_or_path: str, base_url: str = "") -> str | None:
        """Convert a URL or path string to just the path component."""
        if not url_or_path:
            return None
        # Already a path
        if url_or_path.startswith("/"):
            return url_or_path
        # Full URL
        if url_or_path.startswith(("http://", "https://")):
            parsed = urlparse(url_or_path)
            return parsed.path or None
        # Relative path (no scheme, no leading /)
        if base_url and not url_or_path.startswith(("data:", "javascript:", "blob:")):
            full = urljoin(base_url, url_or_path)
            parsed = urlparse(full)
            return parsed.path or None
        return None

    @staticmethod
    def _is_noise(path: str) -> bool:
        """Check if a path is definitely not an API endpoint."""
        if not path or path in _NOISE_EXACT:
            return True
        lower = path.lower()
        for prefix in _NOISE_PREFIXES:
            if lower.startswith(prefix):
                return True
        for ext in _NOISE_EXTENSIONS:
            if lower.endswith(ext):
                return True
        # Too short to be useful (single segment, 1-2 chars)
        segments = [s for s in path.split("/") if s]
        if len(segments) < 1:
            return True
        # Filter out paths that look like version strings or numbers only
        if all(re.match(r"^[0-9v.]+$", s) for s in segments):
            return True
        return False

    # ── Method guessing ────────────────────────────────────────

    @staticmethod
    def _guess_method_near(js: str, start: int, end: int) -> str:
        """Look for HTTP method hints near a path match."""
        window = js[max(0, start - 200):end + 200]
        m = _METHOD_HINT.search(window)
        if m:
            return m.group(1).upper()
        # Check for common function-name hints
        lower_window = window.lower()
        if any(w in lower_window for w in ("post(", ".post", "create", "submit", "save")):
            return "POST"
        if any(w in lower_window for w in (".put", "update")):
            return "PUT"
        if any(w in lower_window for w in (".delete", "remove", "destroy")):
            return "DELETE"
        return "GET"

    @staticmethod
    def _guess_method_from_call(js: str, match_start: int) -> str:
        """Determine HTTP method from a fetch/axios call pattern."""
        prefix = js[max(0, match_start - 50):match_start].lower()
        if "axios.post" in prefix or "$.post" in prefix:
            return "POST"
        if "axios.put" in prefix:
            return "PUT"
        if "axios.delete" in prefix:
            return "DELETE"
        if "axios.patch" in prefix:
            return "PATCH"
        # For fetch(), check for method: in the options
        options_window = js[match_start:match_start + 300]
        m = _METHOD_HINT.search(options_window)
        if m:
            return m.group(1).upper()
        return "GET"

    # ── Param extraction ───────────────────────────────────────

    @staticmethod
    def _extract_params_near(
        js: str, start: int, end: int, window: int = 500
    ) -> list[str]:
        """Extract parameter names near a path/URL match."""
        chunk = js[max(0, start - 50):min(len(js), end + window)]
        params: set[str] = set()

        # Query string params: ?key= or &key=
        for m in _QUERY_PARAM.finditer(chunk):
            p = m.group(1)
            if len(p) > 1 and not p.startswith("_"):
                params.add(p)

        # JSON body keys (within ~200 chars after the URL)
        body_chunk = js[end:min(len(js), end + 300)]
        for m in _BODY_KEY.finditer(body_chunk):
            p = m.group(1)
            # Filter out obvious non-param keys
            if p.lower() in (
                "method", "type", "headers", "body", "credentials",
                "mode", "cache", "redirect", "referrer", "integrity",
                "content", "accept", "authorization", "contenttype",
                "success", "error", "complete", "datatype", "async",
                "url", "data", "timeout", "beforeSend", "xhr",
                "processData", "contentType",
            ):
                continue
            if len(p) > 1 and not p.startswith("_"):
                params.add(p)

        return sorted(params)

    # ── Deduplication ──────────────────────────────────────────

    @staticmethod
    def _deduplicate(endpoints: list[ExtractedEndpoint]) -> list[ExtractedEndpoint]:
        """Deduplicate endpoints by path+method, keeping highest confidence."""
        confidence_rank = {"high": 3, "medium": 2, "low": 1}
        best: dict[tuple[str, str], ExtractedEndpoint] = {}

        for ep in endpoints:
            key = (ep.path, ep.method)
            existing = best.get(key)
            if existing is None:
                best[key] = ep
            else:
                # Keep highest confidence; merge params
                if confidence_rank.get(ep.confidence, 0) > confidence_rank.get(
                    existing.confidence, 0
                ):
                    merged_params = sorted(set(existing.params) | set(ep.params))
                    ep.params = merged_params
                    best[key] = ep
                else:
                    existing.params = sorted(set(existing.params) | set(ep.params))

        return list(best.values())


def extract_endpoints(js_source: str) -> list[dict]:
    """Bridge function for pipeline.py — extract endpoints from raw JS text.

    Returns a list of dicts with keys: path, method, params, confidence.
    """
    extractor = JsExtractor()
    endpoints = extractor.extract_from_source(js_source)
    return [
        {
            "path": ep.path,
            "method": ep.method,
            "params": ep.params,
            "confidence": ep.confidence,
        }
        for ep in endpoints
    ]
