"""Async HTTP engine. Every outbound request is scope-gated — nothing leaves
the box for a host that isn't on the allowlist. Supports JWT / cookie
(JSESSIONID) / Bearer / custom-header auth via Session, structured JSONL
request/response logging, an optional Burp proxy toggle for debugging,
rate limiting, and stealth/low-noise mode."""
from __future__ import annotations

import asyncio
import json
import pathlib
import random
import time
from dataclasses import dataclass, field
from typing import Any

import httpx

from .scope import check as scope_check

BURP_PROXY = "http://127.0.0.1:8080"
DEFAULT_LOG_PATH = pathlib.Path(__file__).parent.parent / "outputs" / "http_log.jsonl"

STEALTH_USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:121.0) Gecko/20100101 Firefox/121.0",
]


@dataclass
class Session:
    """Holds auth material for one logical identity (attacker/victim account,
    etc). Applied to every request made with it. Multiple schemes can be
    combined (e.g. Bearer + a custom header); `bearer` and `jwt` both set the
    Authorization header and the later one wins if both are given."""

    jwt: str | None = None
    bearer: str | None = None
    jsessionid: str | None = None
    headers: dict[str, str] = field(default_factory=dict)
    cookies: dict[str, str] = field(default_factory=dict)

    def apply(self, headers: dict[str, str], cookies: dict[str, str]) -> None:
        if self.jwt:
            headers["Authorization"] = f"Bearer {self.jwt}"
        if self.bearer:
            headers["Authorization"] = f"Bearer {self.bearer}"
        if self.jsessionid:
            cookies["JSESSIONID"] = self.jsessionid
        headers.update(self.headers)
        cookies.update(self.cookies)


class HttpClient:
    """Scope-gated async wrapper around httpx.AsyncClient.

    Every request path funnels through `request()`, which calls
    scope.check(url) first and fails closed (raises ScopeError) before any
    network I/O happens.
    """

    def __init__(
        self,
        *,
        timeout: float = 15.0,
        retries: int = 2,
        use_proxy: bool = False,
        verify_ssl: bool = False,
        log_path: pathlib.Path | str = DEFAULT_LOG_PATH,
        transport: httpx.AsyncBaseTransport | None = None,
        rate_limit: float = 0.0,
        stealth: bool = False,
    ) -> None:
        self.log_path = pathlib.Path(log_path)
        self.log_path.parent.mkdir(parents=True, exist_ok=True)

        # Rate limiting: minimum seconds between requests.
        # In stealth mode a random jitter (0.5×–1.5× rate_limit) is added.
        self._rate_limit = rate_limit if rate_limit > 0 else (1.0 if stealth else 0.0)
        self._stealth = stealth
        self._last_request_time: float = 0.0

        # `transport` override exists so tests can inject an httpx
        # MockTransport instead of hitting the real network.
        # verify must be set on BOTH transport and client — httpx ignores
        # the client-level verify when a custom transport is provided.
        ssl_verify = verify_ssl and not use_proxy
        if transport is None:
            transport = httpx.AsyncHTTPTransport(
                retries=retries, verify=ssl_verify,
            )
        client_kwargs: dict[str, Any] = {
            "timeout": timeout,
            "transport": transport,
            "verify": ssl_verify,
        }

        if use_proxy:
            client_kwargs["proxy"] = BURP_PROXY

        # Stealth mode: randomize User-Agent to look like a normal browser
        if stealth:
            client_kwargs.setdefault("headers", {})
            client_kwargs["headers"]["User-Agent"] = random.choice(STEALTH_USER_AGENTS)

        client_kwargs["follow_redirects"] = True
        self._client = httpx.AsyncClient(**client_kwargs)

    async def __aenter__(self) -> "HttpClient":
        return self

    async def __aexit__(self, *exc_info: Any) -> None:
        await self.aclose()

    async def aclose(self) -> None:
        await self._client.aclose()

    async def request(
        self,
        method: str,
        url: str,
        *,
        session: Session | None = None,
        headers: dict[str, str] | None = None,
        cookies: dict[str, str] | None = None,
        follow_redirects: bool | None = None,
        **kw: Any,
    ) -> httpx.Response:
        scope_check(url)  # fail closed before anything touches the network

        # Rate limiting — throttle requests to avoid WAF/IDS detection
        if self._rate_limit > 0:
            now = time.monotonic()
            elapsed_since_last = now - self._last_request_time
            delay = self._rate_limit
            if self._stealth:
                delay *= random.uniform(0.5, 1.5)  # jitter
            wait = delay - elapsed_since_last
            if wait > 0:
                await asyncio.sleep(wait)
            self._last_request_time = time.monotonic()

        headers = dict(headers or {})
        cookies = dict(cookies or {})
        if session is not None:
            session.apply(headers, cookies)
        if cookies:
            # Built as a header rather than passed via httpx's per-request
            # `cookies=` kwarg (deprecated: it merges into shared client-jar
            # state). This keeps each Session's cookies isolated per call.
            existing = headers.get("Cookie", "")
            pairs = "; ".join(f"{k}={v}" for k, v in cookies.items())
            headers["Cookie"] = f"{existing}; {pairs}" if existing else pairs

        # Per-request redirect override — scanners that need to see raw
        # 3xx responses (e.g. SQLi redirect bypass, open-redirect) pass
        # follow_redirects=False; everything else uses the client default.
        req_kw: dict[str, Any] = dict(kw)
        if follow_redirects is not None:
            req_kw["follow_redirects"] = follow_redirects

        start = time.monotonic()
        resp = await self._client.request(method, url, headers=headers, **req_kw)
        elapsed_ms = round((time.monotonic() - start) * 1000, 1)
        self._log(method, url, resp, elapsed_ms)
        return resp

    async def get(self, url: str, **kw: Any) -> httpx.Response:
        return await self.request("GET", url, **kw)

    async def post(self, url: str, **kw: Any) -> httpx.Response:
        return await self.request("POST", url, **kw)

    async def put(self, url: str, **kw: Any) -> httpx.Response:
        return await self.request("PUT", url, **kw)

    async def delete(self, url: str, **kw: Any) -> httpx.Response:
        return await self.request("DELETE", url, **kw)

    def _log(self, method: str, url: str, resp: httpx.Response, elapsed_ms: float) -> None:
        entry = {
            "ts": time.time(),
            "method": method,
            "url": url,
            "status": resp.status_code,
            "len": len(resp.content),
            "elapsed_ms": elapsed_ms,
        }
        with self.log_path.open("a", encoding="utf-8") as f:
            f.write(json.dumps(entry) + "\n")
