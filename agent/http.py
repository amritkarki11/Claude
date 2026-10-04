"""Async HTTP engine. Every outbound request is scope-gated — nothing leaves
the box for a host that isn't on the allowlist. Supports JWT / cookie
(JSESSIONID) / Bearer / custom-header auth via Session, structured JSONL
request/response logging, and an optional Burp proxy toggle for debugging."""
from __future__ import annotations

import json
import pathlib
import time
from dataclasses import dataclass, field
from typing import Any

import httpx

from .scope import check as scope_check

BURP_PROXY = "http://127.0.0.1:8080"
DEFAULT_LOG_PATH = pathlib.Path(__file__).parent.parent / "outputs" / "http_log.jsonl"


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
        log_path: pathlib.Path | str = DEFAULT_LOG_PATH,
        transport: httpx.AsyncBaseTransport | None = None,
    ) -> None:
        self.log_path = pathlib.Path(log_path)
        self.log_path.parent.mkdir(parents=True, exist_ok=True)

        # `transport` override exists so tests can inject an httpx
        # MockTransport instead of hitting the real network.
        transport = transport or httpx.AsyncHTTPTransport(retries=retries)
        client_kwargs: dict[str, Any] = {"timeout": timeout, "transport": transport}
        if use_proxy:
            # Burp's CA isn't trusted by default; disable verification so
            # intercepted TLS traffic doesn't fail locally during debugging.
            client_kwargs["proxy"] = BURP_PROXY
            client_kwargs["verify"] = False
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
        **kw: Any,
    ) -> httpx.Response:
        scope_check(url)  # fail closed before anything touches the network

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

        start = time.monotonic()
        resp = await self._client.request(method, url, headers=headers, **kw)
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
