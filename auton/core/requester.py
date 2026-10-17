"""WAF-evasion HTTP wrapper — jitter, user-agent rotation, and retry on WAF blocks.

All scanners should use this instead of raw requests/httpx calls during
directory fuzzing and scanning.
"""
from __future__ import annotations

import random
import time
import logging
from dataclasses import dataclass, field
from typing import Any

import httpx

logger = logging.getLogger(__name__)

_USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_5) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64; rv:128.0) Gecko/20100101 Firefox/128.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36 Edg/125.0.0.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_5) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:128.0) Gecko/20100101 Firefox/128.0",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_5 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:128.0) Gecko/20100101 Firefox/128.0",
]

_WAF_STATUS_CODES = {403, 429, 503}
_WAF_PAUSE_SECONDS = 10.0
_MAX_RETRIES = 3


@dataclass
class RequesterConfig:
    """Tuning knobs for the WAF-evasion requester."""
    jitter_min: float = 0.5
    jitter_max: float = 2.0
    waf_pause: float = _WAF_PAUSE_SECONDS
    max_retries: int = _MAX_RETRIES
    timeout: float = 15.0
    verify_ssl: bool = True


class Requester:
    """HTTP client wrapper with WAF evasion: jitter, UA rotation, and retry.

    Usage:
        req = Requester()
        resp = req.get("https://example.com/api/users")
        resp = req.post("https://example.com/login", data={"user": "admin"})
    """

    def __init__(self, config: RequesterConfig | None = None):
        self._config = config or RequesterConfig()
        self._ua_index = random.randint(0, len(_USER_AGENTS) - 1)
        self._client = httpx.Client(
            timeout=self._config.timeout,
            verify=self._config.verify_ssl,
            follow_redirects=True,
        )

    @property
    def current_ua(self) -> str:
        return _USER_AGENTS[self._ua_index % len(_USER_AGENTS)]

    def _rotate_ua(self) -> str:
        self._ua_index = (self._ua_index + 1) % len(_USER_AGENTS)
        return self.current_ua

    def _jitter(self) -> None:
        delay = random.uniform(self._config.jitter_min, self._config.jitter_max)
        time.sleep(delay)

    def _merge_headers(self, headers: dict[str, str] | None) -> dict[str, str]:
        merged = {"User-Agent": self.current_ua}
        if headers:
            merged.update(headers)
        return merged

    def get(
        self,
        url: str,
        headers: dict[str, str] | None = None,
        params: dict[str, str] | None = None,
        **kwargs: Any,
    ) -> httpx.Response:
        return self._request("GET", url, headers=headers, params=params, **kwargs)

    def post(
        self,
        url: str,
        headers: dict[str, str] | None = None,
        data: Any = None,
        json: Any = None,
        **kwargs: Any,
    ) -> httpx.Response:
        return self._request("POST", url, headers=headers, data=data, json=json, **kwargs)

    def head(
        self,
        url: str,
        headers: dict[str, str] | None = None,
        **kwargs: Any,
    ) -> httpx.Response:
        return self._request("HEAD", url, headers=headers, **kwargs)

    def _request(self, method: str, url: str, **kwargs: Any) -> httpx.Response:
        """Core request method with jitter, WAF detection, and retry."""
        kwargs["headers"] = self._merge_headers(kwargs.get("headers"))

        for attempt in range(self._config.max_retries + 1):
            self._jitter()
            try:
                resp = self._client.request(method, url, **kwargs)
            except httpx.RequestError as exc:
                logger.warning("Request error on %s %s (attempt %d): %s",
                               method, url, attempt + 1, exc)
                if attempt == self._config.max_retries:
                    raise
                time.sleep(self._config.waf_pause)
                continue

            if resp.status_code not in _WAF_STATUS_CODES:
                return resp

            # WAF detected
            if attempt < self._config.max_retries:
                old_ua = self.current_ua
                new_ua = self._rotate_ua()
                logger.info(
                    "WAF detected (%d) on %s — pausing %.0fs, rotating UA",
                    resp.status_code, url, self._config.waf_pause,
                )
                kwargs["headers"]["User-Agent"] = new_ua
                time.sleep(self._config.waf_pause)
            else:
                logger.warning("WAF block persists after %d retries on %s",
                               self._config.max_retries, url)
                return resp

        return resp  # type: ignore[possibly-undefined]

    def close(self) -> None:
        self._client.close()

    def __enter__(self) -> Requester:
        return self

    def __exit__(self, *args: Any) -> None:
        self.close()
