"""Detect exposed JavaScript source maps.

For each JS file: (1) look for a trailing `//# sourceMappingURL=` comment,
(2) try the conventional `<jsfile>.map` path, and (3) confirm the candidate
returns HTTP 200 and parses as JSON with a "sources" list. Only maps that pass
(3) are reported. All fetching goes through agent.http.HttpClient, so every
request is scope-gated; a candidate outside scope is skipped, not fetched.

Output: list of {"js_url", "map_url", "status", "source_count", "source_files"}.
"""
from __future__ import annotations

import json
import re
from urllib.parse import urldefrag, urljoin, urlsplit, urlunsplit

import httpx

from ..http import HttpClient, Session
from ..scope import ScopeError

# Both `//# sourceMappingURL=` and the legacy `//@` form; also CSS-style `/*# ... */`.
_RE_SMAP = re.compile(r"""(?://|/\*)[#@]\s*sourceMappingURL=([^\s*'"]+)""")
_TAIL_BYTES = 4096  # the comment is specified to be at the end of the file
_XSSI_PREFIX = re.compile(r"^\)\]\}'[^\n]*\n")


def find_map_comment(js_text: str) -> str | None:
    """Return the sourceMappingURL value from the end of the file, or None.
    The last match in the tail wins (that is the one browsers honour)."""
    matches = _RE_SMAP.findall(js_text[-_TAIL_BYTES:])
    return matches[-1] if matches else None


def conventional_map_url(js_url: str) -> str:
    """`<jsfile>.map`, keeping any query string off the path."""
    p = urlsplit(urldefrag(js_url)[0])
    return urlunsplit((p.scheme, p.netloc, p.path + ".map", "", ""))


def parse_source_map(body: str) -> list[str] | None:
    """Return the "sources" list if body is a JSON object with one, else None."""
    try:
        data = json.loads(_XSSI_PREFIX.sub("", body, count=1))
    except ValueError:
        return None
    if not isinstance(data, dict) or not isinstance(data.get("sources"), list):
        return None
    return [str(s) for s in data["sources"]]


async def _get(client: HttpClient, url: str, session: Session | None) -> httpx.Response | None:
    try:
        return await client.get(url, session=session)
    except ScopeError:
        return None  # off-scope candidate (e.g. CDN-hosted map): never fetched
    except httpx.HTTPError:
        return None


async def _confirm_map(
    client: HttpClient, js_url: str, map_url: str, session: Session | None
) -> dict | None:
    resp = await _get(client, map_url, session)
    if resp is None or resp.status_code != 200:
        return None
    sources = parse_source_map(resp.text)
    if sources is None:
        return None
    return {
        "js_url": js_url,
        "map_url": map_url,
        "status": resp.status_code,
        "source_count": len(sources),
        "source_files": sources,
    }


async def detect_sourcemaps(
    client: HttpClient,
    base_url: str,
    js_urls: list[str],
    *,
    session: Session | None = None,
) -> list[dict]:
    """Return one record per confirmed source map. `js_urls` may be relative;
    they are resolved against `base_url`."""
    results: list[dict] = []
    for raw in js_urls:
        js_url = urljoin(base_url, raw)

        candidates: list[str] = []
        js_resp = await _get(client, js_url, session)
        if js_resp is not None and js_resp.status_code == 200:
            ref = find_map_comment(js_resp.text)
            # Inline data: maps carry no separate URL to fetch; skip them.
            if ref and not ref.lower().startswith("data:"):
                candidates.append(urljoin(js_url, ref))
        conventional = conventional_map_url(js_url)
        if conventional not in candidates:
            candidates.append(conventional)

        for map_url in candidates:
            found = await _confirm_map(client, js_url, map_url, session)
            if found:
                results.append(found)
                break  # one confirmed map per JS file
    return results
