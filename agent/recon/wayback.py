"""Historical URL discovery: Wayback Machine CDX API + URLScan.io search.

Archive/OSINT lookups, not an attack on the target: the requests land on
web.archive.org / urlscan.io (public third-party archives), not on the
target host. CLAUDE.md's scope guard exists to keep the agent from probing
hosts outside the authorized allowlist; these two archive hosts are added
to the *runtime* allowlist via agent.scope.add_to_scope() -- the same public
hook set_scope()/--target already use -- so the scope-gated HttpClient can
reach them without the guard treating "ask an archive about the target" as
"attack the archive". The actual target host is never added here and still
goes through the normal scope check wherever its URLs are fetched (e.g. the
discovered JS files, below).

Fails loudly per source: each source's outcome is recorded in `sources`
(e.g. "wayback: 142 urls" / "urlscan: unavailable (429)") and a failure is
also appended to `errors`. A source that errors contributes zero URLs to
the merge -- it never raises and never silently disappears.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from urllib.parse import quote, urlsplit

import httpx

from ..http import HttpClient, Session
from ..scope import add_to_scope, in_scope
from .js_extractor import extract_endpoints

CDX_HOST = "web.archive.org"
URLSCAN_HOST = "urlscan.io"

CDX_URL = "http://web.archive.org/cdx/search/cdx"
URLSCAN_URL = "https://urlscan.io/api/v1/search/"

# Same "this is a static asset, not an endpoint" list js_extractor uses,
# minus js/mjs (those are their own bucket, checked first).
_STATIC_EXT = re.compile(
    r"\.(?:css|png|jpe?g|gif|svg|ico|woff2?|ttf|eot|otf|mp[34]|webm|webp|pdf|docx?|xlsx?|zip|txt)$",
    re.I,
)


@dataclass
class ArchiveResult:
    js_urls: list[str] = field(default_factory=list)
    endpoints: list[str] = field(default_factory=list)
    other: list[str] = field(default_factory=list)
    js_endpoints: list[dict] = field(default_factory=list)  # extracted from fetched in-scope JS
    sources: dict[str, str] = field(default_factory=dict)   # source name -> human status
    errors: list[str] = field(default_factory=list)

    @property
    def summary(self) -> dict:
        return {
            "js_urls": len(self.js_urls),
            "endpoints": len(self.endpoints),
            "other": len(self.other),
            "js_endpoints": len(self.js_endpoints),
        }

    def to_dict(self) -> dict:
        return {
            "js_urls": self.js_urls,
            "endpoints": self.endpoints,
            "other": self.other,
            "js_endpoints": self.js_endpoints,
            "sources": self.sources,
            "errors": self.errors,
            "summary": self.summary,
        }


def categorize(url: str) -> str:
    """js_urls (ends in .js/.mjs) / other (known static asset) / endpoints (everything else)."""
    path = urlsplit(url).path.lower()
    if path.endswith((".js", ".mjs")):
        return "js_urls"
    if _STATIC_EXT.search(path):
        return "other"
    return "endpoints"


def _err_label(e: Exception) -> str:
    if isinstance(e, httpx.HTTPStatusError):
        return str(e.response.status_code)
    return type(e).__name__


async def fetch_wayback(client: HttpClient, host: str, *, session: Session | None = None) -> tuple[list[str], str]:
    """Query the CDX API for every archived URL under `host`. Never raises;
    returns ([], "wayback: unavailable (<reason>)") on any failure."""
    add_to_scope(CDX_HOST)
    url = f"{CDX_URL}?url={quote(host, safe='')}/*&output=json&fl=original&collapse=urlkey"
    try:
        resp = await client.get(url, session=session)
        resp.raise_for_status()
        rows = resp.json()
    except httpx.HTTPError as e:
        return [], f"wayback: unavailable ({_err_label(e)})"
    except ValueError as e:  # malformed JSON
        return [], f"wayback: unavailable (bad response: {e})"

    # CDX json output: first row is the field header (["original"]), rest are data rows.
    urls = [row[0] for row in rows[1:]] if rows else []
    return urls, f"wayback: {len(urls)} urls"


async def fetch_urlscan(client: HttpClient, host: str, *, session: Session | None = None) -> tuple[list[str], str]:
    """Query URLScan.io's search API for pages observed under `host`. Never
    raises; returns ([], "urlscan: unavailable (<reason>)") on any failure."""
    add_to_scope(URLSCAN_HOST)
    url = f"{URLSCAN_URL}?q=domain:{quote(host, safe='')}"
    try:
        resp = await client.get(url, session=session)
        resp.raise_for_status()
        data = resp.json()
    except httpx.HTTPError as e:
        return [], f"urlscan: unavailable ({_err_label(e)})"
    except ValueError as e:
        return [], f"urlscan: unavailable (bad response: {e})"

    urls = []
    for r in data.get("results", []) if isinstance(data, dict) else []:
        page_url = (r.get("page") or {}).get("url")
        if page_url:
            urls.append(page_url)
    return urls, f"urlscan: {len(urls)} urls"


async def extract_archive_js(
    client: HttpClient, js_urls: list[str], *, session: Session | None = None
) -> list[dict]:
    """Fetch each discovered JS url that is IN SCOPE (i.e. actually belongs
    to the target, not to an archive host) and feed it through the existing
    js_extractor.extract_endpoints() flow. Out-of-scope JS urls (most
    archive hits will point elsewhere entirely) are skipped, never fetched.
    """
    endpoints: list[dict] = []
    for js in js_urls:
        if not in_scope(js):
            continue
        try:
            resp = await client.get(js, session=session)
            resp.raise_for_status()
        except httpx.HTTPError:
            continue
        endpoints.extend({**e, "source": js} for e in extract_endpoints(resp.text))
    return endpoints


async def run_archive_recon(
    client: HttpClient, host: str, *, session: Session | None = None
) -> ArchiveResult:
    """Fetch + merge + dedupe + categorize archive URLs for `host`, then feed
    in-scope discovered JS through the normal endpoint-extraction flow.

    Designed to be folded into the recon report under an "archive" key,
    e.g. `report["archive"] = (await run_archive_recon(...)).to_dict()`.
    """
    result = ArchiveResult()

    wb_urls, wb_status = await fetch_wayback(client, host, session=session)
    us_urls, us_status = await fetch_urlscan(client, host, session=session)
    result.sources["wayback"] = wb_status
    result.sources["urlscan"] = us_status
    for status in (wb_status, us_status):
        if "unavailable" in status:
            result.errors.append(status)

    seen: set[str] = set()
    for url in wb_urls + us_urls:
        if not url or url in seen:
            continue
        seen.add(url)
        bucket = categorize(url)
        getattr(result, bucket).append(url)

    result.js_endpoints = await extract_archive_js(client, result.js_urls, session=session)
    return result
