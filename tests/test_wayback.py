"""wayback: CDX + URLScan parsing, merge/dedupe, JS categorization, and
that a failing source is reported rather than swallowed."""
import json

import httpx

from agent.http import HttpClient
from agent.recon.wayback import (
    categorize,
    fetch_urlscan,
    fetch_wayback,
    run_archive_recon,
)
from agent.scope import ALLOWED, in_scope

HOST = next(iter(ALLOWED))

CDX_ROWS = [
    ["original"],
    [f"https://{HOST}/app.js"],
    [f"https://{HOST}/api/users?id=1"],  # endpoint
    [f"https://{HOST}/images/logo.png"],  # static -> other
    [f"https://{HOST}/app.js"],  # duplicate of the first row
]

URLSCAN_RESULTS = {
    "results": [
        {"page": {"url": f"https://{HOST}/app.js"}},  # dup across sources
        {"page": {"url": f"https://{HOST}/api/orders"}},  # endpoint
        {"page": {"url": "https://unrelated.example.net/bundle.js"}},  # out of scope
        {"page": {}},  # no url -> skipped, not a crash
    ]
}


def _ok_transport(urlscan_status: int = 200) -> httpx.MockTransport:
    def handler(req: httpx.Request) -> httpx.Response:
        if req.url.host == "web.archive.org":
            return httpx.Response(200, json=CDX_ROWS)
        if req.url.host == "urlscan.io":
            if urlscan_status != 200:
                return httpx.Response(urlscan_status, text="rate limited")
            return httpx.Response(200, json=URLSCAN_RESULTS)
        if req.url.host == HOST and req.url.path == "/app.js":
            return httpx.Response(200, text="fetch('/api/from-js?x=1')")
        return httpx.Response(404)

    return httpx.MockTransport(handler)


def test_categorize():
    assert categorize(f"https://{HOST}/app.js") == "js_urls"
    assert categorize(f"https://{HOST}/lib.mjs") == "js_urls"
    assert categorize(f"https://{HOST}/images/logo.png") == "other"
    assert categorize(f"https://{HOST}/api/users?id=1") == "endpoints"
    assert categorize(f"https://{HOST}/api/orders") == "endpoints"


async def test_fetch_wayback_parses_cdx_json(tmp_path):
    async with HttpClient(transport=_ok_transport(), log_path=tmp_path / "l.jsonl") as c:
        urls, status = await fetch_wayback(c, HOST)
    assert urls == [
        f"https://{HOST}/app.js",
        f"https://{HOST}/api/users?id=1",
        f"https://{HOST}/images/logo.png",
        f"https://{HOST}/app.js",
    ]
    assert status == "wayback: 4 urls"
    # the archive host itself must now be reachable (added to scope, not blocked)
    assert in_scope("https://web.archive.org/x")


async def test_fetch_urlscan_parses_results_and_skips_missing_url(tmp_path):
    async with HttpClient(transport=_ok_transport(), log_path=tmp_path / "l.jsonl") as c:
        urls, status = await fetch_urlscan(c, HOST)
    assert urls == [
        f"https://{HOST}/app.js",
        f"https://{HOST}/api/orders",
        "https://unrelated.example.net/bundle.js",
    ]
    assert status == "urlscan: 3 urls"


async def test_run_archive_recon_merges_dedupes_and_categorizes(tmp_path):
    async with HttpClient(transport=_ok_transport(), log_path=tmp_path / "l.jsonl") as c:
        result = await run_archive_recon(c, HOST)

    # deduped across both sources; categorized by extension regardless of scope
    assert result.js_urls == [f"https://{HOST}/app.js", "https://unrelated.example.net/bundle.js"]
    assert set(result.endpoints) == {
        f"https://{HOST}/api/users?id=1",
        f"https://{HOST}/api/orders",
    }
    assert result.other == [f"https://{HOST}/images/logo.png"]
    assert result.sources == {"wayback": "wayback: 4 urls", "urlscan": "urlscan: 3 urls"}
    assert result.errors == []

    # in-scope JS got fed through the normal extraction flow
    paths = {e["path"] for e in result.js_endpoints}
    assert "/api/from-js" in paths


async def test_failing_source_is_reported_not_swallowed(tmp_path):
    async with HttpClient(transport=_ok_transport(urlscan_status=429), log_path=tmp_path / "l.jsonl") as c:
        result = await run_archive_recon(c, HOST)

    assert result.sources["urlscan"] == "urlscan: unavailable (429)"
    assert result.sources["wayback"] == "wayback: 4 urls"
    assert "urlscan: unavailable (429)" in result.errors
    # wayback's urls still made it through -- one source failing doesn't empty the merge
    assert result.js_urls == [f"https://{HOST}/app.js"]
    assert set(result.endpoints) == {f"https://{HOST}/api/users?id=1"}


async def test_both_sources_down_reports_both_without_raising(tmp_path):
    def handler(req: httpx.Request) -> httpx.Response:
        return httpx.Response(503, text="down")

    async with HttpClient(transport=httpx.MockTransport(handler), log_path=tmp_path / "l.jsonl") as c:
        result = await run_archive_recon(c, HOST)

    assert result.sources["wayback"] == "wayback: unavailable (503)"
    assert result.sources["urlscan"] == "urlscan: unavailable (503)"
    assert len(result.errors) == 2
    assert result.js_urls == result.endpoints == result.other == []
