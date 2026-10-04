"""Unit test: a JS file with a sourceMappingURL comment and a valid .map is
detected with the right source count; non-maps are rejected."""
import json

import httpx

from agent.http import HttpClient
from agent.recon.sourcemap_detector import detect_sourcemaps
from agent.scope import ALLOWED

HOST = next(iter(ALLOWED))
BASE = f"https://{HOST}/"

SOURCES = ["webpack:///./src/index.js", "webpack:///./src/api.js", "webpack:///./src/auth.js"]
MAP_JSON = {"version": 3, "file": "app.js", "sources": SOURCES, "mappings": "AAAA"}


def _transport() -> httpx.MockTransport:
    def handler(req: httpx.Request) -> httpx.Response:
        path = req.url.path
        if path == "/static/app.js":
            return httpx.Response(200, text="console.log(1);\n//# sourceMappingURL=app.js.map\n")
        if path == "/static/app.js.map":
            return httpx.Response(200, text=json.dumps(MAP_JSON))
        if path == "/static/plain.js":  # no comment; conventional map is an HTML 200
            return httpx.Response(200, text="var a=1;")
        if path == "/static/plain.js.map":
            return httpx.Response(200, text="<html>not found page</html>")
        if path == "/static/conv.js":  # no comment, but conventional map exists
            return httpx.Response(200, text="var b=2;")
        if path == "/static/conv.js.map":
            return httpx.Response(200, text=json.dumps({"version": 3, "sources": ["a.ts"]}))
        return httpx.Response(404)

    return httpx.MockTransport(handler)


async def test_detects_exposed_maps(tmp_path):
    js = ["/static/app.js", "/static/plain.js", f"https://{HOST}/static/conv.js"]
    async with HttpClient(transport=_transport(), log_path=tmp_path / "log.jsonl") as client:
        found = await detect_sourcemaps(client, BASE, js)

    by_js = {r["js_url"]: r for r in found}
    assert set(by_js) == {f"https://{HOST}/static/app.js", f"https://{HOST}/static/conv.js"}

    app = by_js[f"https://{HOST}/static/app.js"]
    assert app["map_url"] == f"https://{HOST}/static/app.js.map"
    assert app["status"] == 200
    assert app["source_count"] == 3
    assert app["source_files"] == SOURCES

    assert by_js[f"https://{HOST}/static/conv.js"]["source_count"] == 1


async def test_off_scope_map_comment_is_skipped(tmp_path):
    def handler(req: httpx.Request) -> httpx.Response:
        if req.url.path == "/x.js":
            return httpx.Response(200, text="//# sourceMappingURL=https://evil.example.com/x.js.map")
        assert req.url.host == HOST  # nothing off-scope may be requested
        return httpx.Response(404)

    async with HttpClient(transport=httpx.MockTransport(handler), log_path=tmp_path / "l.jsonl") as c:
        assert await detect_sourcemaps(c, BASE, ["/x.js"]) == []
