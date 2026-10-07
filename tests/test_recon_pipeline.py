"""Integration test: crawl -> JS extract -> source-map detect on a mock site."""
import json

import httpx

from agent.http import HttpClient
from agent.recon.pipeline import format_summary, run_recon, write_report
from agent.scope import ALLOWED

HOST = next(iter(ALLOWED))
BASE = f"https://{HOST}"

HTML = """<html><body>
  <a href="/about">about</a>
  <form action="/login" method="post"><input name="user"><input name="pw"></form>
  <script src="/static/app.js"></script>
  <script src="https://cdn.evil.example/lib.js"></script>
</body></html>"""
JS = """fetch('/api/users?page=1');
axios.post('/api/login', {username: u, password: p});
//# sourceMappingURL=app.js.map
"""
SMAP = json.dumps({"version": 3, "sources": ["src/a.js", "src/b.js", "src/c.js"]})


def _handler(req: httpx.Request) -> httpx.Response:
    assert req.url.host == HOST  # off-scope CDN must never be requested
    html = {"headers": {"content-type": "text/html"}}
    routes = {
        "/": httpx.Response(200, text=HTML, **html),
        "/about": httpx.Response(200, text="<html>about</html>", **html),
        "/static/app.js": httpx.Response(200, text=JS, headers={"content-type": "text/javascript"}),
        "/static/app.js.map": httpx.Response(200, text=SMAP),
    }
    return routes.get(req.url.path, httpx.Response(404))


async def test_recon_combined_report(tmp_path):
    async with HttpClient(transport=httpx.MockTransport(_handler), log_path=tmp_path / "l.jsonl") as c:
        report = await run_recon(c, BASE + "/")

    assert report["pages_crawled"] == [f"{BASE}/", f"{BASE}/about"]
    assert report["forms"][0]["action"] == f"{BASE}/login"
    assert report["forms"][0]["inputs"] == ["user", "pw"]
    assert report["js_urls"] == [f"{BASE}/static/app.js"]
    assert report["skipped_js"] == ["https://cdn.evil.example/lib.js"]

    eps = {(e["method"], e["path"]): e for e in report["endpoints"]}
    assert eps[("GET", "/api/users")]["params"] == ["page"]
    assert eps[("POST", "/api/login")]["params"] == ["password", "username"]
    assert all(e["source"] == f"{BASE}/static/app.js" for e in report["endpoints"])

    [sm] = report["sourcemaps"]
    assert sm["map_url"] == f"{BASE}/static/app.js.map" and sm["source_count"] == 3

    s = report["summary"]
    assert (s["pages"], s["forms"], s["js_files"], s["sourcemaps"], s["sources_exposed"]) == (2, 1, 1, 1, 3)

    path = write_report(report, tmp_path / "outputs")
    assert path.name.startswith(f"recon_{HOST}_") and path.suffix == ".json"
    assert json.loads(path.read_text()) == report
    assert "2 pages" in format_summary(report, path)


def test_extract_chunk_refs():
    from agent.recon.pipeline import extract_chunk_refs

    js = (
        'const x=()=>import("./lazy-AbC123xy.js");'
        'm.f||(m.f=["assets/a-Zx81kQ2p.js","assets/style-Qw3rTy.css"]);'
        'load("assets/b-Pq9wEr71.js");import("https://evil.example/x.js");'
    )
    refs = extract_chunk_refs(js, f"{BASE}/assets/index-1.js")
    assert f"{BASE}/assets/lazy-AbC123xy.js" in refs
    assert f"{BASE}/assets/assets/a-Zx81kQ2p.js" in refs  # resolved against the JS file's base
    assert f"{BASE}/assets/assets/b-Pq9wEr71.js" in refs
    assert "https://evil.example/x.js" in refs  # pipeline drops cross-origin refs
    assert not any(r.endswith(".css") for r in refs)


async def test_recon_follows_chunks_deduped_scoped_and_capped(tmp_path):
    fetched: list[str] = []
    chunks = {
        "/static/app.js": 'import("./c1.js");import("./c2.js");import("https://cdn.evil.example/x.js");',
        "/static/c1.js": 'import("./c2.js");fetch("/api/chunked?q=1");//# sourceMappingURL=c1.js.map',
        "/static/c2.js": f"var k='AKIAIOSFODNN7EXAMPLE';import('./app.js');",
    }

    def handler(req: httpx.Request) -> httpx.Response:
        assert req.url.host == HOST
        fetched.append(req.url.path)
        if req.url.path == "/":
            return httpx.Response(200, text='<script src="/static/app.js"></script>', headers={"content-type": "text/html"})
        if req.url.path in chunks:
            return httpx.Response(200, text=chunks[req.url.path], headers={"content-type": "text/javascript"})
        if req.url.path == "/static/c1.js.map":
            return httpx.Response(200, text=SMAP)
        return httpx.Response(404)

    async with HttpClient(transport=httpx.MockTransport(handler), log_path=tmp_path / "l.jsonl") as c:
        report = await run_recon(c, BASE + "/")
    assert report["js_urls"] == [f"{BASE}/static/{n}.js" for n in ("app", "c1", "c2")]
    assert len(report["js_urls"]) == len(set(report["js_urls"]))  # each chunk processed once
    assert "https://cdn.evil.example/x.js" in report["skipped_js"]
    assert any(e["path"] == "/api/chunked" for e in report["endpoints"])
    assert [m["map_url"] for m in report["sourcemaps"]] == [f"{BASE}/static/c1.js.map"]
    assert any(s["type"] == "aws_access_key" and s["source"].endswith("c2.js") for s in report["secrets"])

    async with HttpClient(transport=httpx.MockTransport(handler), log_path=tmp_path / "l2.jsonl") as c:
        capped = await run_recon(c, BASE + "/", max_js_files=2)
    assert len(capped["js_urls"]) == 2


async def test_recon_folds_in_archive_section_and_new_js(tmp_path):
    """include_archive=True: wayback/urlscan hits land under report["archive"],
    and any NEW in-scope JS they surface gets fetched + extracted + source-mapped
    + secret-scanned exactly like crawled JS -- deduped against what the crawl
    already found."""
    CDX_ROWS = [["original"], [f"{BASE}/static/app.js"], [f"{BASE}/static/old.js"]]
    URLSCAN_RESULTS = {"results": [{"page": {"url": f"{BASE}/api/legacy?id=1"}}]}

    def handler(req: httpx.Request) -> httpx.Response:
        if req.url.host == "web.archive.org":
            return httpx.Response(200, json=CDX_ROWS)
        if req.url.host == "urlscan.io":
            return httpx.Response(200, json=URLSCAN_RESULTS)
        assert req.url.host == HOST
        html = {"headers": {"content-type": "text/html"}}
        routes = {
            "/": httpx.Response(200, text=HTML, **html),
            "/about": httpx.Response(200, text="<html>about</html>", **html),
            "/static/app.js": httpx.Response(200, text=JS, headers={"content-type": "text/javascript"}),
            "/static/app.js.map": httpx.Response(200, text=SMAP),
            "/static/old.js": httpx.Response(
                200,
                text="fetch('/api/archived?x=1'); var k='AKIAIOSFODNN7EXAMPLE';",
                headers={"content-type": "text/javascript"},
            ),
        }
        return routes.get(req.url.path, httpx.Response(404))

    async with HttpClient(transport=httpx.MockTransport(handler), log_path=tmp_path / "l.jsonl") as c:
        report = await run_recon(c, BASE + "/", include_archive=True)

    assert HOST in report["archive"]
    arc = report["archive"][HOST]
    assert arc["sources"]["wayback"] == "wayback: 2 urls"
    assert arc["sources"]["urlscan"] == "urlscan: 1 urls"
    assert arc["errors"] == []

    # app.js was already found by the crawl -> not double-counted as "new"
    # old.js is new archive-only JS -> fed into the same extraction pipeline
    assert f"{BASE}/static/old.js" in report["js_urls"]
    assert report["summary"]["archive_new_js"] == 1
    assert report["summary"]["archive_urls"] == 3  # app.js + old.js + /api/legacy

    assert any(e["path"] == "/api/archived" for e in report["endpoints"])
    assert any(s["type"] == "aws_access_key" and s["source"].endswith("old.js") for s in report["secrets"])

    assert "archive: 3 urls, 1 new JS" in format_summary(report, tmp_path / "r.json")


async def test_recon_without_archive_flag_has_no_archive_section(tmp_path):
    async with HttpClient(transport=httpx.MockTransport(_handler), log_path=tmp_path / "l.jsonl") as c:
        report = await run_recon(c, BASE + "/")  # include_archive defaults to False
    assert report["archive"] == {}
    assert "archive:" not in format_summary(report, tmp_path / "r.json")
