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
