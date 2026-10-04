"""Unit test: crawler collects links/forms/scripts across linked pages and
honours depth, same-origin, scheme and max-pages limits."""
import httpx

from agent.http import HttpClient
from agent.recon.crawler import crawl
from agent.scope import ALLOWED

HOST = next(iter(ALLOWED))
BASE = f"https://{HOST}"

PAGES = {
    "/": f"""<html><body>
        <a href="/a">A</a> <a href="{BASE}/a#frag">A again</a>
        <a href="mailto:x@y.z">m</a> <a href="tel:123">t</a> <a href="javascript:void(0)">j</a>
        <a href="https://evil.example.com/x">off-origin</a>
        <script src="/static/app.js"></script>
        </body></html>""",
    "/a": """<html><body>
        <a href="/b">B</a>
        <form action="/login" method="post">
          <input name="user"><input type="password" name="pw"><input type="submit">
          <select name="role"></select><textarea name="note"></textarea>
        </form>
        <script src="vendor.js"></script>
        </body></html>""",
    "/b": '<html><body><a href="/c">C</a><form><input name="q"></form></body></html>',
    "/c": "<html><body>too deep</body></html>",
}


def _transport(hits: list[str]) -> httpx.MockTransport:
    def handler(req: httpx.Request) -> httpx.Response:
        assert req.url.host == HOST  # nothing off-origin may be requested
        hits.append(req.url.path)
        body = PAGES.get(req.url.path)
        if body is None:
            return httpx.Response(404)
        return httpx.Response(200, text=body, headers={"content-type": "text/html"})

    return httpx.MockTransport(handler)


async def test_collects_links_forms_scripts(tmp_path):
    hits: list[str] = []
    async with HttpClient(transport=_transport(hits), log_path=tmp_path / "l.jsonl") as c:
        r = await crawl(c, BASE + "/", max_depth=2)

    assert r["pages_crawled"] == [f"{BASE}/", f"{BASE}/a", f"{BASE}/b"]
    assert f"{BASE}/c" in r["discovered_urls"]  # seen at depth 2, not fetched
    assert "/c" not in hits
    assert len(r["discovered_urls"]) == len(set(r["discovered_urls"]))
    assert not any("evil" in u or u.startswith(("mailto", "tel", "javascript")) for u in r["discovered_urls"])

    assert r["script_urls"] == [f"{BASE}/static/app.js", f"{BASE}/vendor.js"]

    login = next(f for f in r["forms"] if f["action"] == f"{BASE}/login")
    assert login["method"] == "POST"
    assert login["inputs"] == ["user", "pw", "role", "note"]
    q = next(f for f in r["forms"] if f["page"] == f"{BASE}/b")
    assert q["method"] == "GET" and q["action"] == f"{BASE}/b" and q["inputs"] == ["q"]


async def test_depth_and_page_caps(tmp_path):
    hits: list[str] = []
    async with HttpClient(transport=_transport(hits), log_path=tmp_path / "l.jsonl") as c:
        r0 = await crawl(c, BASE + "/", max_depth=0)
        r1 = await crawl(c, BASE + "/", max_depth=5, max_pages=2)
    assert r0["pages_crawled"] == [f"{BASE}/"]
    assert r0["discovered_urls"] == [f"{BASE}/", f"{BASE}/a"]
    assert len(r1["pages_crawled"]) == 2
