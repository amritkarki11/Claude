"""Phase 2.2 unit test: endpoints, methods and params are pulled from sample JS;
URL fetching is scope-gated."""
import httpx
import pytest

from agent.http import HttpClient
from agent.recon.js_extractor import extract_endpoints, extract_from_url
from agent.scope import ALLOWED, ScopeError

SAMPLE_JS = """
const base = "/static/app.js";
function login(u, p) {
  return axios.post("/api/v1/login", { username: u, password: p });
}
async function getUser(id) {
  const r = await fetch(`/api/v1/users/${id}/profile?expand=roles&lang=en`);
  return r.json();
}
fetch("/api/v1/orders", { method: "DELETE", body: JSON.stringify({ orderId: 1, reason: "x" }) });
router.get("/admin/export", handler);
const routes = [{ path: "/dashboard/settings", component: S }];
img.src = "/assets/logo.png";
"""


def _by_path(eps):
    return {e["path"]: e for e in eps}


def test_extracts_endpoints_methods_and_params():
    eps = _by_path(extract_endpoints(SAMPLE_JS))

    assert eps["/api/v1/login"]["method"] == "POST"
    assert eps["/api/v1/login"]["params"] == ["password", "username"]

    prof = eps["/api/v1/users/{id}/profile"]
    assert prof["method"] == "GET"
    assert prof["params"] == ["expand", "id", "lang"]

    assert eps["/api/v1/orders"]["method"] == "DELETE"
    assert eps["/api/v1/orders"]["params"] == ["orderId", "reason"]

    assert eps["/admin/export"]["method"] == "GET"
    assert eps["/dashboard/settings"]["method"] is None

    assert "/static/app.js" not in eps and "/assets/logo.png" not in eps


async def test_extract_from_url_is_scope_gated(tmp_path):
    host = next(iter(ALLOWED))
    transport = httpx.MockTransport(lambda r: httpx.Response(200, text=SAMPLE_JS))
    async with HttpClient(transport=transport, log_path=tmp_path / "l.jsonl") as c:
        eps = await extract_from_url(c, f"https://{host}/main.js")
        assert any(e["path"] == "/api/v1/login" for e in eps)
        with pytest.raises(ScopeError):
            await extract_from_url(c, "https://evil.example.com/main.js")
