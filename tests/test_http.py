"""Phase 1 unit test: a scoped request succeeds and logs correctly; an
out-of-scope URL is refused with ScopeError before any network I/O."""
import json

import httpx
import pytest

from agent.http import HttpClient, Session
from agent.scope import ScopeError, ALLOWED

SCOPED_HOST = next(iter(ALLOWED))
SCOPED_URL = f"https://{SCOPED_HOST}/data/myaccount/sendOTP"
OUT_OF_SCOPE_URL = "https://evil.example.com/anything"


def _mock_transport(expected_auth: str | None = None) -> httpx.MockTransport:
    def handler(request: httpx.Request) -> httpx.Response:
        if expected_auth is not None:
            assert request.headers.get("Authorization") == expected_auth
        return httpx.Response(200, json={"ok": True})

    return httpx.MockTransport(handler)


async def test_scoped_authed_request_works_and_logs(tmp_path):
    log_path = tmp_path / "http_log.jsonl"
    session = Session(bearer="test-token-123")

    async with HttpClient(
        transport=_mock_transport(expected_auth="Bearer test-token-123"),
        log_path=log_path,
    ) as client:
        resp = await client.get(SCOPED_URL, session=session)

    assert resp.status_code == 200
    assert resp.json() == {"ok": True}

    lines = log_path.read_text(encoding="utf-8").strip().splitlines()
    assert len(lines) == 1
    entry = json.loads(lines[0])
    assert entry["method"] == "GET"
    assert entry["url"] == SCOPED_URL
    assert entry["status"] == 200
    assert entry["len"] == len(resp.content)
    assert entry["elapsed_ms"] >= 0


async def test_jsessionid_cookie_auth_is_sent(tmp_path):
    log_path = tmp_path / "http_log.jsonl"
    session = Session(jsessionid="ABC123")

    def handler(request: httpx.Request) -> httpx.Response:
        assert "JSESSIONID=ABC123" in request.headers.get("Cookie", "")
        return httpx.Response(200)

    async with HttpClient(transport=httpx.MockTransport(handler), log_path=log_path) as client:
        resp = await client.get(SCOPED_URL, session=session)

    assert resp.status_code == 200


async def test_out_of_scope_url_raises_scope_error(tmp_path):
    log_path = tmp_path / "http_log.jsonl"
    called = False

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal called
        called = True
        return httpx.Response(200)

    async with HttpClient(transport=httpx.MockTransport(handler), log_path=log_path) as client:
        with pytest.raises(ScopeError):
            await client.get(OUT_OF_SCOPE_URL)

    # fail closed: the mock transport was never reached, and nothing logged
    assert called is False
    assert not log_path.exists()
