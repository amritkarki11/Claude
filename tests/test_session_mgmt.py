"""Tests for session management: validity, expiry, JSON login, re-auth."""
from __future__ import annotations

import time

import pytest
import httpx

from agent.http import HttpClient, Session
from agent.auth.login import check_session, reauth, _try_json_login
from agent.scope import add_to_scope


# ── Session validity ─────────────────────────────────────────

def test_session_valid_with_cookies():
    s = Session(cookies={"sid": "abc"})
    assert s.is_valid
    assert not s.is_expired


def test_session_invalid_empty():
    s = Session()
    assert not s.is_valid


def test_session_expired(monkeypatch):
    s = Session(cookies={"sid": "abc"}, max_age=0.01)
    time.sleep(0.02)
    assert s.is_expired
    assert not s.is_valid


def test_refresh_timestamp():
    s = Session(cookies={"sid": "abc"}, max_age=0.01)
    time.sleep(0.02)
    assert s.is_expired
    s.refresh_timestamp()
    assert not s.is_expired


# ── JSON API login ───────────────────────────────────────────

def _json_login_transport():
    async def handler(request: httpx.Request) -> httpx.Response:
        if request.method == "POST" and "/api/login" in str(request.url):
            import json
            body = json.loads(request.content)
            if body.get("username") == "admin" and body.get("password") == "secret":
                return httpx.Response(
                    200,
                    json={"token": "jwt.test.token", "user": "admin"},
                    headers={"Content-Type": "application/json"},
                )
            return httpx.Response(401, json={"error": "invalid credentials"})
        return httpx.Response(404)

    return httpx.MockTransport(handler)


@pytest.mark.asyncio
async def test_json_login_success():
    add_to_scope("apiapp.local")
    transport = _json_login_transport()
    async with HttpClient(transport=transport) as client:
        session = await _try_json_login(
            client, "https://apiapp.local", "admin", "secret",
        )
    assert session is not None
    assert session.bearer == "jwt.test.token"


@pytest.mark.asyncio
async def test_json_login_wrong_creds():
    add_to_scope("apiapp.local")
    transport = _json_login_transport()
    async with HttpClient(transport=transport) as client:
        session = await _try_json_login(
            client, "https://apiapp.local", "admin", "wrong",
        )
    assert session is None


# ── check_session ────────────────────────────────────────────

def _check_transport(status: int):
    async def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(status)
    return httpx.MockTransport(handler)


@pytest.mark.asyncio
async def test_check_session_valid():
    add_to_scope("app.local")
    session = Session(cookies={"sid": "abc"})
    async with HttpClient(transport=_check_transport(200)) as client:
        assert await check_session(client, session, "https://app.local/dashboard")


@pytest.mark.asyncio
async def test_check_session_expired_401():
    add_to_scope("app.local")
    session = Session(cookies={"sid": "abc"})
    async with HttpClient(transport=_check_transport(401)) as client:
        assert not await check_session(client, session, "https://app.local/dashboard")


# ── reauth ───────────────────────────────────────────────────

LOGIN_HTML = """<form action="/do-login" method="POST">
<input type="text" name="username">
<input type="password" name="password">
</form>"""


def _reauth_transport():
    async def handler(request: httpx.Request) -> httpx.Response:
        if request.method == "GET":
            return httpx.Response(200, text=LOGIN_HTML)
        if request.method == "POST" and "/do-login" in str(request.url):
            return httpx.Response(
                302,
                headers={
                    "Location": "/home",
                    "Set-Cookie": "sid=refreshed; Path=/",
                },
            )
        return httpx.Response(200, text="<html>home</html>")

    return httpx.MockTransport(handler)


@pytest.mark.asyncio
async def test_reauth_with_stored_creds():
    add_to_scope("app.local")
    old = Session(cookies={"sid": "old"}, max_age=0.01)
    old._credentials = {"username": "admin", "password": "pass"}
    old._login_url = "https://app.local"
    time.sleep(0.02)
    assert old.is_expired

    async with HttpClient(transport=_reauth_transport()) as client:
        new = await reauth(client, old)
    assert new is not None
    assert "sid" in new.cookies


@pytest.mark.asyncio
async def test_reauth_no_creds():
    add_to_scope("app.local")
    session = Session(cookies={"sid": "old"})
    async with HttpClient(transport=_reauth_transport()) as client:
        result = await reauth(client, session)
    assert result is None
