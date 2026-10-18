"""Tests for agent.auth.login — auto-login form detection."""
from __future__ import annotations

import pytest
import httpx

from agent.auth.login import (
    _parse_forms,
    _is_login_form,
    _find_username_field,
    _find_password_field,
    auto_login,
)
from agent.http import HttpClient, Session
from agent.scope import add_to_scope


# ── Form parsing ───────────────────────────────────────────

def test_parse_login_form():
    html = """
    <form action="/auth/login" method="POST">
        <input type="text" name="username">
        <input type="password" name="password">
        <input type="hidden" name="csrf_token" value="abc123">
        <button type="submit">Login</button>
    </form>
    """
    forms = _parse_forms(html)
    assert len(forms) == 1
    f = forms[0]
    assert f["action"] == "/auth/login"
    assert f["method"] == "POST"
    assert len(f["fields"]) == 3
    assert _is_login_form(f)


def test_parse_non_login_form():
    html = """
    <form action="/search" method="GET">
        <input type="text" name="q">
        <button type="submit">Search</button>
    </form>
    """
    forms = _parse_forms(html)
    assert len(forms) == 1
    assert not _is_login_form(forms[0])


def test_find_username_field():
    fields = [
        {"name": "csrf", "type": "hidden", "value": "tok"},
        {"name": "email", "type": "email", "value": ""},
        {"name": "password", "type": "password", "value": ""},
    ]
    assert _find_username_field(fields) == "email"


def test_find_username_field_fallback_to_text():
    fields = [
        {"name": "login_id", "type": "text", "value": ""},
        {"name": "pass", "type": "password", "value": ""},
    ]
    assert _find_username_field(fields) == "login_id"


def test_find_password_field():
    fields = [
        {"name": "user", "type": "text", "value": ""},
        {"name": "passwd", "type": "password", "value": ""},
    ]
    assert _find_password_field(fields) == "passwd"


# ── Integration with mock transport ───────────────────────

LOGIN_PAGE_HTML = """
<html><body>
<form action="/do-login" method="POST">
    <input type="text" name="username">
    <input type="password" name="password">
    <input type="hidden" name="_token" value="csrf123">
    <button>Sign In</button>
</form>
</body></html>
"""


def _make_mock_transport(login_page_html: str, login_success: bool = True):
    """Build a mock transport that serves a login page and handles POST."""

    async def handler(request: httpx.Request) -> httpx.Response:
        if request.method == "GET":
            return httpx.Response(200, text=login_page_html)
        if request.method == "POST" and "/do-login" in str(request.url):
            if login_success:
                return httpx.Response(
                    302,
                    headers={
                        "Location": "/dashboard",
                        "Set-Cookie": "session_id=abc123; Path=/; HttpOnly",
                    },
                )
            else:
                return httpx.Response(
                    200,
                    text="<html>Login failed: invalid credentials</html>",
                )
        return httpx.Response(404)

    return httpx.MockTransport(handler)


@pytest.mark.asyncio
async def test_auto_login_success():
    add_to_scope("testapp.local")
    transport = _make_mock_transport(LOGIN_PAGE_HTML, login_success=True)
    async with HttpClient(transport=transport) as client:
        session = await auto_login(
            client, "https://testapp.local", "admin", "pass123",
        )
    assert session is not None
    assert "session_id" in session.cookies
    assert session.cookies["session_id"] == "abc123"


@pytest.mark.asyncio
async def test_auto_login_failure():
    add_to_scope("testapp.local")
    transport = _make_mock_transport(LOGIN_PAGE_HTML, login_success=False)
    async with HttpClient(transport=transport) as client:
        session = await auto_login(
            client, "https://testapp.local", "admin", "wrong",
        )
    assert session is None


@pytest.mark.asyncio
async def test_auto_login_no_form():
    add_to_scope("testapp.local")
    transport = _make_mock_transport("<html><body>No forms here</body></html>")
    async with HttpClient(transport=transport) as client:
        session = await auto_login(
            client, "https://testapp.local", "admin", "pass",
        )
    assert session is None
