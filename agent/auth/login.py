"""Auto-login — detect a login form, submit credentials, capture the session.

Flow:
  1. Fetch the target URL (or common login paths) looking for a form with
     a password field.
  2. Fill username into the first text/email field, password into the
     password field, submit via POST to the form's action URL.
  3. Capture Set-Cookie headers from the response and build a Session
     carrying those cookies for all subsequent requests.

All requests go through scope.check() via HttpClient.
"""
from __future__ import annotations

import re
from html.parser import HTMLParser
from urllib.parse import urljoin

from ..http import HttpClient, Session
from ..scope import check as scope_check

_LOGIN_PATHS = [
    "/login", "/signin", "/sign-in", "/auth/login", "/account/login",
    "/user/login", "/admin/login", "/wp-login.php", "/users/sign_in",
    "/session/new", "/log-in",
]

_USERNAME_PATTERNS = re.compile(
    r"^(user|username|email|login|uname|user_login|log|user_email"
    r"|signin_email|account|identity|uid)$",
    re.IGNORECASE,
)

_PASSWORD_PATTERNS = re.compile(
    r"^(pass|password|passwd|pwd|user_password|signin_password|secret)$",
    re.IGNORECASE,
)


class _FormParser(HTMLParser):
    """Extract forms with their fields from HTML."""

    def __init__(self) -> None:
        super().__init__()
        self.forms: list[dict] = []
        self._current_form: dict | None = None

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        a = dict(attrs)
        if tag == "form":
            self._current_form = {
                "action": a.get("action", ""),
                "method": (a.get("method") or "GET").upper(),
                "fields": [],
            }
        elif tag == "input" and self._current_form is not None:
            name = a.get("name", "")
            itype = (a.get("type") or "text").lower()
            value = a.get("value", "")
            if name:
                self._current_form["fields"].append({
                    "name": name, "type": itype, "value": value,
                })

    def handle_endtag(self, tag: str) -> None:
        if tag == "form" and self._current_form is not None:
            self.forms.append(self._current_form)
            self._current_form = None


def _is_login_form(form: dict) -> bool:
    """A login form has at least one password field."""
    return any(f["type"] == "password" for f in form["fields"])


def _find_field(fields: list[dict], pattern: re.Pattern) -> str | None:
    """Return the name of the first field matching the pattern."""
    for f in fields:
        if pattern.match(f["name"]):
            return f["name"]
    return None


def _find_username_field(fields: list[dict]) -> str | None:
    """Find the username/email field — try pattern first, fall back to first text/email."""
    matched = _find_field(fields, _USERNAME_PATTERNS)
    if matched:
        return matched
    for f in fields:
        if f["type"] in ("text", "email"):
            return f["name"]
    return None


def _find_password_field(fields: list[dict]) -> str | None:
    return _find_field(fields, _PASSWORD_PATTERNS)


def _parse_forms(html: str) -> list[dict]:
    parser = _FormParser()
    parser.feed(html)
    return parser.forms


async def _discover_login_page(
    client: HttpClient, base_url: str,
) -> tuple[str | None, dict | None]:
    """Try common login paths and return (page_url, login_form) or (None, None)."""
    base = base_url.rstrip("/")

    # First try the target URL itself
    urls_to_try = [base_url]
    for path in _LOGIN_PATHS:
        urls_to_try.append(base + path)

    for url in urls_to_try:
        try:
            scope_check(url)
        except Exception:
            continue
        try:
            resp = await client.get(url)
            if resp.status_code >= 400:
                continue
            forms = _parse_forms(resp.text)
            for form in forms:
                if _is_login_form(form):
                    return url, form
        except Exception:
            continue

    return None, None


async def auto_login(
    client: HttpClient,
    target_url: str,
    username: str,
    password: str,
    *,
    console=None,
) -> Session | None:
    """Auto-detect login form, submit credentials, return authenticated Session.

    Returns None if no login form found or login failed.
    """
    def _log(msg: str) -> None:
        if console:
            console.print(msg)

    _log("  [bold green]* Auto-login: searching for login form...[/bold green]")

    page_url, form = await _discover_login_page(client, target_url)
    if not form:
        _log("  [yellow]No login form detected on target or common paths.[/yellow]")
        return None

    _log(f"  [green]+[/green] Login form found at [white]{page_url}[/white]")

    user_field = _find_username_field(form["fields"])
    pass_field = _find_password_field(form["fields"])

    if not user_field or not pass_field:
        _log("  [yellow]Could not identify username/password fields in the form.[/yellow]")
        return None

    _log(f"  [dim]  Fields: username={user_field}, password={pass_field}[/dim]")

    # Build form data — include hidden fields (CSRF tokens, etc.)
    data: dict[str, str] = {}
    for f in form["fields"]:
        if f["type"] == "hidden" and f["value"]:
            data[f["name"]] = f["value"]
    data[user_field] = username
    data[pass_field] = password

    # Resolve form action URL
    action = form["action"]
    if not action:
        action = page_url
    elif not action.startswith("http"):
        action = urljoin(page_url, action)

    _log(f"  [bold green]* Submitting credentials to {action}[/bold green]")

    try:
        resp = await client.request(
            form["method"], action,
            data=data,
            headers={"Content-Type": "application/x-www-form-urlencoded"},
        )
    except Exception as exc:
        _log(f"  [red]Login request failed: {exc}[/red]")
        return None

    # Extract cookies from all responses in the redirect chain + final response
    cookies: dict[str, str] = {}
    for hist_resp in resp.history:
        for cookie in hist_resp.cookies.jar:
            cookies[cookie.name] = cookie.value
    for cookie in resp.cookies.jar:
        cookies[cookie.name] = cookie.value

    if not cookies:
        _log("  [yellow]No session cookies received — login may have failed.[/yellow]")
        # Still return a session with whatever headers came back, in case
        # the app uses something other than cookies
        return None

    # Check for obvious login failure signals
    body_lower = resp.text[:2000].lower()
    fail_signals = [
        "invalid password", "incorrect password", "login failed",
        "authentication failed", "invalid credentials", "wrong password",
        "bad credentials", "account not found", "invalid username",
    ]
    if any(sig in body_lower for sig in fail_signals):
        _log("  [red]Login appears to have failed (server returned an error message).[/red]")
        return None

    session = Session(cookies=cookies)
    cookie_names = ", ".join(cookies.keys())
    _log(
        f"  [bold green]* Login successful![/bold green] "
        f"Captured cookies: [white]{cookie_names}[/white]"
    )
    _log(f"  [dim]  All subsequent requests will use this authenticated session.[/dim]")

    return session
