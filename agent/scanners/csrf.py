"""CSRF scanner — detects missing or weak Cross-Site Request Forgery protections.

Verification chain (3-step GO/NO-GO):
  1. TOKEN_CHECK   → does the form/endpoint have a CSRF token field?
  2. OMIT_TOKEN    → submit WITHOUT the token — does the server still accept it?
  3. TAMPER_TOKEN  → submit with a GARBAGE token — does the server still accept it?

A finding is CONFIRMED only if:
  - The endpoint is state-changing (POST/PUT/PATCH/DELETE)
  - Step 1 finds no CSRF token, OR Step 2/3 prove the token is not enforced
  - The response indicates success (not a 4xx/5xx rejection)

False-positive controls:
  - Only tests state-changing methods (ignores GET/HEAD/OPTIONS)
  - Checks for CSRF tokens in forms, headers (X-CSRF-Token), and cookies
  - Verifies the server actually rejects tampered tokens before confirming
  - Checks SameSite cookie attribute — SameSite=Strict/Lax downgrades severity
"""
from __future__ import annotations

import re
from typing import Any

from ..http import HttpClient, Session
from ..recipes.schema import Recipe
from .base import Scanner, Candidate

# Known CSRF token field names
_CSRF_FIELD_NAMES = re.compile(
    r"^(?:csrf|_csrf|csrftoken|csrf_token|_token|"
    r"authenticity_token|__RequestVerificationToken|"
    r"csrfmiddlewaretoken|anti[-_]?forgery[-_]?token|"
    r"xsrf[-_]?token|__VIEWSTATE|__EVENTVALIDATION)$",
    re.IGNORECASE,
)

# CSRF token headers
_CSRF_HEADERS = [
    "x-csrf-token", "x-xsrf-token", "x-csrftoken",
    "csrf-token", "anti-csrf-token",
]

# SameSite cookie regex
_SAMESITE_RE = re.compile(r"SameSite=(Strict|Lax|None)", re.IGNORECASE)


class CsrfScanner(Scanner):
    """Detects missing or weak CSRF protections on state-changing endpoints."""

    vuln_classes = ["csrf", "cross-site-request-forgery"]

    def __init__(self, client: HttpClient, session: Session):
        super().__init__(client)
        self.session = session

    async def _detect(self, target: str, recipe: Recipe, **context: Any) -> list[Candidate]:
        params = context.get("params", [])
        method = context.get("method", "GET")
        id_location = context.get("id_location", "query")
        injection_points = context.get("injection_points", [])

        # CSRF only matters for state-changing methods
        if method.upper() in ("GET", "HEAD", "OPTIONS"):
            return []

        # Skip login/auth endpoints — no authenticated session to forge
        endpoint_lower = target.lower()
        _LOGIN_KEYWORDS = ("login", "signin", "sign-in", "sign_in", "authenticate",
                           "dologin", "do_login", "auth/login", "j_security_check")
        if any(kw in endpoint_lower for kw in _LOGIN_KEYWORDS):
            return []

        candidates = []

        # Build the form data we'll submit (sibling fields)
        form_data = {}
        csrf_field = None

        if injection_points:
            for point in injection_points:
                name = point["param"]
                siblings = point.get("sibling_fields", {})
                form_data.update(siblings)
                form_data[name] = "test_value"
                # Check if any field is a CSRF token
                if _CSRF_FIELD_NAMES.match(name):
                    csrf_field = name
            # Also check sibling fields for CSRF tokens
            for sib_name in list(form_data.keys()):
                if _CSRF_FIELD_NAMES.match(sib_name):
                    csrf_field = sib_name
        else:
            for param in params:
                form_data[param] = "test_value"
                if _CSRF_FIELD_NAMES.match(param):
                    csrf_field = param

        # ── Step 1: TOKEN_CHECK — is there a CSRF token? ──
        has_token_field = csrf_field is not None

        # Also check if the page itself delivers a CSRF token via meta tag or form
        token_value = None
        try:
            page_resp = await self.client.get(target, session=self.session)
            page_body = page_resp.text

            # Look for CSRF token in the page HTML
            if not has_token_field:
                meta_match = re.search(
                    r'<meta\s+name=["\']csrf[-_]token["\']\s+content=["\']([^"\']+)["\']',
                    page_body, re.IGNORECASE,
                )
                if meta_match:
                    has_token_field = True
                    token_value = meta_match.group(1)

                # Look for hidden input with CSRF name
                input_match = re.search(
                    r'<input[^>]+name=["\'](' + _CSRF_FIELD_NAMES.pattern[2:-2] +
                    r')["\'][^>]+value=["\']([^"\']*)["\']',
                    page_body, re.IGNORECASE,
                )
                if input_match:
                    has_token_field = True
                    csrf_field = input_match.group(1)
                    token_value = input_match.group(2)

            # Check for CSRF headers in response
            for header in _CSRF_HEADERS:
                if header.lower() in {h.lower() for h in page_resp.headers}:
                    has_token_field = True
                    break

            # Check SameSite cookie attribute
            samesite = "none"
            for cookie_header in [v for k, v in page_resp.headers.multi_items() if k.lower() == "set-cookie"]:
                match = _SAMESITE_RE.search(cookie_header)
                if match:
                    samesite = match.group(1).lower()

        except Exception:
            samesite = "unknown"

        if not has_token_field:
            # No CSRF token at all — but we need to verify the endpoint
            # actually does something (not just a safe GET disguised as POST)

            # ── Step 2: OMIT_TOKEN — submit without token ──
            try:
                resp = await self.client.request(
                    method, target, session=self.session,
                    data=form_data,
                    headers={"Content-Type": "application/x-www-form-urlencoded"},
                )

                if resp.status_code < 400:
                    # Server accepted without CSRF token — CONFIRMED
                    severity = "medium" if samesite in ("strict", "lax") else "high"
                    candidates.append(self._make_candidate(
                        recipe=recipe, endpoint=target, method=method,
                        evidence={
                            "technique": "no_csrf_token",
                            "has_token_field": False,
                            "samesite": samesite,
                            "server_accepted": True,
                            "status_code": resp.status_code,
                            "detail": (
                                "No CSRF token field found on this state-changing endpoint. "
                                "The server accepted the request without any anti-CSRF protection."
                            ),
                        },
                        confidence="high",
                        request_data={"form_data": form_data, "method": method},
                        response_data={"status": resp.status_code, "body_snippet": resp.text[:300]},
                    ))
            except Exception:
                pass

            return candidates

        # Token field exists — test if it's actually enforced

        # ── Step 2: OMIT_TOKEN — submit WITHOUT the CSRF token ──
        omit_data = {k: v for k, v in form_data.items() if k != csrf_field}
        omit_accepted = False
        try:
            resp_omit = await self.client.request(
                method, target, session=self.session,
                data=omit_data,
                headers={"Content-Type": "application/x-www-form-urlencoded"},
            )
            omit_accepted = resp_omit.status_code < 400
        except Exception:
            pass

        # ── Step 3: TAMPER_TOKEN — submit with garbage token ──
        tamper_data = dict(form_data)
        if csrf_field:
            tamper_data[csrf_field] = "INVALID_CSRF_TOKEN_12345"
        tamper_accepted = False
        try:
            resp_tamper = await self.client.request(
                method, target, session=self.session,
                data=tamper_data,
                headers={"Content-Type": "application/x-www-form-urlencoded"},
            )
            tamper_accepted = resp_tamper.status_code < 400
        except Exception:
            pass

        # ── Verdict ──
        if omit_accepted and tamper_accepted:
            # Token exists but is completely ignored
            candidates.append(self._make_candidate(
                recipe=recipe, endpoint=target, method=method,
                evidence={
                    "technique": "csrf_token_not_enforced",
                    "has_token_field": True,
                    "csrf_field": csrf_field,
                    "omit_accepted": True,
                    "tamper_accepted": True,
                    "samesite": samesite,
                    "detail": (
                        f"CSRF token field '{csrf_field}' exists but is not enforced. "
                        "Server accepted requests with the token omitted AND with a "
                        "garbage token value."
                    ),
                },
                confidence="high",
                request_data={"form_data": form_data, "csrf_field": csrf_field, "method": method},
                response_data={
                    "omit_status": resp_omit.status_code if omit_accepted else None,
                    "tamper_status": resp_tamper.status_code if tamper_accepted else None,
                },
            ))
        elif omit_accepted:
            # Token can be omitted entirely
            candidates.append(self._make_candidate(
                recipe=recipe, endpoint=target, method=method,
                evidence={
                    "technique": "csrf_token_optional",
                    "has_token_field": True,
                    "csrf_field": csrf_field,
                    "omit_accepted": True,
                    "tamper_accepted": False,
                    "samesite": samesite,
                    "detail": (
                        f"CSRF token field '{csrf_field}' exists but is optional. "
                        "Server accepted requests with the token completely omitted."
                    ),
                },
                confidence="high",
                request_data={"form_data": form_data, "csrf_field": csrf_field, "method": method},
                response_data={"omit_status": resp_omit.status_code},
            ))
        elif tamper_accepted:
            # Token is required but not validated
            candidates.append(self._make_candidate(
                recipe=recipe, endpoint=target, method=method,
                evidence={
                    "technique": "csrf_token_not_validated",
                    "has_token_field": True,
                    "csrf_field": csrf_field,
                    "omit_accepted": False,
                    "tamper_accepted": True,
                    "samesite": samesite,
                    "detail": (
                        f"CSRF token field '{csrf_field}' is required but not validated. "
                        "Server rejected requests without the token but accepted a "
                        "garbage token value."
                    ),
                },
                confidence="high",
                request_data={"form_data": form_data, "csrf_field": csrf_field, "method": method},
                response_data={"tamper_status": resp_tamper.status_code},
            ))
        # else: token is properly enforced — no finding

        return candidates
