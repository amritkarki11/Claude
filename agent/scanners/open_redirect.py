"""Open Redirect scanner — detects unvalidated URL redirects.

An open redirect lets an attacker craft a link on the trusted domain that
silently sends the victim to a malicious site.  Common in login flows,
logout, OAuth callbacks, and any endpoint with url/next/redirect params.

Verification chain (3-step GO/NO-GO):
  1. BASELINE    → submit the param with an internal URL, confirm redirect works
  2. EXTERNAL    → submit with an external domain, check if redirect follows
  3. BYPASS      → try filter-bypass variants if step 2 is blocked

A finding is CONFIRMED only if:
  - The server issues a 3xx redirect to an attacker-controlled domain, OR
  - The response body contains a meta-refresh / JS redirect to an external domain
  - The target domain is genuinely external (not a subdomain of the app)

False-positive controls:
  - Only tests parameters whose name suggests a redirect target
  - Verifies the redirect actually lands on the external domain (not just echoed)
  - Checks for meta-refresh and JS-based redirects in the body, not just 3xx
  - Tests multiple bypass techniques to avoid missing WAF-circumvented cases
"""
from __future__ import annotations

import re
from typing import Any
from urllib.parse import urljoin, urlparse

from ..http import HttpClient, Session
from ..recipes.schema import Recipe
from .base import Scanner, Candidate

# Parameter names that commonly hold redirect targets
_REDIRECT_PARAMS = re.compile(
    r"^(?:url|uri|next|redirect|redirect_uri|redirect_url|"
    r"return|return_url|return_to|returnUrl|returnTo|"
    r"continue|dest|destination|target|rurl|redir|"
    r"forward|goto|go|out|view|link|to|ref|callback|"
    r"callback_url|success_url|error_url|login_url|"
    r"logout_url|checkout_url|RelayState)$",
    re.IGNORECASE,
)

# External test domains — IANA-reserved, guaranteed not to host anything real
_EXTERNAL_TARGETS = [
    "https://evil.com",
    "https://attacker.example.com",
]

# Bypass payloads — ordered by likelihood of working
_BYPASS_PAYLOADS = [
    "//evil.com",                    # protocol-relative
    "https://evil.com",              # plain external
    "/\\evil.com",                   # backslash confusion
    "https://evil.com%00.trusted.com",  # null byte
    "https://evil.com?.trusted.com",    # query confusion
    "https://evil.com#.trusted.com",    # fragment confusion
    "https://evil.com@trusted.com",     # credential section
    "//evil.com/%2f..",              # path traversal in authority
    "https:evil.com",               # missing slashes
    "\thttps://evil.com",           # tab prefix
    "https://evil。com",             # fullwidth dot (homograph)
]

# Regex to detect redirect in response body (meta-refresh or JS)
_BODY_REDIRECT_RE = re.compile(
    r'(?:'
    r'<meta[^>]+http-equiv=["\']?refresh["\']?[^>]+url=([^\s"\'>]+)'
    r'|'
    r'(?:window\.)?location(?:\.href)?\s*=\s*["\']([^"\']+)["\']'
    r'|'
    r'(?:window\.)?location\.replace\s*\(\s*["\']([^"\']+)["\']\s*\)'
    r')',
    re.IGNORECASE,
)


class OpenRedirectScanner(Scanner):
    """Detects open redirect vulnerabilities in URL-redirect parameters."""

    vuln_classes = ["open-redirect"]

    def __init__(self, client: HttpClient, session: Session):
        super().__init__(client)
        self.session = session

    async def _detect(
        self, target: str, recipe: Recipe, **context: Any,
    ) -> list[Candidate]:
        params = context.get("params", [])
        method = context.get("method", "GET")
        id_location = context.get("id_location", "query")
        injection_points = context.get("injection_points", [])

        candidates: list[Candidate] = []

        if injection_points:
            for point in injection_points:
                vuln_classes = point.get("vuln_classes", [])
                if "open-redirect" not in vuln_classes:
                    continue
                param = point["param"]
                loc = point.get("location", id_location)
                meth = point.get("method", method)
                siblings = point.get("sibling_fields", {})
                result = await self._probe(target, param, meth, loc, siblings)
                if result:
                    candidates.append(self._make_candidate(
                        recipe=recipe, endpoint=target, method=meth,
                        evidence=result,
                        confidence=result.get("confidence", "medium"),
                        request_data={
                            "param": param,
                            "payload": result["payload"],
                            "id_location": loc,
                        },
                        response_data={
                            "status": result.get("status"),
                            "redirect_to": result.get("redirect_to"),
                        },
                    ))
        else:
            # Only test params whose names suggest redirect targets
            for param in params:
                if not _REDIRECT_PARAMS.match(param):
                    continue
                result = await self._probe(target, param, method, id_location, {})
                if result:
                    candidates.append(self._make_candidate(
                        recipe=recipe, endpoint=target, method=method,
                        evidence=result,
                        confidence=result.get("confidence", "medium"),
                        request_data={
                            "param": param,
                            "payload": result["payload"],
                            "id_location": id_location,
                        },
                        response_data={
                            "status": result.get("status"),
                            "redirect_to": result.get("redirect_to"),
                        },
                    ))

        return candidates

    # ── probing logic ───────────────────────────────────────

    async def _probe(
        self,
        target: str,
        param: str,
        method: str,
        id_location: str,
        siblings: dict[str, str],
    ) -> dict | None:
        """Three-step open redirect verification."""
        app_domain = urlparse(target).netloc.lower()

        # ── Step 1: BASELINE — confirm the param actually triggers a redirect ──
        internal_url = urljoin(target, "/")
        try:
            resp = await self._send(
                target, param, internal_url, method, id_location, siblings,
                follow_redirects=False,
            )
            # If the param doesn't influence a redirect at all, skip it
            if not self._is_redirect(resp) and not self._body_redirects_to(resp.text):
                return None
        except Exception:
            return None

        # ── Step 2: EXTERNAL — try a plain external domain ──
        for ext_target in _EXTERNAL_TARGETS:
            result = await self._try_redirect(
                target, param, ext_target, method, id_location,
                siblings, app_domain,
            )
            if result:
                result["technique"] = "direct_external"
                return result

        # ── Step 3: BYPASS — try filter-bypass variants ──
        for bypass in _BYPASS_PAYLOADS:
            result = await self._try_redirect(
                target, param, bypass, method, id_location,
                siblings, app_domain,
            )
            if result:
                result["technique"] = "filter_bypass"
                return result

        return None

    async def _try_redirect(
        self,
        target: str,
        param: str,
        payload: str,
        method: str,
        id_location: str,
        siblings: dict[str, str],
        app_domain: str,
    ) -> dict | None:
        """Submit a redirect payload and check if it lands externally."""
        try:
            resp = await self._send(
                target, param, payload, method, id_location, siblings,
                follow_redirects=False,
            )
        except Exception:
            return None

        # Check 3xx Location header
        if self._is_redirect(resp):
            location = resp.headers.get("location", "")
            if self._is_external(location, app_domain):
                return {
                    "payload": payload,
                    "redirect_to": location,
                    "redirect_type": "header",
                    "status": resp.status_code,
                    "confidence": "high",
                    "detail": (
                        f"Open redirect confirmed: parameter '{param}' redirects "
                        f"to external domain via {resp.status_code} Location header."
                    ),
                }

        # Check body-based redirects (meta-refresh, JS location)
        body_target = self._body_redirects_to(resp.text)
        if body_target and self._is_external(body_target, app_domain):
            return {
                "payload": payload,
                "redirect_to": body_target,
                "redirect_type": "body",
                "status": resp.status_code,
                "confidence": "medium",
                "detail": (
                    f"Open redirect via JavaScript/meta-refresh: parameter '{param}' "
                    f"causes client-side redirect to external domain."
                ),
            }

        return None

    # ── HTTP helpers ────────────────────────────────────────

    async def _send(
        self,
        target: str,
        param: str,
        value: str,
        method: str,
        id_location: str,
        siblings: dict[str, str],
        *,
        follow_redirects: bool = False,
    ):
        """Send the request with the redirect payload."""
        if id_location == "query":
            params = dict(siblings)
            params[param] = value
            return await self.client.request(
                method, target, session=self.session,
                params=params,
                follow_redirects=follow_redirects,
            )
        elif id_location == "body":
            data = dict(siblings)
            data[param] = value
            return await self.client.request(
                method, target, session=self.session,
                data=data,
                headers={"Content-Type": "application/x-www-form-urlencoded"},
                follow_redirects=follow_redirects,
            )
        else:
            # Fallback: try query param
            params = dict(siblings)
            params[param] = value
            return await self.client.request(
                method, target, session=self.session,
                params=params,
                follow_redirects=follow_redirects,
            )

    # ── analysis helpers ────────────────────────────────────

    @staticmethod
    def _is_redirect(resp) -> bool:
        """Check if the response is a 3xx redirect."""
        return 300 <= resp.status_code < 400 and "location" in {
            h.lower() for h in resp.headers
        }

    @staticmethod
    def _body_redirects_to(body: str) -> str | None:
        """Extract redirect target from meta-refresh or JS redirect in body."""
        match = _BODY_REDIRECT_RE.search(body)
        if match:
            # Return the first non-None group
            return next((g for g in match.groups() if g), None)
        return None

    @staticmethod
    def _is_external(url: str, app_domain: str) -> bool:
        """Check if the URL points to a domain other than the application."""
        if not url:
            return False
        try:
            parsed = urlparse(url if "://" in url else f"https:{url}")
            target_domain = parsed.netloc.lower()
            if not target_domain:
                return False
            # Strip port for comparison
            app_host = app_domain.split(":")[0]
            target_host = target_domain.split(":")[0]
            # External if the target is not the app domain or a subdomain of it
            if target_host == app_host:
                return False
            if target_host.endswith(f".{app_host}"):
                return False
            return True
        except Exception:
            return False
