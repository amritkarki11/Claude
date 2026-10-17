"""XSS scanner — detects reflected Cross-Site Scripting.

Strategy:
  1. Inject a unique canary string, check if it appears unencoded in response
  2. Inject HTML/JS payloads, check if they survive encoding
  3. Verify payload lands in executable HTML context (not inside error text,
     HTML comments, or encoded attribute values)
  4. Replay the winning payload to confirm consistency
  5. Check response headers for missing Content-Security-Policy

Does NOT test stored XSS (requires two-phase interaction) — that's a
future scanner.
"""
from __future__ import annotations

import hashlib
import html
import re
import time
from typing import Any
from urllib.parse import urlencode, urlparse, parse_qs, urlunparse, urljoin

from ..http import HttpClient, Session
from ..recipes.schema import Recipe
from .base import Scanner, Candidate

# Canary: unique string unlikely to appear naturally
_CANARY_PREFIX = "xSSc4n4ry"

# Payloads ordered by likelihood of bypass
_PAYLOADS = [
    "<script>alert(1)</script>",
    "<img src=x onerror=alert(1)>",
    '"><script>alert(1)</script>',
    "<svg/onload=alert(1)>",
]

# Words around the reflection that indicate the app caught/blocked it
_FAILURE_INDICATORS = re.compile(
    r"(?:failed|error|invalid|blocked|denied|rejected|not\s+found|"
    r"exception|illegal|bad\s+request|forbidden|violation)",
    re.IGNORECASE,
)

# Patterns that mean the payload was HTML-encoded (not executable)
_ENCODED_PAYLOADS = [
    "&lt;script&gt;", "&lt;img ", "&lt;svg", "&#60;script", "&#x3c;script",
]


class XssScanner(Scanner):
    """Detects reflected XSS by injecting canary strings and payloads."""

    vuln_classes = ["xss", "reflected-xss"]

    def __init__(self, client: HttpClient, session: Session):
        super().__init__(client)
        self.session = session

    async def _detect(self, target: str, recipe: Recipe,
                      **context: Any) -> list[Candidate]:
        params = context.get("params", [])
        method = context.get("method", "GET")
        id_location = context.get("id_location", "query")
        injection_points = context.get("injection_points", [])

        if not params and not injection_points:
            return []

        candidates = []

        if injection_points:
            for point in injection_points:
                if "xss" not in point.get("vuln_classes", []) and \
                   "reflected-xss" not in point.get("vuln_classes", []):
                    continue
                param = point["param"]
                loc = point.get("location", id_location)
                meth = point.get("method", method)
                siblings = point.get("sibling_fields", {})
                result = await self._probe(target, param, meth, loc, siblings=siblings)
                if result and result.get("confirmed"):
                    candidates.append(
                        self._make_candidate(
                            recipe=recipe, endpoint=target, method=meth,
                            evidence=result,
                            confidence=result.get("confidence", "medium"),
                            request_data={
                                "param": param,
                                "payload": result["payload"],
                                "id_location": loc,
                                "siblings": siblings,
                                "full_request": result.get("full_request", ""),
                            },
                            response_data={
                                "status": result.get("status"),
                                "reflected": True,
                                "full_response": result.get("full_response", ""),
                            },
                        )
                    )
        else:
            for param in params:
                result = await self._probe(target, param, method, id_location)
                if result and result.get("confirmed"):
                    candidates.append(
                        self._make_candidate(
                            recipe=recipe, endpoint=target, method=method,
                            evidence=result,
                            confidence=result.get("confidence", "medium"),
                            request_data={
                                "param": param,
                                "payload": result["payload"],
                                "id_location": id_location,
                                "full_request": result.get("full_request", ""),
                            },
                            response_data={
                                "status": result.get("status"),
                                "reflected": True,
                                "full_response": result.get("full_response", ""),
                            },
                        )
                    )

        return candidates

    async def _probe(self, target: str, param: str,
                     method: str, id_location: str,
                     *, siblings: dict[str, str] | None = None) -> dict | None:
        # Step 1: canary reflection check — is the param reflected at all?
        canary = self._make_canary()
        try:
            resp = await self._send(target, param, canary, method, id_location, siblings=siblings)
            body = resp.text
            if canary not in body:
                return None  # param not reflected at all
        except Exception:
            return None

        # Step 2: try actual payloads — find one that reflects unencoded
        for payload in _PAYLOADS:
            try:
                resp = await self._send(target, param, payload, method, id_location, siblings=siblings)
                body = resp.text

                if not self._is_reflected_unencoded(payload, body):
                    continue

                # Step 3: check the reflection is in executable context
                if self._is_in_error_context(payload, body):
                    continue

                # Step 4: replay to confirm consistency
                resp2 = await self._send(target, param, payload, method, id_location, siblings=siblings)
                body2 = resp2.text
                if not self._is_reflected_unencoded(payload, body2):
                    continue

                # Step 5: CSP check — parse script-src directive
                csp = resp.headers.get("content-security-policy", "")
                csp_blocks = self._csp_blocks_inline(csp)
                if csp_blocks:
                    confidence = "low"  # CSP blocks inline scripts
                elif csp:
                    confidence = "medium"  # CSP exists but doesn't block inline
                else:
                    confidence = "high"  # No CSP at all

                # Build exact request/response strings
                full_req = self._build_request_string(target, param, payload, method, id_location, siblings)
                full_resp = self._build_response_string(resp, body)

                return {
                    "status": resp.status_code,
                    "payload": payload,
                    "reflected": True,
                    "confirmed": not csp_blocks,  # Only confirmed if CSP doesn't block
                    "body_snippet": body[:2000],
                    "has_csp": bool(csp),
                    "csp_blocks_inline": csp_blocks,
                    "confidence": confidence,
                    "full_request": full_req,
                    "full_response": full_resp,
                    "replay_status": resp2.status_code,
                }
            except Exception:
                continue

        # Canary reflected but no payload survived — not vulnerable
        return None

    async def _send(self, target: str, param: str, value: str,
                    method: str, id_location: str,
                    *, siblings: dict[str, str] | None = None):
        if id_location == "query":
            params = dict(siblings) if siblings else {}
            params[param] = value
            return await self.client.request(
                method, target, session=self.session,
                params=params,
            )
        elif id_location == "body":
            data = dict(siblings) if siblings else {}
            data[param] = value
            return await self.client.post(
                target, session=self.session,
                data=data,
                headers={"Content-Type": "application/x-www-form-urlencoded"},
            )
        else:
            raise ValueError(f"XSS scanner doesn't support id_location: {id_location}")

    @staticmethod
    def _make_canary() -> str:
        ts = str(time.time()).encode()
        suffix = hashlib.md5(ts).hexdigest()[:8]
        return f"{_CANARY_PREFIX}{suffix}"

    @staticmethod
    def _csp_blocks_inline(csp: str) -> bool:
        """Check if Content-Security-Policy blocks inline script execution.

        Parses the script-src (or default-src fallback) directive and checks
        whether 'unsafe-inline' is absent. If script-src restricts to specific
        sources without 'unsafe-inline', inline XSS payloads won't execute
        even if reflected unencoded.

        Returns True if CSP effectively blocks inline scripts.
        """
        if not csp:
            return False

        csp_lower = csp.lower()
        directives = {}
        for part in csp_lower.split(";"):
            part = part.strip()
            if not part:
                continue
            tokens = part.split()
            if tokens:
                directives[tokens[0]] = tokens[1:]

        # script-src takes precedence over default-src for script execution
        sources = directives.get("script-src", directives.get("default-src", []))

        if not sources:
            return False  # No script restriction at all

        # If 'unsafe-inline' is present, inline scripts are allowed
        if "'unsafe-inline'" in sources:
            return False

        # If 'none' is the only source, everything is blocked
        if "'none'" in sources:
            return True

        # If there are sources but no 'unsafe-inline', inline scripts are blocked
        # (nonce-based or hash-based CSP blocks injected inline scripts)
        return True

    @staticmethod
    def _is_reflected_unencoded(payload: str, body: str) -> bool:
        """Check if the payload appears in the response without HTML encoding.

        Returns False if only the encoded version appears (e.g. &lt;script&gt;).
        """
        # First check: is the exact payload string in the body?
        if payload not in body:
            return False

        # Second check: make sure the encoded version isn't the ONLY one
        # (some apps reflect both encoded and unencoded in different contexts)
        # The raw payload IS in the body, so check it's not inside an HTML
        # comment or a <textarea>/<code>/<pre> which won't execute
        idx = body.find(payload)
        if idx < 0:
            return False

        # Check if it's inside an HTML comment
        before = body[:idx]
        if "<!--" in before:
            comment_start = before.rfind("<!--")
            comment_end = body.find("-->", comment_start)
            if comment_end > idx:
                return False  # payload is inside a comment

        # Check if it's inside a non-executable element
        _SAFE_CONTAINERS = ["<textarea", "<xmp", "<noscript"]
        lower_before = before.lower()
        for tag in _SAFE_CONTAINERS:
            if tag in lower_before:
                close_tag = "</" + tag[1:]
                last_open = lower_before.rfind(tag)
                last_close = lower_before.rfind(close_tag)
                if last_open > last_close:
                    return False  # inside a safe container

        return True

    @staticmethod
    def _is_in_error_context(payload: str, body: str) -> bool:
        """Check if the payload reflection is surrounded by error/failure text.

        If the app says 'Failed due to <img src=x onerror=alert(1)>' that's
        the app displaying an error message, not executing the payload.
        The payload is reflected as text content, not as executable HTML.
        """
        idx = body.find(payload)
        if idx < 0:
            return False

        # Look at the ~200 chars around the reflection
        context_start = max(0, idx - 200)
        context_end = min(len(body), idx + len(payload) + 200)
        context = body[context_start:context_end]

        # Check for failure/error indicators near the reflection
        matches = list(_FAILURE_INDICATORS.finditer(context))
        if len(matches) >= 2:
            # Multiple error indicators around the payload — likely an
            # error page that's reflecting input but not executing it
            return True

        # If the body is mostly an error page (short body with error text)
        if len(body) < 2000:
            full_matches = list(_FAILURE_INDICATORS.finditer(body))
            if len(full_matches) >= 3:
                return True

        return False

    @staticmethod
    def _build_request_string(target: str, param: str, payload: str,
                              method: str, id_location: str,
                              siblings: dict[str, str] | None) -> str:
        """Build an exact HTTP request string for the report."""
        parsed = urlparse(target)
        if id_location == "query":
            params = dict(siblings) if siblings else {}
            params[param] = payload
            qs = urlencode(params)
            path = parsed.path or "/"
            request_line = f"{method} {path}?{qs} HTTP/1.1"
            lines = [request_line, f"Host: {parsed.hostname}"]
            return "\n".join(lines)
        else:
            path = parsed.path or "/"
            data = dict(siblings) if siblings else {}
            data[param] = payload
            body = urlencode(data)
            lines = [
                f"{method} {path} HTTP/1.1",
                f"Host: {parsed.hostname}",
                "Content-Type: application/x-www-form-urlencoded",
                f"Content-Length: {len(body)}",
                "",
                body,
            ]
            return "\n".join(lines)

    @staticmethod
    def _build_response_string(resp, body: str) -> str:
        """Build an exact HTTP response string for the report."""
        status_line = f"HTTP/1.1 {resp.status_code}"
        headers_lines = []
        for name, value in resp.headers.items():
            if name.lower() in ("content-type", "content-length",
                                "content-security-policy", "x-xss-protection",
                                "set-cookie", "server"):
                headers_lines.append(f"{name}: {value}")
        # Truncate body to 2000 chars for report readability
        body_truncated = body[:2000]
        if len(body) > 2000:
            body_truncated += "\n[... truncated ...]"
        parts = [status_line] + headers_lines + ["", body_truncated]
        return "\n".join(parts)
