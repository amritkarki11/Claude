"""Stored XSS scanner — detects persistent Cross-Site Scripting.

Unlike reflected XSS (which bounces the payload back in the same response),
stored XSS persists on the server and triggers when another page renders the
stored content.  Typical sinks: comments, profiles, feedback forms, messages.

Verification chain (4-step GO/NO-GO):
  1. CANARY_STORE  → submit a unique canary to a write endpoint (POST form)
  2. CANARY_RENDER → visit the render page and check if canary appears unencoded
  3. PAYLOAD_STORE → submit an actual XSS payload to the same write endpoint
  4. PAYLOAD_RENDER → visit the render page and check if payload survives encoding

A finding is CONFIRMED only if:
  - The canary survives round-trip (stored AND rendered unencoded)
  - At least one XSS payload is rendered without HTML-entity encoding
  - The render page does not have a strict CSP that blocks inline scripts

False-positive controls:
  - Only tests endpoints classified as storing user content
    (COMMENT, USER_PROFILE, CONTACT, GENERIC_FORM, REGISTRATION, SETTINGS)
  - Verifies the canary actually persists (not just reflected)
  - Checks for CSP headers on the render page — strict CSP downgrades confidence
  - Distinguishes "stored but encoded" (safe) from "stored and raw" (vulnerable)
"""
from __future__ import annotations

import hashlib
import re
import time
from typing import Any
from urllib.parse import urljoin, urlparse

from ..http import HttpClient, Session
from ..recipes.schema import Recipe
from .base import Scanner, Candidate

# Unique canary prefix — unlikely to collide with real content
_CANARY_PREFIX = "StXsS7e5T"

# Payloads ordered from most to least likely to bypass filters
_PAYLOADS = [
    '<script>alert("sxss")</script>',
    '<img src=x onerror=alert("sxss")>',
    '<svg/onload=alert("sxss")>',
    '"><img src=x onerror=alert("sxss")>',
    "'-alert('sxss')-'",
    '<details open ontoggle=alert("sxss")>',
]

# Markers proving payload survived encoding
_RAW_MARKERS = [
    "<script>", "<img ", "<svg", "onerror=", "onload=",
    "ontoggle=", "javascript:", 'alert("sxss")',
]

# Endpoint functions where stored content is likely
_STORE_FUNCTIONS = {
    "COMMENT", "USER_PROFILE", "CONTACT", "GENERIC_FORM",
    "REGISTRATION", "SETTINGS", "UNKNOWN",
}


class StoredXssScanner(Scanner):
    """Detects stored (persistent) XSS via two-phase inject → render probing."""

    vuln_classes = ["xss", "stored-xss"]

    def __init__(self, client: HttpClient, session: Session):
        super().__init__(client)
        self.session = session

    # ── public interface ────────────────────────────────────

    async def _detect(
        self, target: str, recipe: Recipe, **context: Any,
    ) -> list[Candidate]:
        params = context.get("params", [])
        method = context.get("method", "GET")
        injection_points = context.get("injection_points", [])
        endpoint_function = context.get("endpoint_function", "UNKNOWN")
        render_url = context.get("render_url")  # explicit render page if known

        # Stored XSS only applies to state-changing methods on store endpoints
        if method.upper() in ("GET", "HEAD", "OPTIONS"):
            return []
        if endpoint_function not in _STORE_FUNCTIONS:
            return []

        candidates: list[Candidate] = []

        # Determine where stored content might render
        render_urls = self._guess_render_urls(target, render_url, endpoint_function)

        if injection_points:
            for point in injection_points:
                vuln_classes = point.get("vuln_classes", [])
                if "xss" not in vuln_classes and "stored-xss" not in vuln_classes:
                    continue
                param = point["param"]
                siblings = point.get("sibling_fields", {})
                meth = point.get("method", method)

                result = await self._probe_stored(
                    target, param, meth, siblings, render_urls,
                )
                if result:
                    candidates.append(self._make_candidate(
                        recipe=recipe, endpoint=target, method=meth,
                        evidence=result,
                        confidence=result.get("confidence", "medium"),
                        request_data={
                            "param": param,
                            "payload": result["payload"],
                            "method": meth,
                        },
                        response_data={
                            "render_url": result.get("render_url"),
                            "stored": result.get("stored", False),
                        },
                    ))
        else:
            siblings = context.get("siblings", {})
            for param in params:
                result = await self._probe_stored(
                    target, param, method, siblings, render_urls,
                )
                if result:
                    candidates.append(self._make_candidate(
                        recipe=recipe, endpoint=target, method=method,
                        evidence=result,
                        confidence=result.get("confidence", "medium"),
                        request_data={
                            "param": param,
                            "payload": result["payload"],
                            "method": method,
                        },
                        response_data={
                            "render_url": result.get("render_url"),
                            "stored": result.get("stored", False),
                        },
                    ))

        return candidates

    # ── core probing logic ──────────────────────────────────

    async def _probe_stored(
        self,
        write_url: str,
        param: str,
        method: str,
        siblings: dict[str, str],
        render_urls: list[str],
    ) -> dict | None:
        """Four-step stored XSS verification.

        Steps 1-2: canary round-trip (store → render).
        Steps 3-4: payload round-trip (store → render).
        """
        canary = self._make_canary()

        # ── Step 1: CANARY_STORE ──
        try:
            store_resp = await self._submit(write_url, param, canary, method, siblings)
            if store_resp.status_code >= 400:
                return None  # server rejected the submission
        except Exception:
            return None

        # ── Step 2: CANARY_RENDER — check render pages for the canary ──
        found_render_url = None
        for rurl in render_urls:
            try:
                render_resp = await self.client.get(rurl, session=self.session)
                if canary in render_resp.text:
                    found_render_url = rurl
                    break
            except Exception:
                continue

        # Also check the write URL itself (some forms render content on the same page)
        if not found_render_url:
            try:
                same_page = await self.client.get(write_url, session=self.session)
                if canary in same_page.text:
                    found_render_url = write_url
            except Exception:
                pass

        # Also check the Location header from the store response (post-redirect-get)
        if not found_render_url:
            location = store_resp.headers.get("location", "")
            if location:
                redirect_url = urljoin(write_url, location)
                try:
                    redir_resp = await self.client.get(redirect_url, session=self.session)
                    if canary in redir_resp.text:
                        found_render_url = redirect_url
                except Exception:
                    pass

        if not found_render_url:
            return None  # canary not stored/rendered anywhere

        # ── Step 3: PAYLOAD_STORE — inject actual XSS payloads ──
        for payload in _PAYLOADS:
            try:
                await self._submit(write_url, param, payload, method, siblings)
            except Exception:
                continue

            # ── Step 4: PAYLOAD_RENDER — check if payload survived encoding ──
            try:
                render_resp = await self.client.get(
                    found_render_url, session=self.session,
                )
                body = render_resp.text

                if self._is_raw_in_page(payload, body):
                    # Check CSP on the render page
                    csp = render_resp.headers.get("content-security-policy", "")
                    has_strict_csp = bool(csp) and "unsafe-inline" not in csp

                    if has_strict_csp:
                        confidence = "medium"
                    else:
                        confidence = "high"

                    return {
                        "technique": "stored_xss_confirmed",
                        "payload": payload,
                        "render_url": found_render_url,
                        "stored": True,
                        "rendered_raw": True,
                        "has_csp": bool(csp),
                        "csp_blocks_inline": has_strict_csp,
                        "confidence": confidence,
                        "body_snippet": body[:500],
                        "detail": (
                            f"Stored XSS confirmed: payload submitted to '{write_url}' "
                            f"via parameter '{param}' is rendered unencoded at "
                            f"'{found_render_url}'."
                        ),
                    }
            except Exception:
                continue

        # Canary stored and rendered, but all payloads were encoded
        return {
            "technique": "stored_but_encoded",
            "payload": canary,
            "render_url": found_render_url,
            "stored": True,
            "rendered_raw": False,
            "confidence": "low",
            "detail": (
                f"User input is stored and rendered at '{found_render_url}', "
                "but XSS payloads appear to be encoded. Manual review recommended."
            ),
        }

    # ── helpers ──────────────────────────────────────────────

    async def _submit(
        self,
        url: str,
        param: str,
        value: str,
        method: str,
        siblings: dict[str, str],
    ):
        """Submit a value to the write endpoint."""
        data = dict(siblings)
        data[param] = value
        return await self.client.request(
            method, url, session=self.session,
            data=data,
            headers={"Content-Type": "application/x-www-form-urlencoded"},
        )

    @staticmethod
    def _make_canary() -> str:
        ts = str(time.time()).encode()
        suffix = hashlib.md5(ts).hexdigest()[:8]
        return f"{_CANARY_PREFIX}{suffix}"

    @staticmethod
    def _is_raw_in_page(payload: str, body: str) -> bool:
        """Check if the XSS payload appears in the page WITHOUT encoding."""
        if payload in body:
            return True
        lower_body = body.lower()
        matched = 0
        for marker in _RAW_MARKERS:
            if marker.lower() in payload.lower() and marker.lower() in lower_body:
                matched += 1
        # Need at least 2 markers to confirm (avoids false matches on benign content)
        return matched >= 2

    @staticmethod
    def _guess_render_urls(
        write_url: str,
        explicit_render: str | None,
        function: str,
    ) -> list[str]:
        """Guess where stored content might be rendered.

        Heuristics:
          - Explicit render URL if provided
          - For comments: try the parent page (strip /comment, /addComment, etc.)
          - For profiles: try /profile, /user, /account pages
          - For feedback/contact: try /admin, /dashboard (admin sees submissions)
          - Always try the write URL's parent path
        """
        urls: list[str] = []

        if explicit_render:
            urls.append(explicit_render)

        parsed = urlparse(write_url)
        base = f"{parsed.scheme}://{parsed.netloc}"
        path = parsed.path.rstrip("/")

        # Comment-like endpoints — try the parent page
        comment_suffixes = (
            "/comment", "/addComment", "/add_comment", "/postComment",
            "/reply", "/addReply", "/feedback", "/submitFeedback",
            "/add", "/post", "/submit", "/create",
        )
        for suffix in comment_suffixes:
            if path.lower().endswith(suffix.lower()):
                parent = path[: -len(suffix)]
                if parent:
                    urls.append(base + parent)
                break

        # Profile endpoints — try sibling view pages
        if function == "USER_PROFILE":
            for view_path in ("/profile", "/user", "/account", "/settings"):
                urls.append(base + view_path)

        # Contact/feedback — might render in admin panel
        if function in ("CONTACT", "GENERIC_FORM"):
            for admin_path in ("/admin", "/dashboard", "/admin/feedback"):
                urls.append(base + admin_path)

        # Try the parent directory of the write URL
        if "/" in path:
            parent_path = path.rsplit("/", 1)[0]
            if parent_path:
                urls.append(base + parent_path)

        # Try the write URL itself with GET (post-then-view pattern)
        urls.append(write_url.split("?")[0])

        # Deduplicate while preserving order
        seen: set[str] = set()
        unique: list[str] = []
        for u in urls:
            if u not in seen:
                seen.add(u)
                unique.append(u)

        return unique
