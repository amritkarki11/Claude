"""XSS scanner — detects reflected Cross-Site Scripting.

Strategy:
  1. Inject a unique canary string, check if it appears unencoded in response
  2. Inject HTML/JS payloads, check if they survive encoding
  3. Check response headers for missing Content-Security-Policy

Does NOT test stored XSS (requires two-phase interaction) — that's a
future scanner.
"""
from __future__ import annotations

import hashlib
import time
from typing import Any

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
    "'-alert(1)-'",
    "<svg/onload=alert(1)>",
    "javascript:alert(1)",
]

# Signs the payload was reflected without encoding
_REFLECTION_MARKERS = [
    "<script>", "<img ", "<svg", "onerror=", "onload=",
    "javascript:", "alert(1)",
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

        if not params:
            return []

        candidates = []

        for param in params:
            result = await self._probe(target, param, method, id_location)
            if result:
                candidates.append(
                    self._make_candidate(
                        recipe=recipe,
                        endpoint=target,
                        method=method,
                        evidence=result,
                        confidence=result.get("confidence", "medium"),
                        request_data={
                            "param": param,
                            "payload": result["payload"],
                            "id_location": id_location,
                        },
                        response_data={
                            "status": result.get("status"),
                            "reflected": result.get("reflected", False),
                        },
                    )
                )

        return candidates

    async def _probe(self, target: str, param: str,
                     method: str, id_location: str) -> dict | None:
        # Step 1: canary reflection check
        canary = self._make_canary()
        try:
            resp = await self._send(target, param, canary, method, id_location)
            body = resp.text
            if canary not in body:
                return None  # param not reflected at all
        except Exception:
            return None

        # Step 2: try actual payloads
        for payload in _PAYLOADS:
            try:
                resp = await self._send(target, param, payload, method, id_location)
                body = resp.text
                if self._is_reflected_unencoded(payload, body):
                    # Check CSP header
                    csp = resp.headers.get("content-security-policy", "")
                    confidence = "high" if not csp else "medium"

                    return {
                        "status": resp.status_code,
                        "payload": payload,
                        "reflected": True,
                        "body_snippet": body[:500],
                        "has_csp": bool(csp),
                        "confidence": confidence,
                    }
            except Exception:
                continue

        # Canary reflected but payloads were encoded — low confidence
        return {
            "status": resp.status_code,
            "payload": canary,
            "reflected": True,
            "encoded": True,
            "confidence": "low",
            "body_snippet": body[:500],
            "note": "Input reflected but payloads appear to be encoded",
        }

    async def _send(self, target: str, param: str, value: str,
                    method: str, id_location: str):
        if id_location == "query":
            return await self.client.request(
                method, target, session=self.session,
                params={param: value},
            )
        elif id_location == "body":
            return await self.client.post(
                target, session=self.session,
                data={param: value},
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
    def _is_reflected_unencoded(payload: str, body: str) -> bool:
        """Check if the payload appears in the response without HTML encoding."""
        if payload in body:
            return True
        # Check for key markers
        lower_body = body.lower()
        for marker in _REFLECTION_MARKERS:
            if marker.lower() in payload.lower() and marker.lower() in lower_body:
                return True
        return False
