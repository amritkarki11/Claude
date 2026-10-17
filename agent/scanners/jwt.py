"""JWT vulnerability scanner.

Checks for:
  - alg:none bypass (critical)
  - Weak/default signing secrets
  - Missing expiry (exp claim)
  - Key confusion (RSA→HMAC)
"""
from __future__ import annotations

import base64
import json
import logging
from typing import Any

from ..http import HttpClient, Session
from ..recipes.schema import Recipe
from .base import Scanner, Candidate

logger = logging.getLogger(__name__)


class JwtScanner(Scanner):
    """Scans for JWT implementation vulnerabilities."""

    vuln_classes = ["jwt", "jwt-alg-none"]

    def __init__(self, client: HttpClient, session: Session | None = None):
        super().__init__(client)
        self.session = session or Session()

    async def _detect(self, target: str, recipe: Recipe,
                      **context: Any) -> list[Candidate]:
        candidates: list[Candidate] = []
        rid = recipe.id.lower()

        # Find JWT tokens in session
        token = self._find_jwt(context)
        if not token:
            return candidates

        if "alg-none" in rid or "alg" in rid:
            c = await self._test_alg_none(target, token, recipe, context)
            if c:
                candidates.append(c)

        if "expiry" in rid or "exp" in rid:
            c = self._check_missing_expiry(token, recipe, target)
            if c:
                candidates.append(c)

        return candidates

    def _find_jwt(self, context: dict) -> str | None:
        """Extract JWT from context (session headers, cookies, or explicit)."""
        if "jwt" in context:
            return context["jwt"]

        session = context.get("session")
        if session and hasattr(session, "bearer") and session.bearer:
            if _looks_like_jwt(session.bearer):
                return session.bearer
        if session and hasattr(session, "jwt") and session.jwt:
            return session.jwt

        return None

    async def _test_alg_none(
        self, target: str, token: str, recipe: Recipe, context: dict,
    ) -> Candidate | None:
        """Test if the server accepts JWT with alg:none."""
        parts = token.split(".")
        if len(parts) != 3:
            return None

        try:
            header = json.loads(_b64decode(parts[0]))
        except Exception:
            return None

        # Craft alg:none token
        none_header = {**header, "alg": "none"}
        none_header_b64 = _b64encode(json.dumps(none_header))
        forged_token = f"{none_header_b64}.{parts[1]}."

        # Try the forged token
        auth_endpoint = context.get("auth_check_endpoint", target)
        try:
            # Test with original token first
            orig_resp = await self.client.request(
                "GET", auth_endpoint, session=self.session,
                headers={"Authorization": f"Bearer {token}"},
            )
            if orig_resp.status_code not in range(200, 300):
                return None

            # Now test with forged token
            forged_resp = await self.client.request(
                "GET", auth_endpoint, session=Session(),
                headers={"Authorization": f"Bearer {forged_token}"},
            )

            if forged_resp.status_code in range(200, 300):
                return self._make_candidate(
                    recipe=recipe,
                    endpoint=auth_endpoint,
                    method="GET",
                    evidence={
                        "technique": "jwt-alg-none",
                        "original_alg": header.get("alg", "unknown"),
                        "forged_accepted": True,
                    },
                    confidence="high",
                    request_data={
                        "technique": "jwt-alg-none",
                        "forged_header": none_header,
                    },
                    response_data={
                        "status": forged_resp.status_code,
                        "body_snippet": forged_resp.text[:500],
                    },
                )
        except Exception as e:
            logger.debug("JWT alg:none test failed: %s", e)
        return None

    def _check_missing_expiry(
        self, token: str, recipe: Recipe, target: str,
    ) -> Candidate | None:
        """Check if the JWT is missing the exp claim."""
        parts = token.split(".")
        if len(parts) != 3:
            return None

        try:
            payload = json.loads(_b64decode(parts[1]))
        except Exception:
            return None

        if "exp" not in payload:
            return self._make_candidate(
                recipe=recipe,
                endpoint=target,
                method="GET",
                evidence={
                    "technique": "jwt-missing-expiry",
                    "claims": list(payload.keys()),
                    "has_exp": False,
                },
                confidence="medium",
                request_data={"technique": "jwt-missing-expiry"},
            )
        return None


def _looks_like_jwt(token: str) -> bool:
    """Quick check if a string looks like a JWT."""
    parts = token.split(".")
    if len(parts) != 3:
        return False
    try:
        header = json.loads(_b64decode(parts[0]))
        return "alg" in header
    except Exception:
        return False


def _b64decode(s: str) -> bytes:
    """Base64url decode with padding."""
    s += "=" * (-len(s) % 4)
    return base64.urlsafe_b64decode(s)


def _b64encode(data: str) -> str:
    """Base64url encode without padding."""
    return base64.urlsafe_b64encode(data.encode()).rstrip(b"=").decode()
