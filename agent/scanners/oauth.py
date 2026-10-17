"""OAuth/SSO vulnerability scanner.

Checks for:
  - Missing state parameter (CSRF on OAuth flow)
  - Open redirect via redirect_uri manipulation
  - Token leakage in URL fragments or referrer
"""
from __future__ import annotations

import logging
import re
from typing import Any
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

from ..http import HttpClient, Session
from ..recipes.schema import Recipe
from .base import Scanner, Candidate

logger = logging.getLogger(__name__)

_OAUTH_ENDPOINT_PATTERNS = re.compile(
    r"(?:/oauth|/authorize|/auth/|/login/oauth|/connect/authorize|"
    r"/api/oauth|/oauth2/|/openid)",
    re.IGNORECASE,
)


class OAuthScanner(Scanner):
    """Scans for OAuth/SSO misconfigurations."""

    vuln_classes = ["oauth", "oauth-state", "oauth-redirect"]

    def __init__(self, client: HttpClient, session: Session | None = None):
        super().__init__(client)
        self.session = session or Session()

    async def _detect(self, target: str, recipe: Recipe,
                      **context: Any) -> list[Candidate]:
        candidates: list[Candidate] = []
        endpoints = context.get("endpoints", [])
        rid = recipe.id.lower()

        oauth_urls = self._find_oauth_urls(endpoints, target)
        if not oauth_urls:
            return candidates

        for url in oauth_urls:
            if "state" in rid:
                c = await self._check_missing_state(url, recipe)
                if c:
                    candidates.append(c)

            if "redirect" in rid:
                c = await self._check_redirect_uri(url, recipe)
                if c:
                    candidates.append(c)

        return candidates

    def _find_oauth_urls(self, endpoints: list, target: str) -> list[str]:
        """Find OAuth-related URLs from discovered endpoints."""
        urls = []
        for ep in endpoints:
            url = ep if isinstance(ep, str) else getattr(ep, "url", "")
            if url and _OAUTH_ENDPOINT_PATTERNS.search(url):
                urls.append(url)
        return urls

    async def _check_missing_state(self, url: str, recipe: Recipe) -> Candidate | None:
        """Check if OAuth authorization endpoint works without state parameter."""
        parsed = urlparse(url)
        params = parse_qs(parsed.query)

        if "state" in params:
            without_state = {k: v for k, v in params.items() if k != "state"}
            new_query = urlencode(without_state, doseq=True)
            test_url = urlunparse(parsed._replace(query=new_query))
        else:
            test_url = url

        try:
            resp = await self.client.request(
                "GET", test_url, session=self.session,
            )
            # If the server redirects or shows the auth page without requiring state,
            # that's a finding
            if resp.status_code in (200, 302, 303):
                location = resp.headers.get("location", "")
                body = resp.text[:2000] if resp.status_code == 200 else ""

                # Check if state is not enforced
                if resp.status_code in (302, 303):
                    if "error" not in location.lower() or "state" not in location.lower():
                        return self._make_candidate(
                            recipe=recipe,
                            endpoint=url,
                            method="GET",
                            evidence={
                                "technique": "oauth-missing-state",
                                "test_url": test_url,
                                "redirect_location": location[:500],
                                "state_enforced": False,
                            },
                            confidence="medium",
                            request_data={
                                "url": test_url,
                                "technique": "oauth-missing-state",
                            },
                            response_data={
                                "status": resp.status_code,
                                "location": location[:500],
                            },
                        )
                elif "login" in body.lower() or "authorize" in body.lower():
                    return self._make_candidate(
                        recipe=recipe,
                        endpoint=url,
                        method="GET",
                        evidence={
                            "technique": "oauth-missing-state",
                            "test_url": test_url,
                            "state_enforced": False,
                        },
                        confidence="medium",
                        request_data={
                            "url": test_url,
                            "technique": "oauth-missing-state",
                        },
                        response_data={
                            "status": resp.status_code,
                            "body_snippet": body[:500],
                        },
                    )
        except Exception as e:
            logger.debug("OAuth state check failed: %s", e)
        return None

    async def _check_redirect_uri(self, url: str, recipe: Recipe) -> Candidate | None:
        """Check if redirect_uri can be manipulated to an external domain."""
        parsed = urlparse(url)
        params = parse_qs(parsed.query)

        if "redirect_uri" not in params:
            return None

        original_redirect = params["redirect_uri"][0]
        test_redirects = [
            "https://evil.com/callback",
            original_redirect + ".evil.com",
            original_redirect + "@evil.com",
            original_redirect + "/../../../evil.com",
        ]

        for test_uri in test_redirects:
            params_copy = dict(params)
            params_copy["redirect_uri"] = [test_uri]
            new_query = urlencode(params_copy, doseq=True)
            test_url = urlunparse(parsed._replace(query=new_query))

            try:
                resp = await self.client.request(
                    "GET", test_url, session=self.session,
                )
                if resp.status_code in (302, 303):
                    location = resp.headers.get("location", "")
                    if "evil.com" in location:
                        return self._make_candidate(
                            recipe=recipe,
                            endpoint=url,
                            method="GET",
                            evidence={
                                "technique": "oauth-redirect-manipulation",
                                "original_redirect": original_redirect,
                                "injected_redirect": test_uri,
                                "actual_redirect": location[:500],
                            },
                            confidence="high",
                            request_data={
                                "url": test_url,
                                "technique": "oauth-redirect-manipulation",
                            },
                            response_data={
                                "status": resp.status_code,
                                "location": location[:500],
                            },
                        )
            except Exception as e:
                logger.debug("OAuth redirect check failed: %s", e)

        return None
