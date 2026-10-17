"""Privilege Escalation scanner — detects if a bypassed session has admin access.

After authentication bypass, this scanner checks whether the obtained session
has elevated privileges by:
  1. Probing for admin/management endpoints discovered during auth crawl
  2. Checking if the session can access user management, settings, or config pages
  3. Attempting horizontal privilege escalation (accessing other users' data)
  4. Checking for role/privilege parameters that can be tampered

This scanner is triggered automatically after a successful auth bypass,
not via the normal recipe→scanner pipeline.
"""
from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urljoin, urlparse

from ..http import HttpClient, Session

logger = logging.getLogger(__name__)


# ── Admin / privileged endpoint patterns ────────────────────

_ADMIN_URL_PATTERNS = re.compile(
    r"(?:admin|manage|management|config|configuration|"
    r"settings|system|control|panel|console|"
    r"users|user-management|accounts|roles|permissions|"
    r"audit|logs|debug|phpinfo|phpmyadmin|"
    r"wp-admin|administrator|backend|"
    r"api/admin|api/users|api/config)",
    re.IGNORECASE,
)

# Body content that indicates admin-level access
_ADMIN_BODY_INDICATORS = re.compile(
    r"(?:user\s*management|manage\s*users|"
    r"admin\s*panel|admin\s*dashboard|"
    r"system\s*settings|configuration|"
    r"create\s*user|delete\s*user|edit\s*user|"
    r"role\s*management|permissions|"
    r"all\s*users|user\s*list|"
    r"transfer\s*funds|wire\s*transfer|"
    r"account\s*summary|view\s*all)",
    re.IGNORECASE,
)

# Endpoints that indicate regular-user-level access (not admin)
_USER_AREA_PATTERNS = re.compile(
    r"(?:profile|my-?account|my-?settings|dashboard|"
    r"home|main|overview|balance|statement|"
    r"transfer|pay|send|history|transactions)",
    re.IGNORECASE,
)

# Patterns for user ID parameters that can be tampered
_USER_ID_PARAMS = re.compile(
    r"^(?:user_?id|uid|account_?id|acct_?id|"
    r"member_?id|customer_?id|profile_?id|"
    r"id|userid|accountid)$",
    re.IGNORECASE,
)


@dataclass
class PrivEscResult:
    """Result of a privilege escalation check."""
    escalation_type: str       # "vertical" or "horizontal"
    detail: str                # Human-readable description
    evidence: dict = field(default_factory=dict)
    confidence: str = "medium"


class PrivilegeEscalationScanner:
    """Checks if a bypassed session has elevated privileges.

    Not a normal scanner (doesn't extend Scanner base class) because it
    runs outside the recipe pipeline — it's called directly by the
    orchestrator after a successful auth bypass.
    """

    def __init__(self, client: HttpClient, session: Session):
        self.client = client
        self.session = session

    async def check(
        self,
        target_url: str,
        discovered_urls: list[str],
    ) -> list[PrivEscResult]:
        """Run all privilege escalation checks.

        Args:
            target_url: The base target URL
            discovered_urls: URLs found during authenticated crawl
        """
        results: list[PrivEscResult] = []

        # Check 1: Admin endpoint access
        admin_results = await self._check_admin_endpoints(
            target_url, discovered_urls,
        )
        results.extend(admin_results)

        # Check 2: Horizontal privilege escalation (IDOR on user endpoints)
        idor_results = await self._check_horizontal_privesc(
            target_url, discovered_urls,
        )
        results.extend(idor_results)

        # Check 3: Common admin paths not found by crawler
        hidden_admin = await self._probe_common_admin_paths(target_url)
        results.extend(hidden_admin)

        return results

    # ── Vertical privilege escalation ──────────────────────────

    async def _check_admin_endpoints(
        self,
        target_url: str,
        discovered_urls: list[str],
    ) -> list[PrivEscResult]:
        """Check if any discovered URLs are admin/management pages."""
        results: list[PrivEscResult] = []

        admin_urls = [
            url for url in discovered_urls
            if _ADMIN_URL_PATTERNS.search(url)
        ]

        for url in admin_urls:
            try:
                resp = await self.client.request(
                    "GET", url, session=self.session,
                )
                if resp.status_code == 200:
                    body = resp.text[:5000]
                    if _ADMIN_BODY_INDICATORS.search(body):
                        results.append(PrivEscResult(
                            escalation_type="vertical",
                            detail=(
                                f"Admin endpoint accessible: {url} — "
                                f"bypassed session has admin-level access"
                            ),
                            evidence={
                                "url": url,
                                "status": resp.status_code,
                                "admin_indicators": _extract_matches(
                                    _ADMIN_BODY_INDICATORS, body,
                                ),
                                "body_snippet": body[:2000],
                            },
                            confidence="high",
                        ))
                    elif not _is_error_page(body):
                        results.append(PrivEscResult(
                            escalation_type="vertical",
                            detail=(
                                f"Admin-pattern URL accessible: {url} — "
                                f"returned 200 with non-error content"
                            ),
                            evidence={
                                "url": url,
                                "status": resp.status_code,
                                "body_snippet": body[:2000],
                            },
                            confidence="medium",
                        ))
            except Exception as e:
                logger.debug("PrivEsc admin check failed for %s: %s", url, e)

        return results

    # ── Horizontal privilege escalation ────────────────────────

    async def _check_horizontal_privesc(
        self,
        target_url: str,
        discovered_urls: list[str],
    ) -> list[PrivEscResult]:
        """Check if user ID parameters allow accessing other users' data."""
        results: list[PrivEscResult] = []

        # Find URLs with user-id-like parameters
        user_urls = [
            url for url in discovered_urls
            if _USER_AREA_PATTERNS.search(url)
        ]

        for url in user_urls:
            parsed = urlparse(url)
            if not parsed.query:
                continue

            # Check for user ID params in the query string
            from urllib.parse import parse_qs
            params = parse_qs(parsed.query)
            for param_name in params:
                if not _USER_ID_PARAMS.match(param_name):
                    continue

                original_value = params[param_name][0]

                # Try a different user ID
                test_ids = _generate_test_ids(original_value)
                for test_id in test_ids:
                    try:
                        # Replace the param value
                        test_url = url.replace(
                            f"{param_name}={original_value}",
                            f"{param_name}={test_id}",
                        )
                        resp = await self.client.request(
                            "GET", test_url, session=self.session,
                        )

                        if resp.status_code == 200 and not _is_error_page(resp.text):
                            # Got a 200 with a different user ID — potential IDOR
                            results.append(PrivEscResult(
                                escalation_type="horizontal",
                                detail=(
                                    f"Horizontal privilege escalation: "
                                    f"changing {param_name} from {original_value} to "
                                    f"{test_id} returns different user data at {url}"
                                ),
                                evidence={
                                    "url": url,
                                    "param": param_name,
                                    "original_id": original_value,
                                    "tampered_id": test_id,
                                    "status": resp.status_code,
                                    "body_snippet": resp.text[:2000],
                                },
                                confidence="medium",
                            ))
                            break  # One IDOR per param is enough
                    except Exception as e:
                        logger.debug("PrivEsc IDOR check failed: %s", e)

        return results

    # ── Hidden admin path probing ──────────────────────────────

    async def _probe_common_admin_paths(
        self,
        target_url: str,
    ) -> list[PrivEscResult]:
        """Probe for common admin paths the crawler may not have found."""
        results: list[PrivEscResult] = []

        common_paths = [
            "/admin",
            "/admin/",
            "/admin/admin.jsp",
            "/admin.jsp",
            "/admin/admin.php",
            "/manager/",
            "/management/",
            "/api/admin/users",
            "/api/users",
            "/phpmyadmin/",
            "/console/",
            "/debug/",
            "/_admin/",
        ]

        for path in common_paths:
            url = urljoin(target_url, path)
            try:
                resp = await self.client.request(
                    "GET", url, session=self.session,
                )
                if resp.status_code == 200:
                    body = resp.text[:5000]
                    if not _is_error_page(body) and len(body) > 200:
                        # Check if the same URL returns 403/401 without auth
                        unauth_resp = await self.client.request(
                            "GET", url, session=Session(),
                        )
                        if unauth_resp.status_code in (401, 403, 302):
                            results.append(PrivEscResult(
                                escalation_type="vertical",
                                detail=(
                                    f"Admin path accessible with bypass session: {url} — "
                                    f"returns 200 with auth but {unauth_resp.status_code} without"
                                ),
                                evidence={
                                    "url": url,
                                    "auth_status": resp.status_code,
                                    "unauth_status": unauth_resp.status_code,
                                    "body_snippet": body[:2000],
                                },
                                confidence="high",
                            ))
            except Exception as e:
                logger.debug("PrivEsc path probe failed for %s: %s", url, e)

        return results


# ── Helpers ─────────────────────────────────────────────────


def _is_error_page(body: str) -> bool:
    """Check if a page body looks like an error/404 page."""
    if not body or len(body) < 50:
        return True
    lower = body.lower()
    error_patterns = [
        "page not found", "404", "not found",
        "access denied", "forbidden", "unauthorized",
        "error occurred", "internal server error",
        "500", "invalid request",
    ]
    matches = sum(1 for p in error_patterns if p in lower)
    return matches >= 2


def _extract_matches(pattern: re.Pattern, text: str) -> list[str]:
    """Extract all regex matches from text."""
    return [m.group() for m in pattern.finditer(text)][:5]


def _generate_test_ids(original: str) -> list[str]:
    """Generate test IDs to try for IDOR.

    If original is numeric, try adjacent numbers.
    If alphanumeric, try variations.
    """
    test_ids = []
    try:
        num = int(original)
        test_ids.extend([str(num + 1), str(num - 1), str(num + 100), "1"])
    except ValueError:
        # Not numeric — try common test values
        test_ids.extend(["1", "2", "admin", "test"])
    return test_ids
