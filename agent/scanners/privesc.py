"""Privilege Escalation scanner — detects if a bypassed session has admin access.

After authentication bypass, this scanner checks whether the obtained session
has elevated privileges by:
  1. Probing for admin/management endpoints discovered during auth crawl
  2. Checking if the session can access user management, settings, or config pages
  3. Attempting horizontal privilege escalation (accessing other users' data)

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

# High-signal: paths that almost always mean admin functionality
_ADMIN_PATH_STRONG = re.compile(
    r"/(?:admin|wp-admin|administrator|phpmyadmin|"
    r"manage(?:ment)?/(?:users|roles|config|system)|"
    r"control[_-]?panel|console|debug|phpinfo|"
    r"api/admin|api/v\d+/admin)",
    re.IGNORECASE,
)

# Low-signal: paths that COULD be admin but are often regular user pages.
# These need body-content confirmation before reporting.
_ADMIN_PATH_WEAK = re.compile(
    r"/(?:users|accounts|settings|config|roles|permissions|"
    r"audit|logs|system)",
    re.IGNORECASE,
)

# Body content that confirms admin-level access (not just user-level)
_ADMIN_BODY_INDICATORS = re.compile(
    r"(?:user\s*management|manage\s*users|"
    r"admin\s*(?:panel|dashboard|console)|"
    r"system\s*(?:settings|configuration|admin)|"
    r"create\s*user|delete\s*user|"
    r"role\s*management|assign\s*role|"
    r"all\s*users\s*list|"
    r"server\s*(?:status|info|configuration))",
    re.IGNORECASE,
)

# Patterns for user ID parameters that can be tampered
_USER_ID_PARAMS = re.compile(
    r"^(?:user_?id|uid|account_?id|acct_?id|"
    r"member_?id|customer_?id|profile_?id|"
    r"id|userid|accountid)$",
    re.IGNORECASE,
)

# Pages that are normal user-level (not escalation even if accessible)
_NORMAL_USER_PAGES = re.compile(
    r"(?:my[_-]?account|profile|dashboard|home|"
    r"balance|statement|transfer|pay[_-]?bill|"
    r"history|transactions|overview|"
    r"job|career|contact|about|faq|help|"
    r"news|press|blog|media|investor|"
    r"loan|credit|mortgage|insurance|"
    r"feedback|survey|search|result|"
    r"terms|privacy|legal|disclaimer)",
    re.IGNORECASE,
)


@dataclass
class PrivEscResult:
    """Result of a privilege escalation check."""
    escalation_type: str       # "vertical" or "horizontal"
    detail: str
    evidence: dict = field(default_factory=dict)
    confidence: str = "medium"


class PrivilegeEscalationScanner:
    """Checks if a bypassed session has elevated privileges."""

    def __init__(self, client: HttpClient, session: Session):
        self.client = client
        self.session = session

    async def check(
        self,
        target_url: str,
        discovered_urls: list[str],
    ) -> list[PrivEscResult]:
        results: list[PrivEscResult] = []
        seen_paths: set[str] = set()

        admin_results = await self._check_admin_endpoints(
            target_url, discovered_urls, seen_paths,
        )
        results.extend(admin_results)

        idor_results = await self._check_horizontal_privesc(
            target_url, discovered_urls,
        )
        results.extend(idor_results)

        hidden_admin = await self._probe_common_admin_paths(
            target_url, seen_paths,
        )
        results.extend(hidden_admin)

        return results

    # ── Vertical privilege escalation ──────────────────────────

    async def _check_admin_endpoints(
        self,
        target_url: str,
        discovered_urls: list[str],
        seen_paths: set[str],
    ) -> list[PrivEscResult]:
        """Check if any discovered URLs are real admin/management pages.

        Only reports when:
          - Strong admin path + 200 + non-error body + returns 401/403 without auth
          - OR weak admin path + admin body indicators + auth-required confirmation
        """
        results: list[PrivEscResult] = []

        for url in discovered_urls:
            path = urlparse(url).path or "/"

            if path in seen_paths:
                continue

            # Skip URLs that are clearly normal user pages
            if _NORMAL_USER_PAGES.search(path):
                continue

            is_strong = bool(_ADMIN_PATH_STRONG.search(path))
            is_weak = bool(_ADMIN_PATH_WEAK.search(path))

            if not is_strong and not is_weak:
                continue

            try:
                resp = await self.client.request(
                    "GET", url, session=self.session,
                )
                if resp.status_code != 200:
                    continue

                body = resp.text[:5000]
                if _is_error_page(body):
                    continue

                has_admin_body = bool(_ADMIN_BODY_INDICATORS.search(body))

                # Weak-signal paths require admin body indicators
                if is_weak and not has_admin_body:
                    continue

                # Confirm: page must require auth (401/403/302 without session)
                unauth_resp = await self.client.request(
                    "GET", url, session=Session(),
                )
                if unauth_resp.status_code not in (401, 403, 302):
                    continue

                seen_paths.add(path)
                confidence = "high" if (is_strong and has_admin_body) else "medium"

                results.append(PrivEscResult(
                    escalation_type="vertical",
                    detail=(
                        f"Admin endpoint accessible: {url} — "
                        f"returns 200 with bypass session but "
                        f"{unauth_resp.status_code} without auth"
                    ),
                    evidence={
                        "url": url,
                        "auth_status": resp.status_code,
                        "unauth_status": unauth_resp.status_code,
                        "admin_indicators": _extract_matches(
                            _ADMIN_BODY_INDICATORS, body,
                        ) if has_admin_body else [],
                        "body_snippet": body[:2000],
                    },
                    confidence=confidence,
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
        seen_params: set[tuple[str, str]] = set()

        for url in discovered_urls:
            parsed = urlparse(url)
            if not parsed.query:
                continue

            from urllib.parse import parse_qs
            params = parse_qs(parsed.query)
            for param_name in params:
                if not _USER_ID_PARAMS.match(param_name):
                    continue

                key = (parsed.path, param_name)
                if key in seen_params:
                    continue

                original_value = params[param_name][0]
                test_ids = _generate_test_ids(original_value)

                for test_id in test_ids:
                    try:
                        test_url = url.replace(
                            f"{param_name}={original_value}",
                            f"{param_name}={test_id}",
                        )

                        # Get original response for comparison
                        orig_resp = await self.client.request(
                            "GET", url, session=self.session,
                        )
                        tampered_resp = await self.client.request(
                            "GET", test_url, session=self.session,
                        )

                        if tampered_resp.status_code != 200:
                            continue
                        if _is_error_page(tampered_resp.text):
                            continue

                        # Key check: response bodies must differ meaningfully
                        # (same page = no escalation, just default rendering)
                        if _responses_differ(orig_resp.text, tampered_resp.text):
                            seen_params.add(key)
                            results.append(PrivEscResult(
                                escalation_type="horizontal",
                                detail=(
                                    f"Horizontal privilege escalation: "
                                    f"changing {param_name} from {original_value} "
                                    f"to {test_id} returns different user data"
                                ),
                                evidence={
                                    "url": url,
                                    "param": param_name,
                                    "original_id": original_value,
                                    "tampered_id": test_id,
                                    "status": tampered_resp.status_code,
                                    "body_snippet": tampered_resp.text[:2000],
                                },
                                confidence="medium",
                            ))
                            break
                    except Exception as e:
                        logger.debug("PrivEsc IDOR check failed: %s", e)

        return results

    # ── Hidden admin path probing ──────────────────────────────

    async def _probe_common_admin_paths(
        self,
        target_url: str,
        seen_paths: set[str],
    ) -> list[PrivEscResult]:
        """Probe for common admin paths the crawler may not have found."""
        results: list[PrivEscResult] = []

        common_paths = [
            "/admin", "/admin/", "/admin/admin.jsp", "/admin.jsp",
            "/admin/admin.php", "/manager/", "/management/",
            "/api/admin/users", "/api/users",
            "/phpmyadmin/", "/console/", "/debug/", "/_admin/",
        ]

        for path in common_paths:
            if path.rstrip("/") in seen_paths:
                continue

            url = urljoin(target_url, path)
            try:
                resp = await self.client.request(
                    "GET", url, session=self.session,
                )
                if resp.status_code != 200:
                    continue

                body = resp.text[:5000]
                if _is_error_page(body) or len(body) < 200:
                    continue

                # Must return 401/403 without auth to confirm access control
                unauth_resp = await self.client.request(
                    "GET", url, session=Session(),
                )
                if unauth_resp.status_code in (401, 403, 302):
                    seen_paths.add(path.rstrip("/"))
                    results.append(PrivEscResult(
                        escalation_type="vertical",
                        detail=(
                            f"Admin path accessible with bypass session: {url} — "
                            f"returns 200 with auth but "
                            f"{unauth_resp.status_code} without"
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
    return [m.group() for m in pattern.finditer(text)][:5]


def _generate_test_ids(original: str) -> list[str]:
    test_ids = []
    try:
        num = int(original)
        test_ids.extend([str(num + 1), str(num - 1), str(num + 100), "1"])
    except ValueError:
        test_ids.extend(["1", "2", "admin", "test"])
    return test_ids


def _responses_differ(body_a: str, body_b: str) -> bool:
    """Check if two response bodies differ meaningfully (not just timestamps/tokens).

    Strips common dynamic content (CSRF tokens, timestamps, session IDs) and
    compares what's left. Returns True only if the structural content changed.
    """
    def _normalize(text: str) -> str:
        # Strip hidden input values (CSRF tokens, nonces, etc.)
        text = re.sub(
            r'(<input[^>]*type=["\']hidden["\'][^>]*?)value=["\'][^"\']*["\']',
            r"\1", text, flags=re.I,
        )
        text = re.sub(r"\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}", "", text)
        text = re.sub(r"[a-f0-9]{32,}", "", text)
        text = re.sub(r"\s+", " ", text).strip()
        return text

    na = _normalize(body_a[:3000])
    nb = _normalize(body_b[:3000])

    if na == nb:
        return False

    # Require at least 5% difference to be "meaningful"
    shorter = min(len(na), len(nb)) or 1
    diff_chars = sum(1 for a, b in zip(na, nb) if a != b) + abs(len(na) - len(nb))
    return diff_chars / shorter > 0.05
