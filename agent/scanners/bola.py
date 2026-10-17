"""BOLA scanner — Broken Object-Level Authorization (OWASP API1).

Extends basic IDOR to automatically discover and test object references
found during crawling. Instead of requiring explicit victim_ids from CLI,
this scanner:
  1. Extracts IDs from crawled URLs, forms, and API responses
  2. Swaps IDs between attacker/victim sessions
  3. Compares response bodies to confirm unauthorized access

This covers both horizontal BOLA (same-privilege cross-account access) and
vertical BOLA (lower-privilege accessing higher-privilege objects).
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

# Patterns for parameters likely carrying object IDs
_ID_PARAM_PATTERN = re.compile(
    r"^(?:id|user_?id|uid|account_?id|acct_?id|order_?id|"
    r"invoice_?id|transaction_?id|txn_?id|"
    r"profile_?id|customer_?id|"
    r"doc_?id|file_?id|record_?id|item_?id|"
    r"pid|oid|rid|fid|tid|aid)$",
    re.IGNORECASE,
)

# URL path patterns that often carry IDs: /resource/{id}
_PATH_ID_PATTERN = re.compile(
    r"/(?:users?|accounts?|profiles?|orders?|invoices?|"
    r"transactions?|documents?|files?|records?|items?|"
    r"customers?|members?|tickets?)/(\d+|[a-f0-9-]{8,})",
    re.IGNORECASE,
)


class BolaScanner(Scanner):
    """Detects Broken Object-Level Authorization via ID swapping."""

    vuln_classes = ["bola", "idor"]

    def __init__(self, client: HttpClient,
                 attacker_session: Session,
                 victim_session: Session | None = None):
        super().__init__(client)
        self.attacker = attacker_session
        self.victim = victim_session

    async def _detect(self, target: str, recipe: Recipe,
                      **context: Any) -> list[Candidate]:
        """Run BOLA detection.

        Context kwargs:
            endpoints: list of endpoint dicts with url, method, params
            victim_ids: optional explicit IDs to test
            id_param: optional specific param name
        """
        candidates: list[Candidate] = []
        endpoints = context.get("endpoints", [])
        explicit_ids = context.get("victim_ids", [])
        explicit_param = context.get("id_param", "")

        # Strategy 1: test explicitly provided IDs (from CLI)
        if explicit_ids and target:
            c = await self._test_explicit(target, recipe, explicit_ids,
                                          explicit_param or "id",
                                          context.get("id_location", "body"))
            candidates.extend(c)

        # Strategy 2: auto-discover and test IDs from crawled endpoints
        for ep in endpoints:
            ep_url = ep if isinstance(ep, str) else ep.get("url", "")
            if not ep_url:
                continue
            c = await self._test_endpoint_ids(ep_url, recipe)
            candidates.extend(c)

        return candidates

    async def _test_explicit(
        self, target: str, recipe: Recipe,
        victim_ids: list, id_param: str, id_location: str,
    ) -> list[Candidate]:
        """Test with explicitly provided victim IDs (backward compat with IdorScanner)."""
        candidates = []
        for vid in victim_ids:
            try:
                evidence = await self._probe(target, id_param, str(vid), id_location)
                if evidence:
                    candidates.append(self._make_candidate(
                        recipe=recipe,
                        endpoint=target,
                        method="POST" if id_location == "body" else "GET",
                        evidence=evidence,
                        confidence=self._assess_confidence(evidence),
                        request_data={
                            "id_param": id_param,
                            "id_value": str(vid),
                            "id_location": id_location,
                            "session": "attacker",
                            "technique": "explicit-id-swap",
                        },
                        response_data={
                            "status": evidence.get("status"),
                            "body_snippet": evidence.get("body_snippet", ""),
                        },
                    ))
            except Exception as e:
                logger.debug("BOLA explicit probe failed: %s", e)
        return candidates

    async def _test_endpoint_ids(
        self, url: str, recipe: Recipe,
    ) -> list[Candidate]:
        """Auto-discover IDs in a URL and test by incrementing/decrementing."""
        candidates = []
        parsed = urlparse(url)

        # Check query parameters for ID-like params
        params = parse_qs(parsed.query, keep_blank_values=True)
        for param_name, values in params.items():
            if not _ID_PARAM_PATTERN.match(param_name):
                continue
            if not values or not values[0]:
                continue
            original = values[0]
            for test_val in _generate_adjacent_ids(original):
                evidence = await self._probe_and_compare(
                    url, param_name, original, test_val, "query",
                )
                if evidence:
                    candidates.append(self._make_candidate(
                        recipe=recipe,
                        endpoint=url,
                        method="GET",
                        evidence=evidence,
                        confidence=self._assess_confidence(evidence),
                        request_data={
                            "id_param": param_name,
                            "id_value": test_val,
                            "original_value": original,
                            "id_location": "query",
                            "session": "attacker",
                            "technique": "auto-id-swap",
                        },
                        response_data={
                            "status": evidence.get("status"),
                            "body_snippet": evidence.get("body_snippet", ""),
                        },
                    ))
                    break  # one finding per param

        # Check path for IDs
        path_match = _PATH_ID_PATTERN.search(parsed.path)
        if path_match:
            original_id = path_match.group(1)
            for test_val in _generate_adjacent_ids(original_id):
                new_path = parsed.path[:path_match.start(1)] + test_val + parsed.path[path_match.end(1):]
                test_url = urlunparse(parsed._replace(path=new_path))
                evidence = await self._probe_and_compare(
                    url, "path_id", original_id, test_val, "path",
                    test_url=test_url,
                )
                if evidence:
                    candidates.append(self._make_candidate(
                        recipe=recipe,
                        endpoint=url,
                        method="GET",
                        evidence=evidence,
                        confidence=self._assess_confidence(evidence),
                        request_data={
                            "id_param": "path_segment",
                            "id_value": test_val,
                            "original_value": original_id,
                            "id_location": "path",
                            "session": "attacker",
                            "technique": "auto-path-id-swap",
                        },
                        response_data={
                            "status": evidence.get("status"),
                            "body_snippet": evidence.get("body_snippet", ""),
                        },
                    ))
                    break

        return candidates

    async def _probe(self, url: str, id_param: str, id_value: str,
                     id_location: str) -> dict | None:
        """Send one BOLA probe and check for success."""
        try:
            if id_location == "body":
                resp = await self.client.post(
                    url, session=self.attacker,
                    json={id_param: id_value},
                )
            elif id_location == "query":
                resp = await self.client.get(
                    url, session=self.attacker,
                    params={id_param: id_value},
                )
            elif id_location == "path":
                path_url = url.rstrip("/") + f"/{id_value}"
                resp = await self.client.get(path_url, session=self.attacker)
            else:
                return None

            if 200 <= resp.status_code < 300:
                body = resp.text[:1000]
                if not _looks_like_error(body):
                    return {
                        "status": resp.status_code,
                        "body_snippet": body,
                        "id_value": id_value,
                        "indicates_success": True,
                    }
        except Exception as e:
            logger.debug("BOLA probe error: %s", e)
        return None

    async def _probe_and_compare(
        self, original_url: str, param_name: str,
        original_id: str, test_id: str, location: str,
        *, test_url: str | None = None,
    ) -> dict | None:
        """Probe with swapped ID and compare against original response."""
        try:
            orig_resp = await self.client.get(original_url, session=self.attacker)

            if test_url:
                tampered_resp = await self.client.get(test_url, session=self.attacker)
            elif location == "query":
                parsed = urlparse(original_url)
                params = parse_qs(parsed.query, keep_blank_values=True)
                params[param_name] = [test_id]
                new_query = urlencode(params, doseq=True)
                tampered_url = urlunparse(parsed._replace(query=new_query))
                tampered_resp = await self.client.get(tampered_url, session=self.attacker)
            else:
                return None

            if tampered_resp.status_code not in range(200, 300):
                return None

            body = tampered_resp.text[:2000]
            if _looks_like_error(body):
                return None

            # Key: responses must differ meaningfully (different object data)
            if not _bodies_differ_meaningfully(orig_resp.text[:2000], body):
                return None

            return {
                "status": tampered_resp.status_code,
                "body_snippet": body[:1000],
                "original_id": original_id,
                "test_id": test_id,
                "param": param_name,
                "response_differs": True,
                "indicates_success": True,
            }
        except Exception as e:
            logger.debug("BOLA compare probe error: %s", e)
            return None

    @staticmethod
    def _assess_confidence(evidence: dict) -> str:
        if evidence.get("response_differs"):
            return "high"
        if evidence.get("status") == 200:
            return "medium"
        return "low"


def _looks_like_error(body: str) -> bool:
    lower = body.lower()
    signals = [
        "error", "denied", "forbidden", "unauthorized",
        "not found", "invalid", "no permission", "access denied",
        "does not exist", "not allowed",
    ]
    return sum(1 for s in signals if s in lower) >= 1


def _generate_adjacent_ids(original: str) -> list[str]:
    """Generate test IDs adjacent to the original."""
    ids = []
    try:
        num = int(original)
        ids.extend([str(num + 1), str(num - 1)])
        if num > 100:
            ids.append("1")
    except ValueError:
        pass
    return ids


def _bodies_differ_meaningfully(body_a: str, body_b: str) -> bool:
    """Check if response bodies contain different object data."""
    # Strip common dynamic content
    def _strip_dynamic(t: str) -> str:
        t = re.sub(r"\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}", "", t)
        t = re.sub(r"[a-f0-9]{32,}", "", t)
        t = re.sub(r"\s+", " ", t).strip()
        return t

    a = _strip_dynamic(body_a)
    b = _strip_dynamic(body_b)

    if a == b:
        return False

    shorter = min(len(a), len(b)) or 1
    diff = sum(1 for x, y in zip(a, b) if x != y) + abs(len(a) - len(b))
    return diff / shorter > 0.05
