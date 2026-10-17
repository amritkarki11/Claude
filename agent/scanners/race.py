"""Race condition scanner — detects TOCTOU and double-action vulnerabilities.

Strategy: fire multiple identical requests concurrently and check if the
server processes more than one (e.g., double withdrawal, double coupon apply,
double vote). Uses asyncio.gather for true concurrency.
"""
from __future__ import annotations

import asyncio
import logging
from typing import Any
from urllib.parse import urlparse

from ..http import HttpClient, Session
from ..recipes.schema import Recipe
from .base import Scanner, Candidate

logger = logging.getLogger(__name__)

# Endpoints likely to have race conditions
_RACE_SENSITIVE_PATTERNS = [
    "transfer", "withdraw", "payment", "pay",
    "redeem", "coupon", "voucher", "apply",
    "vote", "like", "follow", "subscribe",
    "order", "purchase", "checkout", "buy",
    "confirm", "approve", "submit",
]

_DEFAULT_CONCURRENCY = 5


class RaceConditionScanner(Scanner):
    """Detects race conditions via concurrent request replay."""

    vuln_classes = ["race", "race-condition", "toctou"]

    def __init__(self, client: HttpClient, session: Session | None = None):
        super().__init__(client)
        self.session = session or Session()

    async def _detect(self, target: str, recipe: Recipe,
                      **context: Any) -> list[Candidate]:
        candidates: list[Candidate] = []
        endpoints = context.get("endpoints", [])
        concurrency = context.get("concurrency", _DEFAULT_CONCURRENCY)

        race_endpoints = self._find_race_endpoints(endpoints, target)
        for url, method in race_endpoints:
            c = await self._test_race(url, method, recipe, concurrency)
            if c:
                candidates.append(c)

        return candidates

    def _find_race_endpoints(
        self, endpoints: list, target: str,
    ) -> list[tuple[str, str]]:
        """Find endpoints likely susceptible to race conditions."""
        results: list[tuple[str, str]] = []
        seen: set[str] = set()

        for ep in endpoints:
            if isinstance(ep, str):
                url, method = ep, "POST"
            elif hasattr(ep, "url"):
                url = ep.url
                method = getattr(ep, "method", "POST")
            else:
                continue

            path = urlparse(url).path.lower()
            for pattern in _RACE_SENSITIVE_PATTERNS:
                if pattern in path and url not in seen:
                    seen.add(url)
                    results.append((url, method))
                    break

        return results

    async def _test_race(
        self, url: str, method: str, recipe: Recipe, concurrency: int,
    ) -> Candidate | None:
        """Fire concurrent requests and check for double-processing."""
        try:
            # First, get a baseline single response
            baseline = await self.client.request(
                method, url, session=self.session,
            )
            if baseline.status_code not in range(200, 400):
                return None

            # Fire concurrent requests
            tasks = [
                self.client.request(method, url, session=self.session)
                for _ in range(concurrency)
            ]
            responses = await asyncio.gather(*tasks, return_exceptions=True)

            # Analyze: count successes
            successes = []
            errors = []
            for r in responses:
                if isinstance(r, Exception):
                    errors.append(str(r))
                    continue
                if 200 <= r.status_code < 300:
                    successes.append({
                        "status": r.status_code,
                        "body_len": len(r.text),
                        "body_snippet": r.text[:200],
                    })

            # If all concurrent requests succeeded, possible race condition
            if len(successes) > 1:
                # Check if responses are substantively identical (same action repeated)
                unique_bodies = set(s["body_snippet"] for s in successes)

                return self._make_candidate(
                    recipe=recipe,
                    endpoint=url,
                    method=method,
                    evidence={
                        "technique": "race-condition-concurrent",
                        "concurrency": concurrency,
                        "successes": len(successes),
                        "errors": len(errors),
                        "unique_responses": len(unique_bodies),
                        "all_identical": len(unique_bodies) == 1,
                    },
                    confidence="medium" if len(unique_bodies) == 1 else "low",
                    request_data={
                        "url": url,
                        "method": method,
                        "concurrency": concurrency,
                        "technique": "race-condition",
                    },
                    response_data={
                        "successes": successes[:3],
                    },
                )
        except Exception as e:
            logger.debug("Race condition test failed for %s: %s", url, e)

        return None
